mod mysql;
use std::io::{Read, Write};

use mysql::protos::drop_packet;
use mysql::protos::drop_packet_sync;
use mysql::protos::request;
use mysql::protos::request_async;
use mysql::protos::CapabilityFlags;
use mysql::protos::ClientPacketSendExt;
use mysql::protos::ErrPacket;
use mysql::protos::GenericOKErrPacket;
use mysql::protos::QueryCommand;
use mysql::protos::QueryCommandResponse;
use mysql::protos::QuitCommand;
use mysql::protos::StmtCloseCommand;
use mysql::protos::StmtExecuteCommand;
use mysql::protos::StmtExecuteFlags;
use mysql::protos::StmtExecuteResult;
use mysql::protos::StmtPrepareCommand;
use mysql::protos::StmtResetCommand;
use mysql::protos::Value;
use parking_lot::Mutex;
use parking_lot::MutexGuard;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use crate::authentication::Authentication;
use crate::protos::Handshake;

pub use self::mysql::*;

mod resultset_stream;
pub use self::resultset_stream::*;

#[derive(Debug)]
pub enum CommunicationError {
    IO(std::io::Error),
    Server(ErrPacket),
}
impl From<std::io::Error> for CommunicationError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}
impl From<ErrPacket> for CommunicationError {
    fn from(e: ErrPacket) -> Self {
        Self::Server(e)
    }
}
impl std::fmt::Display for CommunicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IO(io) => write!(f, "IO Error: {io}"),
            Self::Server(e) => write!(f, "Server Error: {}", e.error_message),
        }
    }
}
impl std::error::Error for CommunicationError {}

pub struct SharedClient<Stream: AsyncWriteExt + Unpin>(Mutex<Client<Stream>>);
impl<Stream: AsyncWriteExt + Unpin> SharedClient<Stream> {
    pub fn unshare(self) -> Client<Stream> {
        self.0.into_inner()
    }

    pub fn lock(&self) -> MutexGuard<Client<Stream>> {
        self.0.lock()
    }
}

pub struct SharedBlockingClient<Stream: Write>(Mutex<BlockingClient<Stream>>);
impl<Stream: Write> SharedBlockingClient<Stream> {
    pub fn unshare(self) -> BlockingClient<Stream> {
        self.0.into_inner()
    }

    pub fn lock(&self) -> MutexGuard<BlockingClient<Stream>> {
        self.0.lock()
    }
}

pub struct ConnectInfo<'s> {
    username: &'s str,
    password: &'s str,
    database: Option<&'s str>,
    max_packet_size: u32,
    character_set: u8,
}
impl<'s> ConnectInfo<'s> {
    pub fn new(username: &'s str, password: &'s str) -> Self {
        Self {
            username,
            password,
            database: None,
            max_packet_size: 16777216,
            character_set: 0xff,
        }
    }

    /// Sets initial connected database name: default is `None`
    pub fn database(mut self, db_name: &'s str) -> Self {
        self.database = Some(db_name);
        self
    }

    /// Sets max packet size: default is big enough value
    pub fn max_packet_size(mut self, packet_size: u32) -> Self {
        self.max_packet_size = packet_size;
        self
    }

    /// Sets character set: default is utf8mb4
    pub fn character_set(mut self, character_set: u8) -> Self {
        self.character_set = character_set;
        self
    }
}

pub struct BlockingClient<Stream: Write> {
    stream: Stream,
    capability: CapabilityFlags,
}
impl<Stream: Write> BlockingClient<Stream> {
    pub fn handshake(
        mut stream: Stream,
        connect_info: &ConnectInfo,
    ) -> Result<Self, CommunicationError>
    where
        Stream: Read,
    {
        let (server_handshake, sequence_id) = Handshake::read_packet_sync(&mut stream)?;

        let server_caps = match server_handshake {
            Handshake::V10Long(ref p) => p.short.capability_flags,
            Handshake::V10Short(ref p) => p.capability_flags,
            _ => CapabilityFlags::new(),
        };
        let mut required_caps = CapabilityFlags::new();
        required_caps
            .set_support_41_protocol()
            .set_support_secure_connection()
            .set_use_long_password()
            .set_support_deprecate_eof()
            .set_client_plugin_auth()
            .set_support_plugin_auth_lenenc_client_data();
        if connect_info.database.is_some() {
            required_caps.set_connect_with_db();
        }
        let capability = required_caps & server_caps;

        let con_info = authentication::ConnectionInfo {
            client_capabilities: capability,
            max_packet_size: connect_info.max_packet_size,
            character_set: connect_info.character_set,
            username: connect_info.username,
            password: connect_info.password,
            database: connect_info.database,
        };

        let (auth_plugin_name, auth_data_1, auth_data_2) = match server_handshake {
            Handshake::V10Long(ref p) => (
                p.auth_plugin_name.as_deref(),
                &p.short.auth_plugin_data_part_1[..],
                p.auth_plugin_data_part_2.as_deref(),
            ),
            Handshake::V10Short(ref p) => (None, &p.auth_plugin_data_part_1[..], None),
            Handshake::V9(ref p) => (None, p.scramble.as_bytes(), None),
        };
        match auth_plugin_name {
            Some(x) if x == authentication::Native41::NAME => authentication::Native41 {
                server_data_1: auth_data_1,
                server_data_2: auth_data_2.expect("no extra data passed from server"),
            }
            .run_sync(&mut stream, &con_info, sequence_id + 1)?,
            Some(x) if x == authentication::ClearText::NAME => {
                authentication::ClearText.run_sync(&mut stream, &con_info, sequence_id + 1)?
            }
            Some(x) if x == authentication::SHA256::NAME => authentication::SHA256 {
                server_spki_der: None,
                scramble_buffer_1: auth_data_1,
                scramble_buffer_2: auth_data_2.unwrap_or(&[]),
            }
            .run_sync(&mut stream, &con_info, sequence_id + 1)?,
            Some(x) if x == authentication::CachedSHA256::NAME => {
                authentication::CachedSHA256(authentication::SHA256 {
                    server_spki_der: None,
                    scramble_buffer_1: auth_data_1,
                    scramble_buffer_2: auth_data_2.unwrap_or(&[]),
                })
                .run_sync(&mut stream, &con_info, sequence_id + 1)?
            }
            Some(x) => unreachable!("unknown auth plugin: {x}"),
            None => unreachable!("auth plugin is not specified"),
        };

        Ok(unsafe { Self::new(stream, capability) })
    }

    /// this function does not perform handshaking. user must be done the operation.
    pub unsafe fn new(stream: Stream, capability: CapabilityFlags) -> Self {
        Self {
            stream: stream,
            capability,
        }
    }

    pub fn share(self) -> SharedBlockingClient<Stream> {
        SharedBlockingClient(Mutex::new(self))
    }

    pub fn quit(&mut self) -> std::io::Result<()> {
        QuitCommand.write_packet_sync(&mut self.stream, 0)
    }

    pub fn query(&mut self, query: &str) -> std::io::Result<QueryCommandResponse>
    where
        Stream: Read,
    {
        request(&QueryCommand(query), &mut self.stream, 0, self.capability)
    }

    pub fn fetch_all<'s>(
        &'s mut self,
        query: &str,
    ) -> Result<TextResultsetIterator<&'s mut Stream>, CommunicationError>
    where
        Stream: Read,
    {
        match self.query(query)? {
            QueryCommandResponse::Resultset { column_count } => self
                .text_resultset_iterator(column_count as _)
                .map_err(From::from),
            QueryCommandResponse::Err(e) => Err(CommunicationError::from(e)),
            QueryCommandResponse::Ok(_) => unreachable!("OK Returned"),
            QueryCommandResponse::LocalInfileRequest { filename } => {
                todo!("local infile request: {filename}")
            }
        }
    }

    pub fn text_resultset_iterator(
        &mut self,
        column_count: usize,
    ) -> std::io::Result<TextResultsetIterator<&mut Stream>>
    where
        Stream: Read,
    {
        TextResultsetIterator::new(&mut self.stream, column_count, self.capability)
    }

    pub fn binary_resultset_iterator(
        &mut self,
        column_count: usize,
    ) -> std::io::Result<BinaryResultsetIterator<&mut Stream>>
    where
        Stream: Read,
    {
        BinaryResultsetIterator::new(&mut self.stream, column_count, self.capability)
    }
}
impl<Stream: Write> Drop for BlockingClient<Stream> {
    fn drop(&mut self) {
        self.quit().expect("Failed to send quit packet at drop")
    }
}
impl BlockingClient<std::net::TcpStream> {
    pub fn into_async(self) -> Client<tokio::io::BufStream<tokio::net::TcpStream>> {
        let stream = unsafe { std::ptr::read(&self.stream as *const std::net::TcpStream) };
        let capability = self.capability;
        std::mem::forget(self);

        stream
            .set_nonblocking(true)
            .expect("Failed to switch blocking mode");

        Client {
            stream: tokio::io::BufStream::new(
                tokio::net::TcpStream::from_std(stream).expect("Failed to wrap std stream"),
            ),
            capability,
        }
    }
}

pub struct Client<Stream: AsyncWriteExt + Unpin> {
    stream: Stream,
    capability: CapabilityFlags,
}
impl<Stream: AsyncWriteExt + Unpin> Client<Stream> {
    pub async fn handshake(
        mut stream: Stream,
        connect_info: &ConnectInfo<'_>,
    ) -> Result<Self, CommunicationError>
    where
        Stream: AsyncReadExt,
    {
        let (server_handshake, sequence_id) = Handshake::read_packet(&mut stream).await?;

        let server_caps = match server_handshake {
            Handshake::V10Long(ref p) => p.short.capability_flags,
            Handshake::V10Short(ref p) => p.capability_flags,
            _ => CapabilityFlags::new(),
        };
        let mut required_caps = CapabilityFlags::new();
        required_caps
            .set_support_41_protocol()
            .set_support_secure_connection()
            .set_use_long_password()
            .set_support_deprecate_eof()
            .set_client_plugin_auth()
            .set_support_plugin_auth_lenenc_client_data();
        if connect_info.database.is_some() {
            required_caps.set_connect_with_db();
        }
        let capability = required_caps & server_caps;

        let con_info = authentication::ConnectionInfo {
            client_capabilities: capability,
            max_packet_size: connect_info.max_packet_size,
            character_set: connect_info.character_set,
            username: connect_info.username,
            password: connect_info.password,
            database: connect_info.database,
        };

        let (auth_plugin_name, auth_data_1, auth_data_2) = match server_handshake {
            Handshake::V10Long(ref p) => (
                p.auth_plugin_name.as_deref(),
                &p.short.auth_plugin_data_part_1[..],
                p.auth_plugin_data_part_2.as_deref(),
            ),
            Handshake::V10Short(ref p) => (None, &p.auth_plugin_data_part_1[..], None),
            Handshake::V9(ref p) => (None, p.scramble.as_bytes(), None),
        };
        match auth_plugin_name {
            Some(x) if x == authentication::Native41::NAME => authentication::Native41 {
                server_data_1: auth_data_1,
                server_data_2: auth_data_2.expect("no extra data passed from server"),
            }
            .run(&mut stream, &con_info, sequence_id + 1)
            .await
            .expect("Failed to authenticate"),
            Some(x) if x == authentication::ClearText::NAME => authentication::ClearText
                .run(&mut stream, &con_info, sequence_id + 1)
                .await
                .expect("Failed to authenticate"),
            Some(x) if x == authentication::SHA256::NAME => authentication::SHA256 {
                server_spki_der: None,
                scramble_buffer_1: auth_data_1,
                scramble_buffer_2: auth_data_2.unwrap_or(&[]),
            }
            .run(&mut stream, &con_info, sequence_id + 1)
            .await
            .expect("Failed to authenticate"),
            Some(x) if x == authentication::CachedSHA256::NAME => {
                authentication::CachedSHA256(authentication::SHA256 {
                    server_spki_der: None,
                    scramble_buffer_1: auth_data_1,
                    scramble_buffer_2: auth_data_2.unwrap_or(&[]),
                })
                .run(&mut stream, &con_info, sequence_id + 1)
                .await
                .expect("Failed to authenticate")
            }
            Some(x) => unreachable!("unknown auth plugin: {x}"),
            None => unreachable!("auth plugin is not specified"),
        };

        Ok(unsafe { Self::new(stream, capability) })
    }

    /// this function does not perform handshaking. user must be done the operation.
    pub unsafe fn new(stream: Stream, capability: CapabilityFlags) -> Self {
        Self {
            stream: stream,
            capability,
        }
    }

    pub fn share(self) -> SharedClient<Stream> {
        SharedClient(Mutex::new(self))
    }

    pub async fn quit(&mut self) -> std::io::Result<()> {
        QuitCommand.write_packet(&mut self.stream, 0).await?;
        Ok(())
    }

    pub async fn query(&mut self, query: &str) -> std::io::Result<QueryCommandResponse>
    where
        Stream: AsyncRead,
    {
        request_async(&QueryCommand(query), &mut self.stream, 0, self.capability).await
    }

    pub async fn fetch_all<'s>(
        &'s mut self,
        query: &'s str,
    ) -> Result<TextResultsetStream<'s, Stream>, CommunicationError>
    where
        Stream: AsyncReadExt,
    {
        match self.query(query).await? {
            QueryCommandResponse::Resultset { column_count } => self
                .text_resultset_stream(column_count as _)
                .await
                .map_err(From::from),
            QueryCommandResponse::Err(e) => Err(CommunicationError::from(e)),
            QueryCommandResponse::Ok(_) => unreachable!("OK Returned"),
            QueryCommandResponse::LocalInfileRequest { filename } => {
                todo!("local infile request: {filename}")
            }
        }
    }

    pub async fn text_resultset_stream<'s>(
        &'s mut self,
        column_count: usize,
    ) -> std::io::Result<TextResultsetStream<'s, Stream>>
    where
        Stream: AsyncReadExt,
    {
        TextResultsetStream::new(&mut self.stream, column_count, self.capability).await
    }

    pub async fn binary_resultset_stream<'s>(
        &'s mut self,
        column_count: usize,
    ) -> std::io::Result<BinaryResultsetStream<'s, Stream>>
    where
        Stream: AsyncReadExt,
    {
        BinaryResultsetStream::new(&mut self.stream, self.capability, column_count).await
    }
}
impl<Stream: AsyncWriteExt + Unpin> Drop for Client<Stream> {
    fn drop(&mut self) {
        eprintln!("warning: client has dropped without explicit quit command");
    }
}

pub trait GenericClient {
    type Stream;

    fn stream(&self) -> &Self::Stream;
    fn stream_mut(&mut self) -> &mut Self::Stream;
    fn capability(&self) -> CapabilityFlags;
}
impl<S: AsyncWriteExt + Unpin> GenericClient for Client<S> {
    type Stream = S;

    fn stream(&self) -> &Self::Stream {
        &self.stream
    }
    fn stream_mut(&mut self) -> &mut Self::Stream {
        &mut self.stream
    }
    fn capability(&self) -> CapabilityFlags {
        self.capability
    }
}
impl<S: Write> GenericClient for BlockingClient<S> {
    type Stream = S;

    fn stream(&self) -> &Self::Stream {
        &self.stream
    }
    fn stream_mut(&mut self) -> &mut Self::Stream {
        &mut self.stream
    }
    fn capability(&self) -> CapabilityFlags {
        self.capability
    }
}

pub trait SharedMysqlClient<'s> {
    type Client: GenericClient;
    type GuardedClientRef: 's + std::ops::Deref<Target = Self::Client> + std::ops::DerefMut;

    fn lock_client(&'s self) -> Self::GuardedClientRef;
}
impl<'s, S> SharedMysqlClient<'s> for SharedClient<S>
where
    S: AsyncWriteExt + Unpin + 's,
{
    type Client = Client<S>;
    type GuardedClientRef = MutexGuard<'s, Client<S>>;

    fn lock_client(&'s self) -> Self::GuardedClientRef {
        self.0.lock()
    }
}

pub trait SharedBlockingMysqlClient<'s> {
    type Client: GenericClient;
    type GuardedClientRef: 's + std::ops::Deref<Target = Self::Client> + std::ops::DerefMut;

    fn lock_client(&'s self) -> Self::GuardedClientRef;
}
impl<'c, Stream: Write + 'c> SharedBlockingMysqlClient<'c> for SharedBlockingClient<Stream> {
    type Client = BlockingClient<Stream>;
    type GuardedClientRef = MutexGuard<'c, BlockingClient<Stream>>;

    fn lock_client(&'c self) -> Self::GuardedClientRef {
        self.lock()
    }
}

pub struct Statement<'c, C: SharedMysqlClient<'c>> {
    client: &'c C,
    statement_id: u32,
}
impl<Stream: AsyncWriteExt + AsyncReadExt + Unpin> SharedClient<Stream> {
    pub async fn prepare<'c, 's: 'c>(
        &'c self,
        statement: &'s str,
    ) -> Result<Statement<'c, Self>, CommunicationError> {
        let mut c = self.lock();
        let cap = c.capability;

        let resp = request_async(&StmtPrepareCommand(statement), c.stream_mut(), 0, cap)
            .await?
            .into_result()?;

        // simply drop unused packets
        for _ in 0..resp.num_params {
            drop_packet(&mut c.stream).await?;
        }
        if !c.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet(&mut c.stream).await?
        }

        for _ in 0..resp.num_columns {
            drop_packet(&mut c.stream).await?;
        }
        if !c.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet(&mut c.stream).await?
        }

        Ok(Statement {
            client: self,
            statement_id: resp.statement_id,
        })
    }
}
impl<'c, C: SharedMysqlClient<'c>> Statement<'c, C>
where
    <C::Client as GenericClient>::Stream: AsyncWriteExt + Unpin,
{
    pub async fn close(self) -> std::io::Result<()> {
        StmtCloseCommand(self.statement_id)
            .write_packet(self.client.lock_client().stream_mut(), 0)
            .await?;
        std::mem::forget(self);
        Ok(())
    }

    pub async fn reset(&mut self) -> Result<(), CommunicationError>
    where
        <C::Client as GenericClient>::Stream: AsyncReadExt,
    {
        let mut c = self.client.lock_client();
        let cap = c.capability();

        StmtResetCommand(self.statement_id)
            .write_packet(c.stream_mut(), 0)
            .await?;
        c.stream_mut().flush().await?;
        GenericOKErrPacket::read_packet(c.stream_mut(), cap)
            .await?
            .into_result()?;

        Ok(())
    }

    /// parameters: an array of (value, unsigned flag)
    pub async fn execute(
        &mut self,
        parameters: &[(Value<'_>, bool)],
        rebound_parameters: bool,
    ) -> std::io::Result<StmtExecuteResult>
    where
        <C::Client as GenericClient>::Stream: AsyncReadExt,
    {
        let mut c = self.client.lock_client();
        let cap = c.capability();

        request_async(
            &StmtExecuteCommand {
                statement_id: self.statement_id,
                flags: StmtExecuteFlags::new(),
                parameters,
                requires_rebound_parameters: rebound_parameters,
            },
            c.stream_mut(),
            0,
            cap,
        )
        .await
    }
}
impl<'c, C: SharedMysqlClient<'c>> Drop for Statement<'c, C> {
    fn drop(&mut self) {
        eprintln!(
            "warning: statement #{} has dropped without explicit closing",
            self.statement_id
        )
    }
}

pub struct BlockingStatement<'c, C: SharedBlockingMysqlClient<'c>>
where
    <C::Client as GenericClient>::Stream: Write,
{
    client: &'c C,
    statement_id: u32,
}
impl<Stream: Write + Read> SharedBlockingClient<Stream> {
    pub fn prepare<'c, 's: 'c>(
        &'c self,
        statement: &'s str,
    ) -> Result<BlockingStatement<'c, Self>, CommunicationError> {
        let mut c = self.lock();
        let cap = c.capability;

        let resp =
            request(&StmtPrepareCommand(statement), c.stream_mut(), 0, cap)?.into_result()?;

        // simply drop unused packets
        for _ in 0..resp.num_params {
            drop_packet_sync(&mut c.stream)?;
        }
        if !c.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet_sync(&mut c.stream)?
        }

        for _ in 0..resp.num_columns {
            drop_packet_sync(&mut c.stream)?;
        }
        if !c.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet_sync(&mut c.stream)?
        }

        Ok(BlockingStatement {
            client: self,
            statement_id: resp.statement_id,
        })
    }
}
impl<'c, C: SharedBlockingMysqlClient<'c>> BlockingStatement<'c, C>
where
    <C::Client as GenericClient>::Stream: Write,
{
    pub fn close(&mut self) -> std::io::Result<()> {
        StmtCloseCommand(self.statement_id)
            .write_packet_sync(self.client.lock_client().stream_mut(), 0)?;
        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), CommunicationError>
    where
        <C::Client as GenericClient>::Stream: Read,
    {
        let mut c = self.client.lock_client();
        let cap = c.capability();

        StmtResetCommand(self.statement_id).write_packet_sync(c.stream_mut(), 0)?;
        c.stream_mut().flush()?;
        GenericOKErrPacket::read_packet_sync(c.stream_mut(), cap)?.into_result()?;

        Ok(())
    }

    /// parameters: an array of (value, unsigned flag)
    pub fn execute(
        &mut self,
        parameters: &[(Value<'_>, bool)],
        rebound_parameters: bool,
    ) -> std::io::Result<StmtExecuteResult>
    where
        <C::Client as GenericClient>::Stream: Read,
    {
        let mut c = self.client.lock_client();
        let cap = c.capability();

        request(
            &StmtExecuteCommand {
                statement_id: self.statement_id,
                flags: StmtExecuteFlags::new(),
                parameters,
                requires_rebound_parameters: rebound_parameters,
            },
            c.stream_mut(),
            0,
            cap,
        )
    }
}
impl<'c, C: SharedBlockingMysqlClient<'c>> Drop for BlockingStatement<'c, C>
where
    <C::Client as GenericClient>::Stream: Write,
{
    fn drop(&mut self) {
        self.close().expect("Failed to close prepared stmt");
    }
}

#[cfg(feature = "r2d2-integration")]
pub mod r2d2;

#[cfg(feature = "autossl")]
pub mod autossl_client;
