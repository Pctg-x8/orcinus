#![cfg_attr(docsrs, feature(doc_cfg))]

//! https://ja.wikipedia.org/wiki/%E3%82%B7%E3%83%A3%E3%83%81
//!
//! async-ready mysql protocol implementation and wrapper libraries.
//!
//! Examples(usage) are in the [repository](https://github.com/Pctg-x8/orcinus)

mod mysql;
use std::io::{Read, Write};

use mysql::authentication::AsyncAuthentication;
use mysql::protos::drop_packet;
use mysql::protos::drop_packet_sync;
use mysql::protos::request;
use mysql::protos::request_async;
use mysql::protos::write_packet;
use mysql::protos::write_packet_sync;
use mysql::protos::AsyncReceivePacket;
use mysql::protos::CapabilityFlags;
use mysql::protos::ErrPacket;
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
use parking_lot::MutexGuard;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;

use crate::authentication::Authentication;
use crate::protos::Handshake;

pub use self::mysql::*;

mod resultset_stream;
pub use self::resultset_stream::*;

/// Composited error while communicating with MySQL server.
#[derive(Debug)]
pub enum CommunicationError {
    /// IO Error from socket
    IO(std::io::Error),
    /// Error packet returned from server
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

/// An information structure to connect to MySQL server.
pub struct ConnectInfo<'s> {
    username: &'s str,
    password: &'s str,
    database: Option<&'s str>,
    max_packet_size: u32,
    character_set: u8,
}
impl<'s> ConnectInfo<'s> {
    /// Build an information structure with username and password.
    pub fn new(username: &'s str, password: &'s str) -> Self {
        Self {
            username,
            password,
            database: None,
            max_packet_size: 16777216,
            character_set: 0xff,
        }
    }

    /// Set initial connected database name: default is `None`
    pub fn database(mut self, db_name: &'s str) -> Self {
        self.database = Some(db_name);
        self
    }

    /// Set max packet size: default is big enough value
    pub fn max_packet_size(mut self, packet_size: u32) -> Self {
        self.max_packet_size = packet_size;
        self
    }

    /// Set character set: default is utf8mb4
    pub fn character_set(mut self, character_set: u8) -> Self {
        self.character_set = character_set;
        self
    }
}

/// A MySQL Client that provides blocking operations.
///
/// This can be used for non-asynchronous environment(such as r2d2-integrated app, or non-asynchronous web server framework).
pub struct BlockingClient<Stream: Write> {
    stream: Stream,
    capability: CapabilityFlags,
}
impl<Stream: Write> BlockingClient<Stream> {
    /// Negotiate handshake protocol with MySQL server on specified stream and information.
    pub fn handshake(mut stream: Stream, connect_info: &ConnectInfo) -> Result<Self, CommunicationError>
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

    /// Create Blocking Client with already handshaked streams.
    ///
    /// this function does not perform handshaking. user must be done the operation.
    pub unsafe fn new(stream: Stream, capability: CapabilityFlags) -> Self {
        Self { stream, capability }
    }

    /// Quit communication with server.
    pub fn quit(&mut self) -> std::io::Result<()> {
        write_packet_sync(&mut self.stream, QuitCommand, 0)
    }

    /// Post SQL statement to server.
    pub fn query(&mut self, query: &str) -> std::io::Result<QueryCommandResponse>
    where
        Stream: Read,
    {
        request(QueryCommand(query), &mut self.stream, 0, self.capability)
    }

    /// Post SQL statement to server, and fetch result sets by iterator(fetching is lazily executed).
    pub fn fetch_all<'s>(&'s mut self, query: &str) -> Result<TextResultsetIterator<&'s mut Stream>, CommunicationError>
    where
        Stream: Read,
    {
        match self.query(query)? {
            QueryCommandResponse::Resultset { column_count } => {
                self.text_resultset_iterator(column_count as _).map_err(From::from)
            }
            QueryCommandResponse::Err(e) => Err(CommunicationError::from(e)),
            QueryCommandResponse::Ok(_) => unreachable!("OK Returned"),
            QueryCommandResponse::LocalInfileRequest { filename } => {
                todo!("local infile request: {filename}")
            }
        }
    }

    /// Fetch result sets of last query execution by iterator(fetching is lazily executed).
    pub fn text_resultset_iterator(
        &mut self,
        column_count: usize,
    ) -> std::io::Result<TextResultsetIterator<&mut Stream>>
    where
        Stream: Read,
    {
        TextResultsetIterator::new(&mut self.stream, column_count, self.capability)
    }

    /// Fetch result sets of last prepared statement execution by iterator(fetching is lazily executed).
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
    /// Make non-blocking client.
    pub fn into_async(self) -> Client<tokio::io::BufStream<tokio::net::TcpStream>> {
        let stream = unsafe { std::ptr::read(&self.stream as *const std::net::TcpStream) };
        let capability = self.capability;
        std::mem::forget(self);

        stream.set_nonblocking(true).expect("Failed to switch blocking mode");

        Client {
            stream: tokio::io::BufStream::new(
                tokio::net::TcpStream::from_std(stream).expect("Failed to wrap std stream"),
            ),
            capability,
        }
    }
}

/// A MySQL Client that provides non-blocking operations.
pub struct Client<Stream: AsyncWriteExt + Send + Sync + Unpin> {
    stream: Stream,
    capability: CapabilityFlags,
}
impl<Stream: AsyncWriteExt + Send + Sync + Unpin> Client<Stream> {
    /// Negotiate handshake protocol with MySQL server on specified stream and information.
    pub async fn handshake(mut stream: Stream, connect_info: &ConnectInfo<'_>) -> Result<Self, CommunicationError>
    where
        Stream: AsyncRead + 'static,
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

    /// Create Blocking Client with already handshaked streams.
    ///
    /// this function does not perform handshaking. user must be done the operation.
    pub unsafe fn new(stream: Stream, capability: CapabilityFlags) -> Self {
        Self { stream, capability }
    }

    /// Quit communication with server.
    pub async fn quit(&mut self) -> std::io::Result<()> {
        write_packet(&mut self.stream, QuitCommand, 0).await?;
        Ok(())
    }

    /// Post SQL statement to server.
    pub async fn query(&mut self, query: &str) -> std::io::Result<QueryCommandResponse>
    where
        Stream: AsyncRead,
    {
        write_packet(&mut self.stream, QueryCommand(query), 0).await?;
        self.stream.flush().await?;
        QueryCommandResponse::read_packet_async(&mut self.stream, self.capability).await
    }

    /// Post SQL statement to server, and fetch result sets by stream(fetching is lazily executed).
    pub async fn fetch_all<'s>(
        &'s mut self,
        query: &'s str,
    ) -> Result<TextResultsetStream<'s, Stream>, CommunicationError>
    where
        Stream: AsyncRead,
    {
        match self.query(query).await? {
            QueryCommandResponse::Resultset { column_count } => {
                self.text_resultset_stream(column_count as _).await.map_err(From::from)
            }
            QueryCommandResponse::Err(e) => Err(CommunicationError::from(e)),
            QueryCommandResponse::Ok(_) => unreachable!("OK Returned"),
            QueryCommandResponse::LocalInfileRequest { filename } => {
                todo!("local infile request: {filename}")
            }
        }
    }

    /// Fetch result sets of last query execution by stream(fetching is lazily executed).
    pub async fn text_resultset_stream<'s>(
        &'s mut self,
        column_count: usize,
    ) -> std::io::Result<TextResultsetStream<'s, Stream>>
    where
        Stream: AsyncRead,
    {
        TextResultsetStream::new(&mut self.stream, column_count, self.capability).await
    }

    /// Fetch result sets of last prepared statement execution by stream(fetching is lazily executed).
    pub async fn binary_resultset_stream<'s>(
        &'s mut self,
        column_count: usize,
    ) -> std::io::Result<BinaryResultsetStream<'s, Stream>>
    where
        Stream: AsyncRead,
    {
        BinaryResultsetStream::new(&mut self.stream, self.capability, column_count).await
    }
}
impl<Stream: AsyncWriteExt + Send + Sync + Unpin> Drop for Client<Stream> {
    fn drop(&mut self) {
        eprintln!("warning: client has dropped without explicit quit command");
    }
}

/// Common client-capable implementation.
pub trait GenericClient {
    /// Stream object that used communicating with server.
    type Stream;

    /// Retrieve stream by immutable reference.
    fn stream(&self) -> &Self::Stream;
    /// Retrieve stream by mutable reference.
    fn stream_mut(&mut self) -> &mut Self::Stream;
    /// Client side capability flags.
    fn capability(&self) -> CapabilityFlags;
}
impl<C: GenericClient> GenericClient for MutexGuard<'_, C> {
    type Stream = C::Stream;

    fn stream(&self) -> &Self::Stream {
        C::stream(self)
    }
    fn stream_mut(&mut self) -> &mut Self::Stream {
        C::stream_mut(self)
    }
    fn capability(&self) -> CapabilityFlags {
        C::capability(self)
    }
}
impl<C: GenericClient> GenericClient for Box<C> {
    type Stream = C::Stream;

    fn stream(&self) -> &Self::Stream {
        C::stream(self)
    }
    fn stream_mut(&mut self) -> &mut Self::Stream {
        C::stream_mut(self)
    }
    fn capability(&self) -> CapabilityFlags {
        C::capability(self)
    }
}
impl<S: AsyncWriteExt + Send + Sync + Unpin> GenericClient for Client<S> {
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

/// Represents Prepared Statement.
#[repr(transparent)]
pub struct Statement(u32);
/// Prepared Statement Ops
impl<Stream: AsyncWriteExt + Sync + Send + Unpin> Client<Stream> {
    /// Prepare the statement.
    pub async fn prepare(&mut self, statement: &str) -> Result<Statement, CommunicationError>
    where
        Stream: AsyncRead,
    {
        let resp = request_async(StmtPrepareCommand(statement), &mut self.stream, 0, self.capability)
            .await?
            .into_result()?;

        // simply drop unused packets
        for _ in 0..resp.num_params {
            drop_packet(&mut self.stream).await?;
        }
        if !self.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet(&mut self.stream).await?
        }

        for _ in 0..resp.num_columns {
            drop_packet(&mut self.stream).await?;
        }
        if !self.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet(&mut self.stream).await?
        }

        Ok(Statement(resp.statement_id))
    }

    /// Close the Prepared Statement.
    pub async fn close_statement(&mut self, statement: Statement) -> std::io::Result<()> {
        write_packet(&mut self.stream, StmtCloseCommand(statement.0), 0).await
    }

    /// Reset the Prepared Statement.
    pub async fn reset_statement(&mut self, statement: &Statement) -> Result<(), CommunicationError>
    where
        Stream: AsyncRead,
    {
        request_async(StmtResetCommand(statement.0), &mut self.stream, 0, self.capability)
            .await?
            .into_result()
            .map(drop)
            .map_err(From::from)
    }

    /// Execute statement with binding parameters.
    ///
    /// parameters: an array of (value, unsigned flag)
    pub async fn execute_statement(
        &mut self,
        statement: &Statement,
        parameters: &[(Value<'_>, bool)],
        rebound_parameters: bool,
    ) -> std::io::Result<StmtExecuteResult>
    where
        Stream: AsyncRead,
    {
        request_async(
            StmtExecuteCommand {
                statement_id: statement.0,
                flags: StmtExecuteFlags::new(),
                parameters,
                requires_rebound_parameters: rebound_parameters,
            },
            &mut self.stream,
            0,
            self.capability,
        )
        .await
    }
}

/// Prepared Statement Ops
impl<Stream: Write> BlockingClient<Stream> {
    /// Prepare the statement.
    pub fn prepare(&mut self, statement: &str) -> Result<Statement, CommunicationError>
    where
        Stream: Read,
    {
        let resp = request(StmtPrepareCommand(statement), &mut self.stream, 0, self.capability)?.into_result()?;

        // simply drop unused packets
        for _ in 0..resp.num_params {
            drop_packet_sync(&mut self.stream)?;
        }
        if !self.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet_sync(&mut self.stream)?
        }

        for _ in 0..resp.num_columns {
            drop_packet_sync(&mut self.stream)?;
        }
        if !self.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet_sync(&mut self.stream)?
        }

        Ok(Statement(resp.statement_id))
    }

    /// Close the Prepared Statement.
    pub fn close_statement(&mut self, statement: Statement) -> std::io::Result<()> {
        write_packet_sync(&mut self.stream, StmtCloseCommand(statement.0), 0)
    }

    /// Reset the Prepared Statement.
    pub fn reset_statement(&mut self, statement: &Statement) -> Result<(), CommunicationError>
    where
        Stream: Read,
    {
        request(StmtResetCommand(statement.0), &mut self.stream, 0, self.capability)?
            .into_result()
            .map(drop)
            .map_err(From::from)
    }

    /// Execute statement with binding parameters.
    ///
    /// parameters: an array of (value, unsigned flag)
    pub fn execute(
        &mut self,
        statement: &Statement,
        parameters: &[(Value<'_>, bool)],
        rebound_parameters: bool,
    ) -> std::io::Result<StmtExecuteResult>
    where
        Stream: Read,
    {
        request(
            StmtExecuteCommand {
                statement_id: statement.0,
                flags: StmtExecuteFlags::new(),
                parameters,
                requires_rebound_parameters: rebound_parameters,
            },
            &mut self.stream,
            0,
            self.capability,
        )
    }
}

mod async_utils;
mod counted_read;

#[cfg(feature = "r2d2-integration")]
#[cfg_attr(docsrs, doc(cfg(feature = "r2d2-integration")))]
pub mod r2d2;

#[cfg(feature = "bb8-integration")]
#[cfg_attr(docsrs, doc(cfg(feature = "bb8-integration")))]
pub mod bb8;

#[cfg(feature = "autossl")]
#[cfg_attr(docsrs, doc(cfg(feature = "autossl")))]
pub mod autossl_client;
