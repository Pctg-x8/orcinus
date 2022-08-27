//! TCP/TLS autoswitching client.

use std::{
    io::{Read, Write},
    net::ToSocketAddrs,
    sync::Arc,
};

use bufstream::BufStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    authentication::{self, AsyncAuthentication, Authentication},
    protos::{
        request, write_packet, write_packet_sync, AsyncReceivePacket, CapabilityFlags, ErrPacket,
        Handshake, QueryCommand, QueryCommandResponse, QuitCommand, SSLRequest,
    },
    BinaryResultsetIterator, BinaryResultsetStream, CommunicationError, GenericClient,
    SharedClient, TextResultsetIterator, TextResultsetStream,
};

pub struct SSLConnectInfo<'s> {
    pub base: super::ConnectInfo<'s>,
    pub ssl_config: Arc<rustls::ClientConfig>,
}

#[derive(Debug)]
pub enum ConnectionError {
    IO(std::io::Error),
    Server(ErrPacket),
    TLS(rustls::Error),
}
impl From<std::io::Error> for ConnectionError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}
impl From<ErrPacket> for ConnectionError {
    fn from(e: ErrPacket) -> Self {
        Self::Server(e)
    }
}
impl From<rustls::Error> for ConnectionError {
    fn from(e: rustls::Error) -> Self {
        Self::TLS(e)
    }
}
impl From<CommunicationError> for ConnectionError {
    fn from(e: CommunicationError) -> Self {
        match e {
            CommunicationError::IO(e) => Self::IO(e),
            CommunicationError::Server(e) => Self::Server(e),
        }
    }
}
impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IO(io) => write!(f, "IO Error: {io}"),
            Self::Server(e) => write!(f, "Server Error: {}", e.error_message),
            Self::TLS(e) => write!(f, "TLS Error: {e}"),
        }
    }
}
impl std::error::Error for ConnectionError {}

pub trait BidirectionalStream: Write + Read {}
impl<T: Write + Read> BidirectionalStream for T {}

pub trait AsyncBidirectionalStream: AsyncWrite + AsyncRead {}
impl<T: AsyncWrite + AsyncRead> AsyncBidirectionalStream for T {}

pub(crate) type DynamicStream = BufStream<Box<dyn BidirectionalStream + Send + Sync>>;
pub struct BlockingClient {
    stream: DynamicStream,
    capability: CapabilityFlags,
}
impl BlockingClient {
    pub fn new(
        addr: impl ToSocketAddrs,
        server_name: rustls::ServerName,
        connect_info: &SSLConnectInfo,
    ) -> Result<Self, ConnectionError> {
        let stream = std::net::TcpStream::connect(addr)?;
        let mut stream =
            BufStream::new(Box::new(stream) as Box<dyn BidirectionalStream + Send + Sync>);
        let (server_handshake, mut sequence_id) = Handshake::read_packet_sync(&mut stream)?;

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
        if connect_info.base.database.is_some() {
            required_caps.set_connect_with_db();
        }

        let capability;
        if server_caps.support_ssl() {
            // try to ssl negotiation
            required_caps.set_support_ssl();
            capability = required_caps & server_caps;

            write_packet_sync(
                &mut stream,
                SSLRequest {
                    capability,
                    max_packet_size: connect_info.base.max_packet_size,
                    character_set: connect_info.base.character_set,
                },
                sequence_id + 1,
            )?;
            sequence_id += 1;
            stream.flush()?;
            let con = rustls::ClientConnection::new(connect_info.ssl_config.clone(), server_name)?;
            let tls_stream = rustls::StreamOwned::new(
                con,
                match stream.into_inner() {
                    Ok(x) => x,
                    Err(e) => panic!("Failed to unwrap bufreaders: {:?}", e.error()),
                },
            );
            stream =
                BufStream::new(Box::new(tls_stream) as Box<dyn BidirectionalStream + Send + Sync>);
        } else {
            capability = required_caps & server_caps;
        }

        let con_info = authentication::ConnectionInfo {
            client_capabilities: capability,
            max_packet_size: connect_info.base.max_packet_size,
            character_set: connect_info.base.character_set,
            username: connect_info.base.username,
            password: connect_info.base.password,
            database: connect_info.base.database,
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

        Ok(Self { stream, capability })
    }

    #[inline]
    pub fn share(self) -> SharedClient<Self> {
        SharedClient::share_from(self)
    }

    pub fn quit(&mut self) -> std::io::Result<()> {
        write_packet_sync(&mut self.stream, QuitCommand, 0)
    }

    pub fn query(&mut self, query: &str) -> std::io::Result<QueryCommandResponse> {
        request(QueryCommand(query), &mut self.stream, 0, self.capability)
    }

    pub fn fetch_all<'s>(
        &'s mut self,
        query: &str,
    ) -> Result<TextResultsetIterator<&'s mut DynamicStream>, CommunicationError> {
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
    ) -> std::io::Result<TextResultsetIterator<&mut DynamicStream>> {
        TextResultsetIterator::new(&mut self.stream, column_count, self.capability)
    }

    pub fn binary_resultset_iterator(
        &mut self,
        column_count: usize,
    ) -> std::io::Result<BinaryResultsetIterator<&mut DynamicStream>> {
        BinaryResultsetIterator::new(&mut self.stream, column_count, self.capability)
    }
}
impl Drop for BlockingClient {
    fn drop(&mut self) {
        self.quit().expect("Failed to send quit packet at drop")
    }
}

pub(crate) type AsyncDynamicStream =
    tokio::io::BufStream<Box<dyn AsyncBidirectionalStream + Send + Sync + Unpin + 'static>>;
pub struct Client {
    stream: AsyncDynamicStream,
    capability: CapabilityFlags,
}
impl Client {
    pub async fn new(
        addr: impl tokio::net::ToSocketAddrs,
        server_name: rustls::ServerName,
        connect_info: &SSLConnectInfo<'_>,
    ) -> Result<Self, CommunicationError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let mut stream = tokio::io::BufStream::new(Box::new(stream) as Box<_>);
        let (server_handshake, mut sequence_id) = Handshake::read_packet(&mut stream).await?;

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
        if connect_info.base.database.is_some() {
            required_caps.set_connect_with_db();
        }

        let capability;
        if server_caps.support_ssl() {
            // try to ssl negotiation
            required_caps.set_support_ssl();
            capability = required_caps & server_caps;

            write_packet(
                &mut stream,
                SSLRequest {
                    capability,
                    max_packet_size: connect_info.base.max_packet_size,
                    character_set: connect_info.base.character_set,
                },
                sequence_id + 1,
            )
            .await?;
            sequence_id += 1;
            stream.flush().await?;
            let tls_stream = tokio_rustls::TlsConnector::from(connect_info.ssl_config.clone())
                .connect(server_name, stream.into_inner())
                .await?;
            stream = tokio::io::BufStream::new(Box::new(tls_stream) as Box<_>);
        } else {
            capability = required_caps & server_caps;
        }

        let con_info = authentication::ConnectionInfo {
            client_capabilities: capability,
            max_packet_size: connect_info.base.max_packet_size,
            character_set: connect_info.base.character_set,
            username: connect_info.base.username,
            password: connect_info.base.password,
            database: connect_info.base.database,
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

        Ok(Self { stream, capability })
    }

    pub fn share(self) -> SharedClient<Self> {
        SharedClient::share_from(self)
    }

    pub async fn quit(&mut self) -> std::io::Result<()> {
        write_packet(&mut self.stream, QuitCommand, 0).await?;
        Ok(())
    }

    pub async fn query(&mut self, query: &str) -> std::io::Result<QueryCommandResponse> {
        write_packet(&mut self.stream, QueryCommand(query), 0).await?;
        self.stream.flush().await?;
        QueryCommandResponse::read_packet_async(&mut self.stream, self.capability).await
    }

    pub async fn fetch_all<'s>(
        &'s mut self,
        query: &'s str,
    ) -> Result<TextResultsetStream<'s, AsyncDynamicStream>, CommunicationError> {
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
    ) -> std::io::Result<TextResultsetStream<'s, AsyncDynamicStream>> {
        TextResultsetStream::new(&mut self.stream, column_count, self.capability).await
    }

    pub async fn binary_resultset_stream<'s>(
        &'s mut self,
        column_count: usize,
    ) -> std::io::Result<BinaryResultsetStream<'s, AsyncDynamicStream>> {
        BinaryResultsetStream::new(&mut self.stream, self.capability, column_count).await
    }
}

impl GenericClient for Client {
    type Stream = AsyncDynamicStream;

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
impl GenericClient for BlockingClient {
    type Stream = DynamicStream;

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
