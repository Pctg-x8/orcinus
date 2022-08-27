//! r2d2 connection pooling integration

use std::net::ToSocketAddrs;

use crate::GenericClient;

/// Plain TCP Connection Manager.
pub struct MysqlTcpConnection<'s, A: ToSocketAddrs> {
    /// Address to connect.
    pub addr: A,
    /// An information structure for connection(passed to `BlockingClient::handshake`).
    pub con_info: super::ConnectInfo<'s>,
}
impl<A: ToSocketAddrs + Send + Sync + 'static> r2d2::ManageConnection
    for MysqlTcpConnection<'static, A>
{
    type Connection = super::BlockingClient<std::net::TcpStream>;
    type Error = super::CommunicationError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let stream = std::net::TcpStream::connect(&self.addr)?;
        super::BlockingClient::handshake(stream, &self.con_info)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.fetch_all("Select 1")
            .map_err(From::from)
            .and_then(|mut s| s.drop_all_rows())
    }
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        self.is_valid(conn).is_err()
    }
}

impl<A: ToSocketAddrs + Send + Sync + 'static> GenericClient
    for r2d2::PooledConnection<MysqlTcpConnection<'static, A>>
{
    type Stream = std::net::TcpStream;

    fn stream(&self) -> &Self::Stream {
        &self.stream
    }
    fn stream_mut(&mut self) -> &mut Self::Stream {
        &mut self.stream
    }
    fn capability(&self) -> crate::protos::CapabilityFlags {
        self.capability
    }
}

#[cfg(feature = "autossl")]
#[cfg_attr(docsrs, doc(cfg(feature = "autossl")))]
/// TCP/TLS Connection Manager.
pub struct MysqlConnection<'s, A: ToSocketAddrs> {
    /// Address to connect.
    pub addr: A,
    /// Destination server name(used in SNI).
    pub server_name: rustls::ServerName,
    /// An information structure for connection(passed to `autossl_client::BlockingClient::new`)
    pub con_info: super::autossl_client::SSLConnectInfo<'s>,
}
#[cfg(feature = "autossl")]
impl<A: ToSocketAddrs + Send + Sync + 'static> r2d2::ManageConnection
    for MysqlConnection<'static, A>
{
    type Connection = super::autossl_client::BlockingClient;
    type Error = super::autossl_client::ConnectionError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        super::autossl_client::BlockingClient::new(
            &self.addr,
            self.server_name.clone(),
            &self.con_info,
        )
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.fetch_all("Select 1")
            .map_err(From::from)
            .and_then(|mut s| s.drop_all_rows())
            .map_err(From::from)
    }
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        self.is_valid(conn).is_err()
    }
}

#[cfg(feature = "autossl")]
impl<A: ToSocketAddrs + Send + Sync + 'static> GenericClient
    for r2d2::PooledConnection<MysqlConnection<'static, A>>
{
    type Stream = super::autossl_client::DynamicStream;

    fn stream(&self) -> &Self::Stream {
        (**self).stream()
    }
    fn stream_mut(&mut self) -> &mut Self::Stream {
        (**self).stream_mut()
    }
    fn capability(&self) -> crate::protos::CapabilityFlags {
        (**self).capability()
    }
}
