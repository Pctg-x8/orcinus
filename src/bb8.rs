//! bb8 asynchronous connection pooling integration

use async_trait::async_trait;
use tokio::net::ToSocketAddrs;

use crate::GenericClient;

/// Plain TCP Connection Manager.
pub struct MysqlTcpConnection<'s, A: ToSocketAddrs> {
    /// Address to connect.
    pub addr: A,
    /// An information structure for connection(passed to `Client::handshake`).
    pub con_info: super::ConnectInfo<'s>,
}
#[async_trait]
impl<A: ToSocketAddrs + Send + Sync + 'static> bb8::ManageConnection for MysqlTcpConnection<'static, A> {
    type Connection = super::Client<tokio::net::TcpStream>;
    type Error = super::CommunicationError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let stream = tokio::net::TcpStream::connect(&self.addr).await?;
        super::Client::handshake(stream, &self.con_info).await
    }
    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        let mut s = conn.fetch_all("Select 1").await?;
        s.drop_all_rows().await?;
        Ok(())
    }
    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

impl<M: bb8::ManageConnection> GenericClient for bb8::PooledConnection<'_, M>
where
    M::Connection: GenericClient,
{
    type Stream = <M::Connection as GenericClient>::Stream;

    fn stream(&self) -> &Self::Stream {
        M::Connection::stream(self)
    }
    fn stream_mut(&mut self) -> &mut Self::Stream {
        M::Connection::stream_mut(self)
    }
    fn capability(&self) -> crate::protos::CapabilityFlags {
        M::Connection::capability(self)
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
#[async_trait]
impl<A: ToSocketAddrs + Send + Sync + 'static> bb8::ManageConnection for MysqlConnection<'static, A> {
    type Connection = super::Client<super::autossl_client::AsyncDynamicStream>;
    type Error = super::autossl_client::ConnectionError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        super::Client::connect_autossl(&self.addr, self.server_name.clone(), &self.con_info)
            .await
            .map_err(From::from)
    }
    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        let mut s = conn.fetch_all("Select 1").await?;
        s.drop_all_rows().await?;
        Ok(())
    }
    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}
