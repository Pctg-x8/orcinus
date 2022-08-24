use async_trait::async_trait;
use parking_lot::{Mutex, MutexGuard};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::ToSocketAddrs,
};

use crate::{
    protos::{drop_packet, request_async, StmtPrepareCommand},
    CommunicationError, GenericClient, SharedMysqlClient, Statement,
};

pub struct MysqlTcpConnection<'s, A: ToSocketAddrs> {
    pub addr: A,
    pub con_info: super::ConnectInfo<'s>,
}
#[async_trait]
impl<A: ToSocketAddrs + Send + Sync + 'static> bb8::ManageConnection
    for MysqlTcpConnection<'static, A>
{
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

#[cfg(feature = "autossl")]
pub struct MysqlConnection<'s, A: ToSocketAddrs> {
    pub addr: A,
    pub server_name: rustls::ServerName,
    pub con_info: super::autossl_client::SSLConnectInfo<'s>,
}
#[cfg(feature = "autossl")]
#[async_trait]
impl<A: ToSocketAddrs + Send + Sync + 'static> bb8::ManageConnection
    for MysqlConnection<'static, A>
{
    type Connection = super::autossl_client::Client;
    type Error = super::autossl_client::ConnectionError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        super::autossl_client::Client::new(&self.addr, self.server_name.clone(), &self.con_info)
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

pub struct SharedPooledClient<'a, M: bb8::ManageConnection>(Mutex<bb8::PooledConnection<'a, M>>);
impl<'a, M: bb8::ManageConnection> SharedPooledClient<'a, M> {
    pub fn share_from(p: bb8::PooledConnection<'a, M>) -> Self {
        Self(Mutex::new(p))
    }

    pub fn unshare(self) -> bb8::PooledConnection<'a, M> {
        self.0.into_inner()
    }

    pub fn lock(&self) -> MutexGuard<bb8::PooledConnection<'a, M>> {
        self.0.lock()
    }
}
impl<'a: 'c, 'c, M: bb8::ManageConnection> SharedMysqlClient<'c> for SharedPooledClient<'a, M>
where
    bb8::PooledConnection<'a, M>: GenericClient,
{
    type Client = bb8::PooledConnection<'a, M>;
    type GuardedClientRef = MutexGuard<'c, bb8::PooledConnection<'a, M>>;

    fn lock_client(&'c self) -> Self::GuardedClientRef {
        self.lock()
    }
}
impl<'a, M: bb8::ManageConnection> SharedPooledClient<'a, M> {
    pub async fn prepare<'c>(
        &'c self,
        statement: &str,
    ) -> Result<Statement<'c, SharedPooledClient<'a, M>>, CommunicationError>
    where
        Self: SharedMysqlClient<'c>,
        bb8::PooledConnection<'a, M>: GenericClient,
        <bb8::PooledConnection<'a, M> as GenericClient>::Stream:
            AsyncWrite + AsyncRead + Unpin + Send + Sync,
    {
        let mut c = self.lock();
        let cap = c.capability();

        let resp = request_async(StmtPrepareCommand(statement), c.stream_mut(), 0, cap)
            .await?
            .into_result()?;

        // simply drop unused packets
        for _ in 0..resp.num_params {
            drop_packet(c.stream_mut()).await?;
        }
        if !cap.support_deprecate_eof() {
            // extra eof packet
            drop_packet(c.stream_mut()).await?;
        }

        for _ in 0..resp.num_columns {
            drop_packet(c.stream_mut()).await?;
        }
        if !cap.support_deprecate_eof() {
            // extra eof packet
            drop_packet(c.stream_mut()).await?;
        }

        Ok(Statement {
            client: self,
            statement_id: resp.statement_id,
        })
    }
}

impl<A: ToSocketAddrs + Send + Sync + 'static> GenericClient
    for bb8::PooledConnection<'_, MysqlTcpConnection<'static, A>>
{
    type Stream = tokio::net::TcpStream;

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
impl<A: ToSocketAddrs + Send + Sync + 'static> GenericClient
    for bb8::PooledConnection<'_, MysqlConnection<'static, A>>
{
    type Stream = super::autossl_client::AsyncDynamicStream;

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
