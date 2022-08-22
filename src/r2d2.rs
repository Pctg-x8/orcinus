use std::{io::Write, net::ToSocketAddrs};

use parking_lot::{Mutex, MutexGuard};

use crate::{
    protos::{drop_packet_sync, request, StmtPrepareCommand},
    BlockingStatement, CommunicationError, GenericClient, SharedBlockingMysqlClient,
};

pub struct MysqlTcpConnection<'s, A: ToSocketAddrs> {
    pub addr: A,
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

#[cfg(feature = "autossl")]
pub struct MysqlConnection<'s, A: ToSocketAddrs> {
    pub addr: A,
    pub server_name: rustls::ServerName,
    pub con_info: super::autossl_client::SSLConnectInfo<'s>,
}
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

pub struct SharedPooledClient<M: r2d2::ManageConnection>(Mutex<r2d2::PooledConnection<M>>);
impl<M: r2d2::ManageConnection> SharedPooledClient<M> {
    pub fn share_from(p: r2d2::PooledConnection<M>) -> Self {
        Self(Mutex::new(p))
    }

    pub fn unshare(self) -> r2d2::PooledConnection<M> {
        self.0.into_inner()
    }

    pub fn lock(&self) -> MutexGuard<r2d2::PooledConnection<M>> {
        self.0.lock()
    }
}

impl<A: ToSocketAddrs + Sync + Send + 'static> SharedPooledClient<MysqlTcpConnection<'static, A>> {
    pub fn prepare<'c>(
        &'c self,
        statement: &str,
    ) -> Result<BlockingStatement<'c, Self>, CommunicationError>
    where
        Self: SharedBlockingMysqlClient<'c>,
        <<Self as SharedBlockingMysqlClient<'c>>::Client as GenericClient>::Stream: Write,
    {
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
            drop_packet_sync(&mut c.stream)?;
        }

        for _ in 0..resp.num_columns {
            drop_packet_sync(&mut c.stream)?;
        }
        if !c.capability.support_deprecate_eof() {
            // extra eof packet
            drop_packet_sync(&mut c.stream)?;
        }

        Ok(BlockingStatement {
            client: self,
            statement_id: resp.statement_id,
        })
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
impl<'c, M: r2d2::ManageConnection> SharedBlockingMysqlClient<'c> for SharedPooledClient<M>
where
    r2d2::PooledConnection<M>: GenericClient,
{
    type Client = r2d2::PooledConnection<M>;
    type GuardedClientRef = MutexGuard<'c, r2d2::PooledConnection<M>>;

    fn lock_client(&'c self) -> Self::GuardedClientRef {
        self.lock()
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
#[cfg(feature = "autossl")]
impl<A: ToSocketAddrs + Sync + Send + 'static> SharedPooledClient<MysqlConnection<'static, A>> {
    pub fn prepare<'c>(
        &'c self,
        statement: &str,
    ) -> Result<BlockingStatement<'c, Self>, CommunicationError>
    where
        Self: SharedBlockingMysqlClient<'c>,
        <<Self as SharedBlockingMysqlClient<'c>>::Client as GenericClient>::Stream: Write,
    {
        let mut c = self.lock();
        let cap = c.capability();

        let resp =
            request(&StmtPrepareCommand(statement), c.stream_mut(), 0, cap)?.into_result()?;

        // simply drop unused packets
        for _ in 0..resp.num_params {
            drop_packet_sync(c.stream_mut())?;
        }
        if !cap.support_deprecate_eof() {
            // extra eof packet
            drop_packet_sync(c.stream_mut())?;
        }

        for _ in 0..resp.num_columns {
            drop_packet_sync(c.stream_mut())?;
        }
        if !cap.support_deprecate_eof() {
            // extra eof packet
            drop_packet_sync(c.stream_mut())?;
        }

        Ok(BlockingStatement {
            client: self,
            statement_id: resp.statement_id,
        })
    }
}
