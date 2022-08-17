use std::{io::Write, net::ToSocketAddrs};

use parking_lot::{Mutex, MutexGuard};

use crate::{
    protos::{drop_packet_sync, ClientPacket, StmtPrepareCommand, StmtPrepareResult},
    BlockingStatement, CommunicationError, SharedBlockingMysqlClient,
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
        <Self as SharedBlockingMysqlClient<'c>>::Stream: Write,
    {
        let mut c = self.lock();
        let cap = c.capability;

        StmtPrepareCommand(statement).write_packet_sync(&mut c.stream, 0)?;
        c.stream.flush()?;
        let resp = StmtPrepareResult::read_packet_sync(&mut c.stream, cap)?.into_result()?;

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
impl<'c, A: ToSocketAddrs + Send + Sync + 'static> SharedBlockingMysqlClient<'c>
    for SharedPooledClient<MysqlTcpConnection<'static, A>>
{
    type Stream = std::net::TcpStream;
    type GuardedClientRef = LockedSharedPooledClient<'c, MysqlTcpConnection<'static, A>>;

    fn lock_client(&'c self) -> Self::GuardedClientRef {
        LockedSharedPooledClient(self.lock())
    }
}

pub struct LockedSharedPooledClient<'c, M: r2d2::ManageConnection>(
    MutexGuard<'c, r2d2::PooledConnection<M>>,
);
impl<'c, M: r2d2::ManageConnection> std::ops::Deref for LockedSharedPooledClient<'c, M> {
    type Target = M::Connection;

    fn deref(&self) -> &Self::Target {
        &**self.0
    }
}
impl<'c, M: r2d2::ManageConnection> std::ops::DerefMut for LockedSharedPooledClient<'c, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut **self.0
    }
}
