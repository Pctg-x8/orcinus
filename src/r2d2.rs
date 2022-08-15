use parking_lot::{Mutex, MutexGuard};
use tokio::{io::AsyncWriteExt, net::ToSocketAddrs};

use crate::{
    protos::{drop_packet, ClientPacket, StmtPrepareCommand, StmtPrepareResult},
    CommunicationError, Statement,
};

pub struct MysqlTcpConnection<'s, A: ToSocketAddrs> {
    pub addr: A,
    pub con_info: super::ConnectInfo<'s>,
}
impl<A: ToSocketAddrs + Send + Sync + 'static> r2d2::ManageConnection
    for MysqlTcpConnection<'static, A>
{
    type Connection = super::Client<tokio::io::BufStream<tokio::net::TcpStream>>;
    type Error = super::CommunicationError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(async {
                let stream = tokio::net::TcpStream::connect(&self.addr).await?;
                let stream = tokio::io::BufStream::new(stream);

                super::Client::handshake(stream, &self.con_info).await
            })
    }
    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(async { conn.query("Select 1").await.map(|_| ()).map_err(From::from) })
    }
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        self.is_valid(conn).is_err()
    }
}

pub struct SharedPooledClient<M: r2d2::ManageConnection>(Mutex<r2d2::PooledConnection<M>>);
impl<M: r2d2::ManageConnection> SharedPooledClient<M> {
    pub fn share_from(pooled_client: r2d2::PooledConnection<M>) -> Self {
        Self(Mutex::new(pooled_client))
    }

    pub fn unshare(self) -> r2d2::PooledConnection<M> {
        self.0.into_inner()
    }

    pub fn lock(&self) -> MutexGuard<r2d2::PooledConnection<M>> {
        self.0.lock()
    }
}
pub struct GuardedSharedPooledClient<'a, M: r2d2::ManageConnection>(
    MutexGuard<'a, r2d2::PooledConnection<M>>,
);
impl<'a, M: r2d2::ManageConnection> std::ops::Deref for GuardedSharedPooledClient<'a, M> {
    type Target = M::Connection;

    fn deref(&self) -> &Self::Target {
        &**self.0
    }
}
impl<'a, M: r2d2::ManageConnection> std::ops::DerefMut for GuardedSharedPooledClient<'a, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut **self.0
    }
}
impl<'c, A: Send + Sync + ToSocketAddrs + 'static> super::SharedMysqlClient<'c>
    for SharedPooledClient<MysqlTcpConnection<'static, A>>
{
    type Stream = tokio::io::BufStream<tokio::net::TcpStream>;
    type GuardedClientRef = GuardedSharedPooledClient<'c, MysqlTcpConnection<'static, A>>;

    fn lock_client(&'c self) -> Self::GuardedClientRef {
        GuardedSharedPooledClient(self.0.lock())
    }
}
impl<A: Send + Sync + ToSocketAddrs + 'static> SharedPooledClient<MysqlTcpConnection<'static, A>> {
    pub async fn prepare<'c, 's: 'c>(
        &'c self,
        statement: &'s str,
    ) -> Result<Statement<'c, Self>, CommunicationError> {
        let mut c = self.lock();
        let cap = c.capability;

        StmtPrepareCommand(statement)
            .write_packet(&mut c.stream, 0)
            .await?;
        c.stream.flush().await?;
        let resp = StmtPrepareResult::read_packet(&mut c.stream, cap)
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
