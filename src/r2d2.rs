use std::net::ToSocketAddrs;

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
        conn.query("Select 1").map(|_| ()).map_err(From::from)
    }
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        self.is_valid(conn).is_err()
    }
}
