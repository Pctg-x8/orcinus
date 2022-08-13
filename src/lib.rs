mod mysql;
use mysql::protos::drop_packet;
use mysql::protos::CapabilityFlags;
use mysql::protos::ClientPacket;
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
use mysql::protos::StmtPrepareResult;
use mysql::protos::StmtResetCommand;
use mysql::protos::Value;
use parking_lot::Mutex;
use parking_lot::MutexGuard;
use tokio::io::AsyncWriteExt;

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

pub struct SharedClient<Stream: AsyncWriteExt + Unpin>(Mutex<Client<Stream>>);
impl<Stream: AsyncWriteExt + Unpin> SharedClient<Stream> {
    pub fn unshare(self) -> Client<Stream> {
        self.0.into_inner()
    }

    pub fn lock(&self) -> MutexGuard<Client<Stream>> {
        self.0.lock()
    }
}

pub struct Client<Stream: AsyncWriteExt + Unpin> {
    stream: Stream,
    capability: CapabilityFlags,
}
impl<Stream: AsyncWriteExt + Unpin> Client<Stream> {
    /// TODO
    pub fn new(stream: Stream, capability: CapabilityFlags) -> Self {
        Self {
            stream: stream,
            capability,
        }
    }

    pub fn share(self) -> SharedClient<Stream> {
        SharedClient(Mutex::new(self))
    }

    pub async fn quit(mut self) -> std::io::Result<()> {
        QuitCommand.write_packet(&mut self.stream, 0).await?;
        std::mem::forget(self);
        Ok(())
    }

    pub async fn query(&mut self, query: &str) -> std::io::Result<QueryCommandResponse>
    where
        Stream: PacketReader,
    {
        QueryCommand(query)
            .write_packet(&mut self.stream, 0)
            .await?;
        self.stream.flush().await?;
        QueryCommandResponse::read_packet(&mut self.stream, self.capability).await
    }

    pub async fn fetch_all<'s>(
        &'s mut self,
        query: &str,
    ) -> Result<TextResultsetStream<'s, Stream>, CommunicationError>
    where
        Stream: PacketReader,
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

    pub async fn text_resultset_stream(
        &mut self,
        column_count: usize,
    ) -> std::io::Result<TextResultsetStream<Stream>>
    where
        Stream: PacketReader,
    {
        TextResultsetStream::new(&mut self.stream, column_count, self.capability).await
    }

    pub async fn binary_resultset_stream(
        &mut self,
        column_count: usize,
    ) -> std::io::Result<BinaryResultsetStream<Stream>>
    where
        Stream: PacketReader,
    {
        BinaryResultsetStream::new(&mut self.stream, self.capability, column_count).await
    }
}
impl<Stream: AsyncWriteExt + Unpin> Drop for Client<Stream> {
    fn drop(&mut self) {
        eprintln!("warning: client has dropped without explicit quit command");
    }
}

pub struct Statement<'c, Stream: AsyncWriteExt + Unpin> {
    client: &'c SharedClient<Stream>,
    statement_id: u32,
}
impl<Stream: AsyncWriteExt + PacketReader + Unpin> SharedClient<Stream> {
    pub async fn prepare<'c>(
        &'c self,
        statement: &str,
    ) -> Result<Statement<'c, Stream>, CommunicationError> {
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
impl<Stream: AsyncWriteExt + Unpin> Statement<'_, Stream> {
    pub async fn close(self) -> std::io::Result<()> {
        StmtCloseCommand(self.statement_id)
            .write_packet(&mut self.client.0.lock().stream, 0)
            .await?;
        std::mem::forget(self);
        Ok(())
    }

    pub async fn reset(&mut self) -> Result<(), CommunicationError>
    where
        Stream: PacketReader,
    {
        let mut c = self.client.0.lock();
        let cap = c.capability;

        StmtResetCommand(self.statement_id)
            .write_packet(&mut c.stream, 0)
            .await?;
        c.stream.flush().await?;
        GenericOKErrPacket::read_packet(&mut c.stream, cap)
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
        Stream: PacketReader,
    {
        let mut c = self.client.0.lock();
        let cap = c.capability;

        StmtExecuteCommand {
            statement_id: self.statement_id,
            flags: StmtExecuteFlags::new(),
            parameters,
            requires_rebound_parameters: rebound_parameters,
        }
        .write_packet(&mut c.stream, 0)
        .await?;
        c.stream.flush().await?;
        StmtExecuteResult::read_packet(&mut c.stream, cap).await
    }
}
impl<Stream: AsyncWriteExt + Unpin> Drop for Statement<'_, Stream> {
    fn drop(&mut self) {
        eprintln!(
            "warning: statement #{} has dropped without explicit closing",
            self.statement_id
        )
    }
}
