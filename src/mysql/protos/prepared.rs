use std::io::Read;

use futures_util::{future::BoxFuture, FutureExt, TryFutureExt};
use tokio::io::AsyncRead;

use crate::{DefFormatStruct, ReadCounted, ReadCountedSync};

use super::{
    format::{self, AsyncProtocolFormatFragment, ProtocolFormatFragment},
    serialize_null_bitmap, serialize_value_types, serialize_values, CapabilityFlags, ErrPacket,
    GenericOKErrPacket, OKPacket, Value,
};

pub struct StmtPrepareCommand<'s>(pub &'s str);
impl super::ClientPacket for StmtPrepareCommand<'_> {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(self.0.as_bytes().len() + 1);
        sink.push(0x16);
        sink.extend(self.0.bytes());

        sink
    }
}
impl super::ClientPacketIO for StmtPrepareCommand<'_> {
    type Receiver = StmtPrepareResult;
}

pub struct StmtCloseCommand(pub u32);
impl super::ClientPacket for StmtCloseCommand {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(5);
        sink.push(0x19);
        sink.extend(self.0.to_le_bytes());

        sink
    }
}

pub struct StmtResetCommand(pub u32);
impl super::ClientPacket for StmtResetCommand {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(5);
        sink.push(0x1a);
        sink.extend(self.0.to_le_bytes());

        sink
    }
}
impl super::ClientPacketIO for StmtResetCommand {
    type Receiver = GenericOKErrPacket;
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct StmtExecuteFlags(u8);
impl StmtExecuteFlags {
    pub const fn new() -> Self {
        Self(0)
    }

    pub fn set_read_only(&mut self) -> &mut Self {
        self.0 |= 0x01;
        self
    }

    pub fn set_for_update(&mut self) -> &mut Self {
        self.0 |= 0x02;
        self
    }

    pub fn set_scrollable(&mut self) -> &mut Self {
        self.0 |= 0x04;
        self
    }
}

pub struct StmtExecuteCommand<'p> {
    pub statement_id: u32,
    pub flags: StmtExecuteFlags,
    pub parameters: &'p [(Value<'p>, bool)],
    pub requires_rebound_parameters: bool,
}
impl super::ClientPacket for StmtExecuteCommand<'_> {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(32);

        sink.push(0x17);
        sink.extend(self.statement_id.to_le_bytes());
        sink.push(self.flags.0);
        sink.extend(1u32.to_le_bytes()); // iteration count
        if self.parameters.len() > 0 {
            serialize_null_bitmap(&self.parameters, &mut sink);
            sink.push(if self.requires_rebound_parameters {
                0x01
            } else {
                0x00
            });

            if self.requires_rebound_parameters {
                serialize_value_types(self.parameters.iter().map(|&(ref a, b)| (a, b)), &mut sink);
                serialize_values(self.parameters.iter(), &mut sink);
            }
        }

        sink
    }
}
impl super::ClientPacketIO for StmtExecuteCommand<'_> {
    type Receiver = StmtExecuteResult;
}

#[derive(Debug)]
pub struct StmtPrepareOk {
    pub statement_id: u32,
    pub num_columns: u16,
    pub num_params: u16,
    pub warning_count: u16,
}
DefFormatStruct!(pub RawStmtPrepareOk(RawStmtPrepareOkFormat) {
    statement_id(u32) <- format::U32,
    num_columns(u16) <- format::U16,
    num_params(u16) <- format::U16,
    _filler([u8; 1]) <- format::FixedBytes::<1>,
    warning_count(u16) <- format::U16
});
impl From<RawStmtPrepareOk> for StmtPrepareOk {
    fn from(r: RawStmtPrepareOk) -> Self {
        Self {
            statement_id: r.statement_id,
            num_columns: r.num_columns,
            num_params: r.num_params,
            warning_count: r.warning_count,
        }
    }
}

pub struct StmtPrepareOkFormat;
impl ProtocolFormatFragment for StmtPrepareOkFormat {
    type Output = StmtPrepareOk;

    fn read_sync(self, reader: impl Read) -> std::io::Result<Self::Output> {
        RawStmtPrepareOkFormat.read_sync(reader).map(From::from)
    }
}
impl<'r, R> AsyncProtocolFormatFragment<'r, R> for StmtPrepareOkFormat
where
    R: AsyncRead + Send + Unpin + 'r,
{
    type ReaderF = futures_util::future::MapOk<
        <RawStmtPrepareOkFormat as AsyncProtocolFormatFragment<'r, R>>::ReaderF,
        fn(RawStmtPrepareOk) -> StmtPrepareOk,
    >;

    fn read_format(self, reader: R) -> Self::ReaderF {
        RawStmtPrepareOkFormat
            .read_format(reader)
            .map_ok(From::from)
    }
}

#[derive(Debug)]
pub struct StmtPrepareResult(Result<StmtPrepareOk, ErrPacket>);
impl From<StmtPrepareOk> for StmtPrepareResult {
    fn from(r: StmtPrepareOk) -> Self {
        Self(Ok(r))
    }
}
impl From<ErrPacket> for StmtPrepareResult {
    fn from(r: ErrPacket) -> Self {
        Self(Err(r))
    }
}
impl StmtPrepareResult {
    #[inline]
    pub fn into_result(self) -> Result<StmtPrepareOk, ErrPacket> {
        self.0
    }
}
impl super::ReceivePacket for StmtPrepareResult {
    fn read_packet(
        mut reader: impl Read,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(&mut reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let first_byte = format::U8.read_sync(&mut reader)?;

        match first_byte {
            0xff => ErrPacket::read_sync(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .map(From::from),
            0x00 => StmtPrepareOkFormat
                .read_sync(reader.into_inner())
                .map(From::from),
            _ => unreachable!("unexpected response of COM_STMT_PREPARE: 0x{first_byte:02x}"),
        }
    }
}
impl<'r, R> super::AsyncReceivePacket<'r, R> for StmtPrepareResult
where
    R: AsyncRead + Unpin + Send + Sync + 'r,
{
    type ReceiveF = BoxFuture<'r, std::io::Result<Self>>;

    fn read_packet_async(mut reader: R, client_capabilities: CapabilityFlags) -> Self::ReceiveF {
        async move {
            let packet_header = format::PacketHeader.read_format(&mut reader).await?;
            let mut reader = ReadCounted::new(reader);
            let first_byte = format::U8.read_format(&mut reader).await?;

            match first_byte {
                0xff => ErrPacket::read(
                    packet_header.payload_length as _,
                    &mut reader,
                    client_capabilities,
                )
                .await
                .map(From::from),
                0x00 => StmtPrepareOkFormat
                    .read_format(reader.into_inner())
                    .await
                    .map(From::from),
                _ => unreachable!("unexpected response of COM_STMT_PREPARE: 0x{first_byte:02x}"),
            }
        }
        .boxed()
    }
}

#[derive(Debug)]
pub enum StmtExecuteResult {
    Resultset { column_count: u64 },
    Err(ErrPacket),
    Ok(OKPacket),
}
impl StmtExecuteResult {
    #[inline]
    const fn resultset_format(
        head_byte: u8,
    ) -> format::Mapped<format::LengthEncodedIntegerAhead, fn(u64) -> StmtExecuteResult> {
        fn make_resultset(column_count: u64) -> StmtExecuteResult {
            StmtExecuteResult::Resultset { column_count }
        }

        format::Mapped(format::LengthEncodedIntegerAhead(head_byte), make_resultset)
    }
}
impl super::ReceivePacket for StmtExecuteResult {
    fn read_packet(
        mut reader: impl Read,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(&mut reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let head_byte = format::U8.read_sync(&mut reader)?;

        match head_byte {
            0x00 => OKPacket::read_sync(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .map(Self::Ok),
            0xff => ErrPacket::read_sync(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .map(Self::Err),
            _ => Self::resultset_format(head_byte).read_sync(reader.into_inner()),
        }
    }
}
impl<'r, R> super::AsyncReceivePacket<'r, R> for StmtExecuteResult
where
    R: AsyncRead + Unpin + Send + Sync + 'r,
{
    type ReceiveF = BoxFuture<'r, std::io::Result<Self>>;

    fn read_packet_async(mut reader: R, client_capabilities: CapabilityFlags) -> Self::ReceiveF {
        async move {
            let packet_header = format::PacketHeader.read_format(&mut reader).await?;
            let mut reader = ReadCounted::new(reader);
            let head_byte = format::U8.read_format(&mut reader).await?;

            match head_byte {
                0x00 => OKPacket::read(
                    packet_header.payload_length as _,
                    &mut reader,
                    client_capabilities,
                )
                .await
                .map(Self::Ok),
                0xff => ErrPacket::read(
                    packet_header.payload_length as _,
                    &mut reader,
                    client_capabilities,
                )
                .await
                .map(Self::Err),
                _ => {
                    Self::resultset_format(head_byte)
                        .read_format(reader.into_inner())
                        .await
                }
            }
        }
        .boxed()
    }
}
