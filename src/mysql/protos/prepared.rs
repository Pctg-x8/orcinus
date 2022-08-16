use std::io::Read;

use tokio::io::AsyncReadExt;

use crate::{PacketReader, ReadCounted, ReadCountedSync, ReadSync};

use super::{
    format::{self, ProtocolFormatFragment},
    serialize_null_bitmap, serialize_value_types, serialize_values, CapabilityFlags, ErrPacket,
    LengthEncodedInteger, OKPacket, Value,
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

#[derive(Debug)]
pub struct StmtPrepareOk {
    pub statement_id: u32,
    pub num_columns: u16,
    pub num_params: u16,
    pub warning_count: u16,
}
impl StmtPrepareOk {
    pub async fn read(reader: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Self> {
        let statement_id = reader.read_u32_le().await?;
        let num_columns = reader.read_u16_le().await?;
        let num_params = reader.read_u16_le().await?;
        let mut _filler = [0u8; 1];
        reader.read_exact(&mut _filler).await?;
        let warning_count = reader.read_u16_le().await?;

        Ok(Self {
            statement_id,
            num_columns,
            num_params,
            warning_count,
        })
    }

    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        ReadSync!(reader => {
            statement_id <- format::U32,
            num_columns <- format::U16,
            num_params <- format::U16,
            _filler <- format::FixedBytes::<1>,
            warning_count <- format::U16
        });

        Ok(Self {
            statement_id,
            num_columns,
            num_params,
            warning_count,
        })
    }
}

#[derive(Debug)]
pub enum StmtPrepareResult {
    Ok(StmtPrepareOk),
    Err(ErrPacket),
}
impl StmtPrepareResult {
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin),
        client_capabilities: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut reader = ReadCounted::new(reader);
        let first_byte = reader.read_u8().await?;

        match first_byte {
            0xff => ErrPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capabilities,
            )
            .await
            .map(Self::Err),
            0x00 => StmtPrepareOk::read(reader.into_inner()).await.map(Self::Ok),
            _ => unreachable!("unexpected response of COM_STMT_PREPARE: 0x{first_byte:02x}"),
        }
    }

    pub fn read_packet_sync(
        reader: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let first_byte = format::U8.read_sync(&mut reader)?;

        match first_byte {
            0xff => ErrPacket::read_sync(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .map(Self::Err),
            0x00 => StmtPrepareOk::read_sync(reader.into_inner()).map(Self::Ok),
            _ => unreachable!("unexpected response of COM_STMT_PREPARE: 0x{first_byte:02x}"),
        }
    }

    #[inline]
    pub fn into_result(self) -> Result<StmtPrepareOk, ErrPacket> {
        match self {
            Self::Ok(o) => Ok(o),
            Self::Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub enum StmtExecuteResult {
    Resultset { column_count: u64 },
    Err(ErrPacket),
    Ok(OKPacket),
}
impl StmtExecuteResult {
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin + ?Sized),
        client_capabilities: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut reader = ReadCounted::new(reader);
        let r1 = reader.read_u8().await?;

        match r1 {
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
                let LengthEncodedInteger(column_count) =
                    LengthEncodedInteger::read_ahead(r1, reader.into_inner()).await?;
                Ok(Self::Resultset { column_count })
            }
        }
    }

    pub fn read_packet_sync(
        reader: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(reader)?;
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
            _ => format::LengthEncodedInteger
                .read_sync(reader.into_inner())
                .map(|x| Self::Resultset { column_count: x }),
        }
    }
}
