use std::io::{SeekFrom, Write};

use futures_util::{
    future::{BoxFuture, LocalBoxFuture},
    pin_mut, FutureExt,
};
use tokio::io::{AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use self::{capabilities::CapabilityFlags, status::StatusFlags};
use super::PacketReader;

pub struct PacketHeader {
    pub payload_length: u32,
    pub sequence_id: u8,
}
impl PacketHeader {
    pub async fn write(self, writer: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
        writer
            .write_all(&[
                (self.payload_length & 0xff) as u8,
                ((self.payload_length >> 8) & 0xff) as _,
                ((self.payload_length >> 16) & 0xff) as _,
                self.sequence_id,
            ])
            .await
    }
}
pub async fn write_packet(
    writer: &mut (impl AsyncWriteExt + Unpin),
    payload: &[u8],
    sequence_id: u8,
) -> std::io::Result<()> {
    PacketHeader {
        payload_length: payload.len() as _,
        sequence_id,
    }
    .write(writer)
    .await?;
    writer.write_all(payload).await
}

pub trait ClientPacket {
    fn serialize_payload(&self) -> Vec<u8>;

    fn write_packet<'a>(
        &'a self,
        writer: &'a mut (impl AsyncWriteExt + Unpin),
        sequence_id: u8,
    ) -> LocalBoxFuture<'a, std::io::Result<()>> {
        async move {
            let payload = self.serialize_payload();

            write_packet(writer, &payload, sequence_id).await
        }
        .boxed_local()
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct LengthEncodedInteger(pub u64);
impl LengthEncodedInteger {
    pub fn payload_size(&self) -> usize {
        if self.0 < 251 {
            1
        } else if self.0 < 2u64.pow(16) {
            3
        } else if self.0 < 2u64.pow(24) {
            4
        } else {
            9
        }
    }

    pub async fn read(reader: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Self> {
        let first_byte = reader.read_u8().await?;

        match first_byte {
            x if x < 251 => Ok(Self(first_byte as _)),
            0xfc => reader.read_u16_le().await.map(|x| Self(x as _)),
            0xfd => {
                let mut bytes = [0u8; 4];
                reader.read_exact(&mut bytes[..3]).await?;
                Ok(Self(u32::from_le_bytes(bytes) as _))
            }
            0xfe => reader.read_u64_le().await.map(Self),
            _ => unreachable!(),
        }
    }

    pub fn write_sync(&self, writer: &mut impl Write) -> std::io::Result<()> {
        if self.0 < 251 {
            writer.write_all(&[self.0 as u8])
        } else if self.0 < 2u64.pow(16) {
            writer.write_all(&[0xfc, (self.0 & 0xff) as _, ((self.0 >> 8) & 0xff) as _])
        } else if self.0 < 2u64.pow(24) {
            writer.write_all(&[
                0xfd,
                (self.0 & 0xff) as _,
                ((self.0 >> 8) & 0xff) as _,
                ((self.0 >> 16) & 0xff) as _,
            ])
        } else {
            writer.write_all(&[
                0xfe,
                (self.0 & 0xff) as _,
                ((self.0 >> 8) & 0xff) as _,
                ((self.0 >> 16) & 0xff) as _,
                ((self.0 >> 24) & 0xff) as _,
                ((self.0 >> 32) & 0xff) as _,
                ((self.0 >> 40) & 0xff) as _,
                ((self.0 >> 48) & 0xff) as _,
            ])
        }
    }

    pub async fn write(&self, writer: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
        if self.0 < 251 {
            writer.write_u8(self.0 as _).await
        } else if self.0 < 2u64.pow(16) {
            writer
                .write_all(&[0xfc, (self.0 & 0xff) as _, ((self.0 >> 8) & 0xff) as _])
                .await
        } else if self.0 < 2u64.pow(24) {
            writer
                .write_all(&[
                    0xfd,
                    (self.0 & 0xff) as _,
                    ((self.0 >> 8) & 0xff) as _,
                    ((self.0 >> 16) & 0xff) as _,
                ])
                .await
        } else {
            writer
                .write_all(&[
                    0xfe,
                    (self.0 & 0xff) as _,
                    ((self.0 >> 8) & 0xff) as _,
                    ((self.0 >> 16) & 0xff) as _,
                    ((self.0 >> 24) & 0xff) as _,
                    ((self.0 >> 32) & 0xff) as _,
                    ((self.0 >> 40) & 0xff) as _,
                    ((self.0 >> 48) & 0xff) as _,
                ])
                .await
        }
    }
}

pub enum OKPacketCapabilityExtraData {
    Protocol41 {
        status_flags: StatusFlags,
        warnings: u16,
    },
    Transactions {
        status_flags: StatusFlags,
    },
}
pub struct OKPacket {
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub capability_extra: Option<OKPacketCapabilityExtraData>,
    pub info: String,
    pub session_state_changes: Option<String>,
}
impl OKPacket {
    pub async fn read(
        payload_size: usize,
        reader: &mut (impl super::PacketReader + Unpin + AsyncSeekExt),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let current_pos = reader.seek(SeekFrom::Current(0)).await?;

        let LengthEncodedInteger(affected_rows) = LengthEncodedInteger::read(reader).await?;
        let LengthEncodedInteger(last_insert_id) = LengthEncodedInteger::read(reader).await?;
        let capability_extra = if client_capability.support_41_protocol() {
            Some(OKPacketCapabilityExtraData::Protocol41 {
                status_flags: StatusFlags(reader.read_u16_le().await?),
                warnings: reader.read_u16_le().await?,
            })
        } else if client_capability.support_transaction() {
            Some(OKPacketCapabilityExtraData::Transactions {
                status_flags: StatusFlags(reader.read_u16_le().await?),
            })
        } else {
            None
        };
        let st = match capability_extra {
            Some(OKPacketCapabilityExtraData::Protocol41 { status_flags, .. })
            | Some(OKPacketCapabilityExtraData::Transactions { status_flags }) => status_flags,
            _ => StatusFlags::new(),
        };
        let (info, session_state_changes) = if client_capability.support_session_track() {
            let LengthEncodedInteger(info_len) = LengthEncodedInteger::read(reader).await?;
            let mut info_bytes = Vec::with_capacity(info_len as _);
            unsafe {
                info_bytes.set_len(info_len as _);
            }
            reader.read_exact(&mut info_bytes).await?;
            let state_changes_bytes = if st.has_state_changed() {
                let LengthEncodedInteger(state_info_len) =
                    LengthEncodedInteger::read(reader).await?;
                let mut state_info_bytes = Vec::with_capacity(state_info_len as _);
                unsafe {
                    state_info_bytes.set_len(state_info_len as _);
                }
                reader.read_exact(&mut state_info_bytes).await?;
                Some(state_info_bytes)
            } else {
                None
            };

            unsafe {
                (
                    String::from_utf8_unchecked(info_bytes),
                    state_changes_bytes.map(|bytes| String::from_utf8_unchecked(bytes)),
                )
            }
        } else {
            let rest_length =
                payload_size as u64 - (reader.seek(SeekFrom::Current(0)).await? - current_pos);
            let mut info_bytes = Vec::with_capacity(rest_length as _);
            unsafe {
                info_bytes.set_len(rest_length as _);
            }
            reader.read_exact(&mut info_bytes).await?;

            unsafe { (String::from_utf8_unchecked(info_bytes), None) }
        };

        Ok(Self {
            affected_rows,
            last_insert_id,
            capability_extra,
            info,
            session_state_changes,
        })
    }
}

pub struct ErrPacket {
    pub code: u16,
    pub sql_state: Option<[u8; 5]>,
    pub error_message: String,
}
impl ErrPacket {
    pub async fn read(
        payload_size: usize,
        reader: &mut (impl super::PacketReader + Unpin + AsyncSeekExt),
        client_capabilities: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let current_pos = reader.seek(SeekFrom::Current(0)).await?;
        let code = reader.read_u16_le().await?;
        let sql_state = if client_capabilities.support_41_protocol() {
            reader.seek(SeekFrom::Current(1)).await?;
            let mut sql_state = [0u8; 5];
            reader.read_exact(&mut sql_state).await?;
            Some(sql_state)
        } else {
            None
        };
        let error_message_len =
            payload_size - (reader.seek(SeekFrom::Current(0)).await? - current_pos) as usize;
        let mut em_bytes = Vec::with_capacity(error_message_len);
        unsafe {
            em_bytes.set_len(error_message_len);
        }
        reader.read_exact(&mut em_bytes).await?;

        Ok(Self {
            code,
            sql_state,
            error_message: unsafe { String::from_utf8_unchecked(em_bytes) },
        })
    }
}

pub struct EOFPacket41 {
    pub warnings: u16,
    pub status_flags: StatusFlags,
}
impl EOFPacket41 {
    pub async fn read(reader: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Self> {
        Ok(Self {
            warnings: reader.read_u16_le().await?,
            status_flags: StatusFlags(reader.read_u16_le().await?),
        })
    }
}

pub enum OKOrEOFPacket {
    OK(OKPacket),
    EOF41(EOFPacket41),
    EOF,
}
pub enum GenericResultPacket {
    OK(OKPacket),
    Err(ErrPacket),
    EOF41(EOFPacket41),
    EOF,
}
impl GenericResultPacket {
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin + AsyncSeekExt),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;

        let header = reader.read_u8().await?;
        match header {
            0x00 => OKPacket::read(packet_header.payload_length as _, reader, client_capability)
                .await
                .map(Self::OK),
            0xfe if client_capability.support_41_protocol() => {
                EOFPacket41::read(reader).await.map(Self::EOF41)
            }
            0xfe => Ok(Self::EOF),
            0xff => ErrPacket::read(packet_header.payload_length as _, reader, client_capability)
                .await
                .map(Self::Err),
            _ => unreachable!("invalid generic response type"),
        }
    }

    pub fn to_result(self) -> Result<OKOrEOFPacket, ErrPacket> {
        match self {
            Self::OK(o) => Ok(OKOrEOFPacket::OK(o)),
            Self::EOF41(e) => Ok(OKOrEOFPacket::EOF41(e)),
            Self::EOF => Ok(OKOrEOFPacket::EOF),
            Self::Err(e) => Err(e),
        }
    }
}

mod capabilities;
mod handshake;
mod status;
mod text;
