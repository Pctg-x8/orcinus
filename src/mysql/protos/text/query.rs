use tokio::io::AsyncReadExt;

use crate::{
    protos::{CapabilityFlags, ClientPacket, ErrPacket, OKPacket, LengthEncodedInteger},
    PacketReader, ReadCounted,
};

pub struct QueryCommand<'s>(pub &'s str);
impl ClientPacket for QueryCommand<'_> {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(1 + self.0.as_bytes().len());
        sink.push(0x03);
        sink.extend(self.0.bytes());

        sink
    }
}

#[derive(Debug)]
pub enum QueryCommandResponse {
    Ok(OKPacket),
    Err(ErrPacket),
    LocalInfileRequest { filename: String },
    ResultSet { column_count: u64 },
}
impl QueryCommandResponse {
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut reader = ReadCounted::new(reader);
        let head_value = reader.read_u8().await?;

        match head_value {
            0x00 => OKPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .await
            .map(Self::Ok),
            0xff => ErrPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .await
            .map(Self::Err),
            0xfb => {
                let fn_len = packet_header.payload_length as usize - reader.read_bytes();
                let mut fn_bytes = Vec::with_capacity(fn_len);
                unsafe {
                    fn_bytes.set_len(fn_len);
                }
                reader.read_exact(&mut fn_bytes).await?;
                Ok(Self::LocalInfileRequest {
                    filename: unsafe { String::from_utf8_unchecked(fn_bytes) },
                })
            },
            _ => {
                let LengthEncodedInteger(column_count) = LengthEncodedInteger::read_ahead(head_value, &mut reader).await?;
                Ok(Self::ResultSet { column_count })
            }
        }
    }
}
