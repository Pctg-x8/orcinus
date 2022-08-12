use std::collections::HashMap;

use tokio::io::AsyncReadExt;

use crate::ReadCounted;

use super::super::PacketReader;
use super::capabilities::CapabilityFlags;
use super::{ErrPacket, LengthEncodedInteger, OKPacket};

#[derive(Debug)]
pub struct HandshakeV10Short {
    pub server_version: String,
    pub connection_id: u32,
    pub auth_plugin_data_part_1: [u8; 8],
    pub capability_flags: CapabilityFlags,
}
#[derive(Debug)]
pub struct HandshakeV10Long {
    pub short: HandshakeV10Short,
    pub character_set: u8,
    pub status_flags: u16,
    pub auth_plugin_data_part_2: Option<Vec<u8>>,
    pub auth_plugin_name: Option<String>,
}
#[derive(Debug)]
pub struct HandshakeV9 {
    pub server_version: String,
    pub connection_id: u32,
    pub scramble: String,
}
#[derive(Debug)]
pub enum Handshake {
    V9(HandshakeV9),
    V10Short(HandshakeV10Short),
    V10Long(HandshakeV10Long),
}
impl Handshake {
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin),
    ) -> std::io::Result<(u8, Self)> {
        let packet_header = reader.read_packet_header().await?;
        let protocol_version = reader.read_u8().await?;

        let decoded_payload = if protocol_version == 9 {
            Self::V9(HandshakeV9 {
                server_version: reader.read_null_terminated_string().await?,
                connection_id: reader.read_u32_le().await?,
                scramble: reader.read_null_terminated_string().await?,
            })
        } else if protocol_version == 10 {
            let mut reader = ReadCounted::new(reader);
            let server_version = reader.read_null_terminated_string().await?;
            let connection_id = reader.read_u32_le().await?;
            let mut auth_plugin_data_part_1 = [0u8; 8];
            reader.read_exact(&mut auth_plugin_data_part_1).await?;
            let mut _filler = [0u8; 1];
            reader.read_exact(&mut _filler).await?;
            let capability_flags = CapabilityFlags::read_lower_bits(&mut reader).await?;

            if packet_header.payload_length as usize > reader.read_bytes() {
                // more data available
                let character_set = reader.read_u8().await?;
                let status_flags = reader.read_u16_le().await?;
                let capability_flags = capability_flags
                    .additional_read_upper_bits(&mut reader)
                    .await?;
                let auth_plugin_data_length = reader.read_u8().await?;
                let mut _filler = [0u8; 10];
                reader.read_exact(&mut _filler).await?;
                let auth_plugin_data_part_2 = if capability_flags.support_secure_connection() {
                    let mut data = vec![0u8; 13.max(auth_plugin_data_length - 8) as _];
                    reader.read_exact(&mut data).await?;
                    Some(data)
                } else {
                    None
                };
                let auth_plugin_name = if capability_flags.support_plugin_auth() {
                    Some(reader.read_null_terminated_string().await?)
                } else {
                    None
                };

                Self::V10Long(HandshakeV10Long {
                    short: HandshakeV10Short {
                        server_version,
                        connection_id,
                        auth_plugin_data_part_1,
                        capability_flags,
                    },
                    character_set,
                    status_flags,
                    auth_plugin_data_part_2,
                    auth_plugin_name,
                })
            } else {
                Self::V10Short(HandshakeV10Short {
                    server_version,
                    connection_id,
                    auth_plugin_data_part_1,
                    capability_flags,
                })
            }
        } else {
            unreachable!("invalid protocol version: {protocol_version}");
        };

        Ok((packet_header.sequence_id, decoded_payload))
    }
}

pub enum HandshakeResponse41AuthResponse<'s> {
    PluginAuthLenEnc(&'s [u8]),
    SecureConnection(&'s [u8]),
    Plain(&'s [u8]),
}
pub struct HandshakeResponse41<'s> {
    pub capability: CapabilityFlags,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: &'s str,
    pub auth_response: HandshakeResponse41AuthResponse<'s>,
    pub database: Option<&'s str>,
    pub auth_plugin_name: Option<&'s str>,
    pub connect_attrs: HashMap<&'s str, &'s str>,
}
impl HandshakeResponse41<'_> {
    pub fn compute_final_capability_flags(&self) -> CapabilityFlags {
        let mut caps = self.capability;
        caps.set_support_41_protocol();
        match self.auth_response {
            HandshakeResponse41AuthResponse::PluginAuthLenEnc(_) => {
                caps.set_support_plugin_auth_lenenc_client_data();
            }
            HandshakeResponse41AuthResponse::SecureConnection(_) => {
                caps.set_support_secure_connection();
            }
            _ => (),
        };
        if self.database.is_some() {
            caps.set_connect_with_db();
        } else {
            caps.clear_connect_with_db();
        }
        if self.auth_plugin_name.is_some() {
            caps.set_client_plugin_auth();
        } else {
            caps.clear_plugin_auth();
        }
        if !self.connect_attrs.is_empty() {
            caps.set_client_connect_attrs();
        } else {
            caps.clear_client_connect_attrs();
        }

        caps
    }
}
impl super::ClientPacket for HandshakeResponse41<'_> {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(128);

        let caps = self.compute_final_capability_flags();
        sink.extend(u32::to_le_bytes(caps.0));
        sink.extend(u32::to_le_bytes(self.max_packet_size));
        sink.push(self.character_set);
        sink.extend(std::iter::repeat(0).take(23));
        sink.extend(self.username.as_bytes());
        sink.push(0);
        match self.auth_response {
            HandshakeResponse41AuthResponse::PluginAuthLenEnc(bytes) => {
                unsafe {
                    LengthEncodedInteger(bytes.len() as _)
                        .write_sync(&mut sink)
                        .unwrap_unchecked()
                };
                sink.extend(bytes);
            }
            HandshakeResponse41AuthResponse::SecureConnection(bytes) => {
                sink.push(bytes.len() as u8);
                sink.extend(bytes);
            }
            HandshakeResponse41AuthResponse::Plain(bytes) => {
                sink.extend(bytes);
                sink.push(0);
            }
        }
        if let Some(db) = self.database {
            sink.extend(db.as_bytes());
            sink.push(0);
        }
        if let Some(pn) = self.auth_plugin_name {
            sink.extend(pn.as_bytes());
            sink.push(0);
        }

        if !self.connect_attrs.is_empty() {
            let attrs_len: usize = self
                .connect_attrs
                .iter()
                .map(|(k, v)| {
                    let (kb, vb) = (k.as_bytes(), v.as_bytes());

                    LengthEncodedInteger(kb.len() as _).payload_size()
                        + kb.len()
                        + LengthEncodedInteger(vb.len() as _).payload_size()
                        + vb.len()
                })
                .sum();
            unsafe {
                LengthEncodedInteger(attrs_len as _)
                    .write_sync(&mut sink)
                    .unwrap_unchecked()
            };
            for (k, v) in &self.connect_attrs {
                let (kb, vb) = (k.as_bytes(), v.as_bytes());

                unsafe {
                    LengthEncodedInteger(kb.len() as _)
                        .write_sync(&mut sink)
                        .unwrap_unchecked()
                };
                sink.extend(kb);
                unsafe {
                    LengthEncodedInteger(vb.len() as _)
                        .write_sync(&mut sink)
                        .unwrap_unchecked()
                };
                sink.extend(vb);
            }
        }

        sink
    }
}

pub struct HandshakeResponse320<'s> {
    pub capability: CapabilityFlags,
    pub max_packet_size: u32,
    pub username: &'s str,
    pub auth_response: &'s [u8],
    pub database: Option<&'s str>,
}
impl HandshakeResponse320<'_> {
    pub fn compute_final_capability_flags(&self) -> CapabilityFlags {
        let mut caps = self.capability;
        if self.database.is_some() {
            caps.set_connect_with_db();
        } else {
            caps.clear_connect_with_db();
        }

        caps
    }
}
impl super::ClientPacket for HandshakeResponse320<'_> {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(48);

        let caps = self.compute_final_capability_flags();
        sink.extend(u16::to_le_bytes(caps.0 as _));
        sink.extend(&u32::to_le_bytes(self.max_packet_size)[0..3]);
        sink.extend(self.username.as_bytes());
        sink.push(0);
        sink.extend(self.auth_response);
        if let Some(db) = self.database {
            sink.push(0);
            sink.extend(db.as_bytes());
            sink.push(0);
        }

        sink
    }
}

#[repr(transparent)]
pub struct AuthMoreData(pub Vec<u8>);
impl AuthMoreData {
    pub async fn read_packet(reader: &mut (impl PacketReader + Unpin)) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let heading = reader.read_u8().await?;
        assert_eq!(heading, 0x01);

        let mut content = Vec::with_capacity(packet_header.payload_length as usize - 1);
        unsafe {
            content.set_len(packet_header.payload_length as usize - 1);
        }
        reader.read_exact(&mut content).await?;
        Ok(Self(content))
    }
}

pub enum HandshakeResult {
    Ok(OKPacket),
    Err(ErrPacket),
}
impl HandshakeResult {
    pub async fn read_packet(
        reader: &mut (impl AsyncReadExt + Unpin),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut reader = ReadCounted::new(reader);
        let head_byte = reader.read_u8().await?;

        match head_byte {
            0xff => ErrPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .await
            .map(Self::Err),
            0x00 => OKPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .await
            .map(Self::Ok),
            _ => unreachable!("unexpected handshake result payload header: 0x{head_byte:02x}"),
        }
    }

    #[inline]
    pub fn into_result(self) -> Result<OKPacket, ErrPacket> {
        match self {
            Self::Ok(o) => Ok(o),
            Self::Err(e) => Err(e),
        }
    }
}
