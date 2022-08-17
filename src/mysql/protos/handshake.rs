use std::collections::HashMap;
use std::io::Read;

use tokio::io::AsyncReadExt;

use crate::protos::format::{AsyncProtocolFormatFragment, ProtocolFormatFragment};
use crate::{protos::format, ReadCounted};
use crate::{DefFormatStruct, DefProtocolFormat, ReadAsync, ReadCountedSync, ReadSync};

use super::super::PacketReader;
use super::capabilities::CapabilityFlags;
use super::{ErrPacket, LengthEncodedInteger};

#[derive(Debug)]
pub struct HandshakeV10Short {
    pub server_version: String,
    pub connection_id: u32,
    pub auth_plugin_data_part_1: [u8; 8],
    pub capability_flags: CapabilityFlags,
}
DefFormatStruct!(RawHandshakeV10Short(RawHandshakeV10ShortProtocolFormat) {
    server_version(String) <- format::NullTerminatedString,
    connection_id(u32) <- format::U32,
    auth_plugin_data_part_1([u8; 8]) <- format::FixedBytes::<8>,
    _filler([u8; 1]) <- format::FixedBytes::<1>,
    capability_flags(CapabilityFlags) <- format::U16.map(CapabilityFlags::from_lower_bits)
});
impl From<RawHandshakeV10Short> for HandshakeV10Short {
    fn from(raw: RawHandshakeV10Short) -> Self {
        Self {
            server_version: raw.server_version,
            connection_id: raw.connection_id,
            auth_plugin_data_part_1: raw.auth_plugin_data_part_1,
            capability_flags: raw.capability_flags,
        }
    }
}
impl HandshakeV10Short {
    pub async fn read(reader: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Self> {
        RawHandshakeV10ShortProtocolFormat
            .read_format(reader)
            .await
            .map(From::from)
    }

    pub fn read_sync(reader: &mut impl Read) -> std::io::Result<Self> {
        RawHandshakeV10ShortProtocolFormat
            .read_sync(reader)
            .map(From::from)
    }
}

#[derive(Debug)]
pub struct HandshakeV10Long {
    pub short: HandshakeV10Short,
    pub character_set: u8,
    pub status_flags: u16,
    pub auth_plugin_data_part_2: Option<Vec<u8>>,
    pub auth_plugin_name: Option<String>,
}
DefFormatStruct!(RawHandshakeV10ExtHead(RawHandshakeV10ExtHeadProtocolFormat) {
    character_set(u8) <- format::U8,
    status_flags(u16) <- format::U16,
    capability_flags_upper_bits(u16) <- format::U16,
    auth_plugin_data_length(u8) <- format::U8,
    _filler([u8; 10]) <- format::FixedBytes::<10>
});
impl HandshakeV10Long {
    pub async fn read_additional(
        short: HandshakeV10Short,
        reader: &mut (impl AsyncReadExt + Unpin),
    ) -> std::io::Result<Self> {
        let head = RawHandshakeV10ExtHeadProtocolFormat
            .read_format(reader)
            .await?;
        let capability_flags = short
            .capability_flags
            .combine_upper_bytes(head.capability_flags_upper_bits);

        let auth_plugin_data_part_2 = if capability_flags.support_secure_connection() {
            Some(
                format::Bytes(13.max(head.auth_plugin_data_length - 8) as _)
                    .read_format(reader)
                    .await?,
            )
        } else {
            None
        };
        let auth_plugin_name = if capability_flags.support_plugin_auth() {
            Some(format::NullTerminatedString.read_format(reader).await?)
        } else {
            None
        };

        Ok(Self {
            short: HandshakeV10Short {
                capability_flags,
                ..short
            },
            character_set: head.character_set,
            status_flags: head.status_flags,
            auth_plugin_data_part_2,
            auth_plugin_name,
        })
    }

    pub fn read_additional_sync(
        short: HandshakeV10Short,
        reader: &mut impl Read,
    ) -> std::io::Result<Self> {
        let head = RawHandshakeV10ExtHeadProtocolFormat.read_sync(reader)?;
        let capability_flags = short
            .capability_flags
            .combine_upper_bytes(head.capability_flags_upper_bits);

        let auth_plugin_data_part_2 = if capability_flags.support_secure_connection() {
            Some(format::Bytes(13.max(head.auth_plugin_data_length - 8) as _).read_sync(reader)?)
        } else {
            None
        };
        let auth_plugin_name = if capability_flags.support_plugin_auth() {
            Some(format::NullTerminatedString.read_sync(reader)?)
        } else {
            None
        };

        Ok(Self {
            short: HandshakeV10Short {
                capability_flags,
                ..short
            },
            character_set: head.character_set,
            status_flags: head.status_flags,
            auth_plugin_data_part_2,
            auth_plugin_name,
        })
    }
}

#[derive(Debug)]
pub struct HandshakeV9 {
    pub server_version: String,
    pub connection_id: u32,
    pub scramble: String,
}
impl HandshakeV9 {
    pub async fn read(reader: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Self> {
        Ok(Self {
            server_version: reader.read_null_terminated_string().await?,
            connection_id: reader.read_u32_le().await?,
            scramble: reader.read_null_terminated_string().await?,
        })
    }

    pub fn read_sync(reader: &mut impl Read) -> std::io::Result<Self> {
        ReadSync!(reader => {
            server_version <- format::NullTerminatedString,
            connection_id <- format::U32,
            scramble <- format::NullTerminatedString
        });

        Ok(Self {
            server_version,
            connection_id,
            scramble,
        })
    }
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
    ) -> std::io::Result<(Self, u8)> {
        let packet_header = reader.read_packet_header().await?;
        let protocol_version = reader.read_u8().await?;

        let decoded_payload = match protocol_version {
            9 => Self::V9(HandshakeV9::read(reader).await?),
            10 => {
                let mut reader = ReadCounted::new(reader);
                let short = HandshakeV10Short::read(&mut reader).await?;

                if packet_header.payload_length as usize > reader.read_bytes() {
                    // more data available
                    Self::V10Long(
                        HandshakeV10Long::read_additional(short, reader.into_inner()).await?,
                    )
                } else {
                    Self::V10Short(short)
                }
            }
            _ => unreachable!("unsupported protocol version: {protocol_version}"),
        };

        Ok((decoded_payload, packet_header.sequence_id))
    }

    pub fn read_packet_sync(reader: &mut impl Read) -> std::io::Result<(Self, u8)> {
        ReadSync!(reader => {
            packet_header <- format::PacketHeader,
            protocol_version <- format::U8
        });

        let decoded_payload = match protocol_version {
            9 => Self::V9(HandshakeV9::read_sync(reader)?),
            10 => {
                let mut reader = ReadCountedSync::new(reader);
                let short = HandshakeV10Short::read_sync(&mut reader)?;

                if packet_header.payload_length as usize > reader.read_bytes() {
                    // more data available
                    Self::V10Long(HandshakeV10Long::read_additional_sync(
                        short,
                        reader.into_inner(),
                    )?)
                } else {
                    Self::V10Short(short)
                }
            }
            _ => unreachable!("unsupported protocol version: {protocol_version}"),
        };

        Ok((decoded_payload, packet_header.sequence_id))
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
    pub auth_response: &'s [u8],
    pub database: Option<&'s str>,
    pub auth_plugin_name: Option<&'s str>,
    pub connect_attrs: HashMap<&'s str, &'s str>,
}
impl HandshakeResponse41<'_> {
    pub fn compute_final_capability_flags(&self) -> CapabilityFlags {
        let mut caps = self.capability;
        caps.set_support_41_protocol();
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
        if caps.support_plugin_auth_lenenc_client_data() {
            unsafe {
                LengthEncodedInteger(self.auth_response.len() as _)
                    .write_sync(&mut sink)
                    .unwrap_unchecked()
            };
            sink.extend(self.auth_response);
        } else if caps.support_secure_connection() {
            sink.push(self.auth_response.len() as u8);
            sink.extend(self.auth_response);
        } else {
            sink.extend(self.auth_response);
            sink.push(0);
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

pub enum HandshakeResponse<'s> {
    New(HandshakeResponse41<'s>),
    Old(HandshakeResponse320<'s>),
}
impl super::ClientPacket for HandshakeResponse<'_> {
    fn serialize_payload(&self) -> Vec<u8> {
        match self {
            Self::New(n) => n.serialize_payload(),
            Self::Old(n) => n.serialize_payload(),
        }
    }
}

pub struct SSLRequest {
    pub capability: CapabilityFlags,
    pub max_packet_size: u32,
    pub character_set: u8,
}
impl super::ClientPacket for SSLRequest {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(32);

        sink.extend(self.capability.0.to_le_bytes());
        sink.extend(self.max_packet_size.to_le_bytes());
        sink.push(self.character_set);
        sink.extend(std::iter::repeat(0).take(23));

        sink
    }
}

pub struct PublicKeyRequest;
impl super::ClientPacket for PublicKeyRequest {
    fn serialize_payload(&self) -> Vec<u8> {
        vec![0x02]
    }
}

#[repr(transparent)]
pub struct AuthMoreData(pub Vec<u8>);
impl AuthMoreData {
    pub async fn expacted_read_packet(
        reader: &mut (impl PacketReader + Unpin),
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut reader = ReadCounted::new(reader);
        let heading = reader.read_u8().await?;
        assert_eq!(heading, 0x01);

        Self::read(packet_header.payload_length as _, &mut reader).await
    }

    pub fn expected_read_packet_sync(reader: &mut impl Read) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let heading = format::U8.read_sync(&mut reader)?;
        assert_eq!(heading, 0x01);

        Self::read_sync(packet_header.payload_length as _, &mut reader)
    }

    pub async fn read(
        payload_length: usize,
        reader: &mut ReadCounted<impl AsyncReadExt + Unpin>,
    ) -> std::io::Result<Self> {
        let mut content = Vec::with_capacity(payload_length - reader.read_bytes());
        unsafe {
            content.set_len(payload_length - reader.read_bytes());
        }
        reader.read_exact(&mut content).await?;
        Ok(Self(content))
    }

    pub fn read_sync(
        payload_length: usize,
        reader: &mut ReadCountedSync<impl Read>,
    ) -> std::io::Result<Self> {
        format::Bytes(payload_length - reader.read_bytes())
            .read_sync(reader)
            .map(Self)
    }
}

pub struct AuthMoreDataResponse(Result<AuthMoreData, ErrPacket>, u8);
impl AuthMoreDataResponse {
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut reader = ReadCounted::new(reader);
        let heading = reader.read_u8().await?;

        match heading {
            0xff => ErrPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .await
            .map(|e| Self(Err(e), packet_header.sequence_id)),
            0x01 => AuthMoreData::read(packet_header.payload_length as _, &mut reader)
                .await
                .map(|x| Self(Ok(x), packet_header.sequence_id)),
            _ => unreachable!("unexpected head byte for AuthMoreData response: 0x{heading:02x}"),
        }
    }

    pub fn read_packet_sync(
        reader: &mut impl Read,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let heading = format::U8.read_sync(&mut reader)?;

        match heading {
            0xff => ErrPacket::read_sync(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .map(|e| Self(Err(e), packet_header.sequence_id)),
            0x01 => AuthMoreData::read_sync(packet_header.payload_length as _, &mut reader)
                .map(|x| Self(Ok(x), packet_header.sequence_id)),
            _ => unreachable!("unexpected head byte for AuthMoreData response: 0x{heading:02x}"),
        }
    }

    #[inline]
    pub fn into_result(self) -> Result<(AuthMoreData, u8), ErrPacket> {
        self.0.map(|x| (x, self.1))
    }
}

pub type HandshakeResult = super::GenericOKErrPacket;
