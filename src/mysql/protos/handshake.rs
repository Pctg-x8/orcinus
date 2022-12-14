use std::collections::HashMap;
use std::io::Read;

use futures_util::future::BoxFuture;
use futures_util::{FutureExt, TryFutureExt};
use tokio::io::AsyncRead;

use crate::counted_read::{ReadCounted, ReadCountedSync};
use crate::protos::format;
use crate::protos::format::{AsyncProtocolFormatFragment, ProtocolFormatFragment};
use crate::{DefFormatStruct, ReadAsync, ReadSync};

use super::capabilities::CapabilityFlags;
use super::{AsyncReceivePacket, ClientPacketIO, ErrPacket, LengthEncodedInteger, ReceivePacket};

#[derive(Debug)]
/// Handshake V10(least common payload): https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
pub struct HandshakeV10Short {
    /// Human readable server version text
    pub server_version: String,
    /// Connection ID
    pub connection_id: u32,
    /// Data for Authentication Plugin(first 8 bytes)
    pub auth_plugin_data_part_1: [u8; 8],
    /// Server capability flags
    pub capability_flags: CapabilityFlags,
}
DefFormatStruct!(pub RawHandshakeV10Short(RawHandshakeV10ShortProtocolFormat) {
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

/// Format Fragment for `HandshakeV10Short`
pub struct HandshakeV10ShortFormat;
impl format::ProtocolFormatFragment for HandshakeV10ShortFormat {
    type Output = HandshakeV10Short;

    fn read_sync(self, reader: impl Read) -> std::io::Result<Self::Output> {
        RawHandshakeV10ShortProtocolFormat.read_sync(reader).map(From::from)
    }
}
impl<'r, R: 'r + AsyncRead + Send + Unpin> format::AsyncProtocolFormatFragment<'r, R> for HandshakeV10ShortFormat {
    type ReaderF = futures_util::future::MapOk<
        <RawHandshakeV10ShortProtocolFormat as format::AsyncProtocolFormatFragment<'r, R>>::ReaderF,
        fn(RawHandshakeV10Short) -> HandshakeV10Short,
    >;

    fn read_format(self, reader: R) -> Self::ReaderF {
        RawHandshakeV10ShortProtocolFormat
            .read_format(reader)
            .map_ok(From::from)
    }
}

#[derive(Debug)]
/// Handshake V10(fullset): https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
pub struct HandshakeV10Long {
    /// Common part of the payload
    pub short: HandshakeV10Short,
    /// Character Set byte
    pub character_set: u8,
    /// Status Flags
    pub status_flags: u16,
    /// Data for Authentication Plugin(more than first 8 bytes)
    pub auth_plugin_data_part_2: Option<Vec<u8>>,
    /// Authentication Plugin name requested by server
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
    /// Read additional portion from the payload
    pub async fn read_additional(
        short: HandshakeV10Short,
        mut reader: &mut (impl AsyncRead + Sync + Send + Unpin + ?Sized),
    ) -> std::io::Result<Self> {
        let head = RawHandshakeV10ExtHeadProtocolFormat.read_format(&mut reader).await?;
        let capability_flags = short
            .capability_flags
            .combine_upper_bytes(head.capability_flags_upper_bits);

        let auth_plugin_data_part_2 = if capability_flags.support_secure_connection() {
            format::Bytes(13.max(head.auth_plugin_data_length - 8) as _)
                .read_format(&mut reader)
                .await
                .map(Some)?
        } else {
            None
        };
        let auth_plugin_name = if capability_flags.support_plugin_auth() {
            format::NullTerminatedString.read_format(&mut reader).await.map(Some)?
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

    /// Read additional portion from the payload
    pub fn read_additional_sync(short: HandshakeV10Short, mut reader: impl Read) -> std::io::Result<Self> {
        let head = RawHandshakeV10ExtHeadProtocolFormat.read_sync(&mut reader)?;
        let capability_flags = short
            .capability_flags
            .combine_upper_bytes(head.capability_flags_upper_bits);

        let auth_plugin_data_part_2 = if capability_flags.support_secure_connection() {
            format::Bytes(13.max(head.auth_plugin_data_length - 8) as _)
                .read_sync(&mut reader)
                .map(Some)?
        } else {
            None
        };
        let auth_plugin_name = if capability_flags.support_plugin_auth() {
            format::NullTerminatedString.read_sync(reader).map(Some)?
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
/// Handshake V9(old protocol): https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
pub struct HandshakeV9 {
    /// Human readable server version text
    pub server_version: String,
    /// Connection ID
    pub connection_id: u32,
    /// Scramble data for authentication
    pub scramble: String,
}
DefFormatStruct!(pub RawHandshakeV9(RawHandshakeV9Format) {
    server_version(String) <- format::NullTerminatedString,
    connection_id(u32) <- format::U32,
    scramble(String) <- format::NullTerminatedString
});
impl From<RawHandshakeV9> for HandshakeV9 {
    fn from(r: RawHandshakeV9) -> Self {
        Self {
            server_version: r.server_version,
            connection_id: r.connection_id,
            scramble: r.scramble,
        }
    }
}

/// Format Fragment for `HandshakeV9`
pub struct HandshakeV9Format;
impl format::ProtocolFormatFragment for HandshakeV9Format {
    type Output = HandshakeV9;

    fn read_sync(self, reader: impl Read) -> std::io::Result<Self::Output> {
        RawHandshakeV9Format.read_sync(reader).map(From::from)
    }
}
impl<'r, R: 'r> format::AsyncProtocolFormatFragment<'r, R> for HandshakeV9Format
where
    R: AsyncRead + Send + Unpin,
{
    type ReaderF = futures_util::future::MapOk<
        <RawHandshakeV9Format as format::AsyncProtocolFormatFragment<'r, R>>::ReaderF,
        fn(RawHandshakeV9) -> HandshakeV9,
    >;

    fn read_format(self, reader: R) -> Self::ReaderF {
        RawHandshakeV9Format.read_format(reader).map_ok(From::from)
    }
}

#[derive(Debug)]
/// Handshake Packet from Server: https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
pub enum Handshake {
    V9(HandshakeV9),
    V10Short(HandshakeV10Short),
    V10Long(HandshakeV10Long),
}
impl Handshake {
    /// Reads a packet. Returned value is with sequence_id.
    pub async fn read_packet(
        mut reader: &mut (impl AsyncRead + Unpin + Sync + Send + ?Sized),
    ) -> std::io::Result<(Self, u8)> {
        ReadAsync!(reader => {
            packet_header <- format::PacketHeader,
            protocol_version <- format::U8
        });

        let decoded_payload = match protocol_version {
            9 => HandshakeV9Format.read_format(reader).await.map(Self::V9)?,
            10 => {
                let mut reader = ReadCounted::new(reader);
                let short = HandshakeV10ShortFormat.read_format(&mut reader).await?;

                if packet_header.payload_length as usize > reader.read_bytes() {
                    // more data available
                    HandshakeV10Long::read_additional(short, reader.into_inner())
                        .await
                        .map(Self::V10Long)?
                } else {
                    Self::V10Short(short)
                }
            }
            _ => unreachable!("unsupported protocol version: {protocol_version}"),
        };

        Ok((decoded_payload, packet_header.sequence_id))
    }

    /// Reads a packet. Returned value is with sequence_id.
    pub fn read_packet_sync(mut reader: impl Read) -> std::io::Result<(Self, u8)> {
        ReadSync!(reader => {
            packet_header <- format::PacketHeader,
            protocol_version <- format::U8
        });

        let decoded_payload = match protocol_version {
            9 => HandshakeV9Format.read_sync(reader).map(Self::V9)?,
            10 => {
                let mut reader = ReadCountedSync::new(reader);
                let short = HandshakeV10ShortFormat.read_sync(&mut reader)?;

                if packet_header.payload_length as usize > reader.read_bytes() {
                    // more data available
                    HandshakeV10Long::read_additional_sync(short, reader.into_inner()).map(Self::V10Long)?
                } else {
                    Self::V10Short(short)
                }
            }
            _ => unreachable!("unsupported protocol version: {protocol_version}"),
        };

        Ok((decoded_payload, packet_header.sequence_id))
    }
}

/// Handshake Response(new): https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse41
pub struct HandshakeResponse41<'s> {
    /// Client-side capability flags
    pub capability: CapabilityFlags,
    /// Maximum packet size
    pub max_packet_size: u32,
    /// Character set expected by client
    pub character_set: u8,
    /// Login user name
    pub username: &'s str,
    /// Response bytes by Authentication Plugin
    pub auth_response: &'s [u8],
    /// Initially selected database name
    pub database: Option<&'s str>,
    /// Used Authentication Plugin name
    pub auth_plugin_name: Option<&'s str>,
    /// Connection Attributes
    pub connect_attrs: HashMap<&'s str, &'s str>,
}
impl super::ClientPacket for HandshakeResponse41<'_> {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(128);

        sink.extend(u32::to_le_bytes(self.capability.0));
        sink.extend(u32::to_le_bytes(self.max_packet_size));
        sink.push(self.character_set);
        sink.extend(std::iter::repeat(0).take(23));
        sink.extend(self.username.as_bytes());
        sink.push(0);
        if self.capability.support_plugin_auth_lenenc_client_data() {
            unsafe {
                LengthEncodedInteger(self.auth_response.len() as _)
                    .write_sync(&mut sink)
                    .unwrap_unchecked()
            };
            sink.extend(self.auth_response);
        } else if self.capability.support_secure_connection() {
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

/// Handshake Response(old): https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse320
pub struct HandshakeResponse320<'s> {
    /// Client-side capability flags
    pub capability: CapabilityFlags,
    /// Maximum packet size
    pub max_packet_size: u32,
    /// Login user name
    pub username: &'s str,
    /// Response bytes from Authentication method
    pub auth_response: &'s [u8],
    /// Initially selected database name
    pub database: Option<&'s str>,
}
impl super::ClientPacket for HandshakeResponse320<'_> {
    fn serialize_payload(&self) -> Vec<u8> {
        let mut sink = Vec::with_capacity(48);

        sink.extend(u16::to_le_bytes(self.capability.0 as _));
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

/// SSL Connection Request: https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
pub struct SSLRequest {
    /// Client-side capability flags
    pub capability: CapabilityFlags,
    /// Maximum packet size
    pub max_packet_size: u32,
    /// Character set expected by client
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

/// Request for "public key retrieval" in sha2 authentication: https://dev.mysql.com/doc/internals/en/public-key-retrieval.html
pub struct PublicKeyRequest;
impl super::ClientPacket for PublicKeyRequest {
    fn serialize_payload(&self) -> Vec<u8> {
        // note: ????????????????????????0x01??????????????????????????????????????????0x02?????????????????????????????????
        vec![0x02]
    }
}
impl ClientPacketIO for PublicKeyRequest {
    type Receiver = AuthMoreDataResponse;
}

/// More data sent from server while authentication flow: https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthMoreData
#[repr(transparent)]
pub struct AuthMoreData(pub Vec<u8>);
impl AuthMoreData {
    #[inline]
    const fn format(required_length: usize) -> format::Mapped<format::Bytes, fn(Vec<u8>) -> AuthMoreData> {
        format::Mapped(format::Bytes(required_length), AuthMoreData)
    }

    /// Reads a packet that is expected as AuthMoreData packet
    pub async fn expacted_read_packet(
        mut reader: &mut (impl AsyncRead + Sync + Send + Unpin + ?Sized),
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_format(&mut reader).await?;
        let mut reader = ReadCounted::new(reader);
        let heading = format::U8.read_format(&mut reader).await?;
        assert_eq!(heading, 0x01, "invalid AuthMoreData packet");

        Self::read(packet_header.payload_length as _, &mut reader).await
    }

    /// Reads a packet that is expected as AuthMoreData packet
    pub fn expected_read_packet_sync(mut reader: impl Read) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(&mut reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let heading = format::U8.read_sync(&mut reader)?;
        assert_eq!(heading, 0x01, "invalid AuthMoreData packet");

        Self::read_sync(packet_header.payload_length as _, &mut reader)
    }

    /// Reads the payload
    pub async fn read(
        payload_length: usize,
        reader: &mut ReadCounted<impl AsyncRead + Sync + Send + Unpin>,
    ) -> std::io::Result<Self> {
        Self::format(payload_length - reader.read_bytes())
            .read_format(reader)
            .await
    }

    /// Reads the payload
    pub fn read_sync(payload_length: usize, reader: &mut ReadCountedSync<impl Read>) -> std::io::Result<Self> {
        Self::format(payload_length - reader.read_bytes()).read_sync(reader)
    }
}

/// AuthMoreData or ERR_Packet
pub struct AuthMoreDataResponse(Result<AuthMoreData, ErrPacket>, u8);
impl From<(AuthMoreData, u8)> for AuthMoreDataResponse {
    fn from((d, sid): (AuthMoreData, u8)) -> Self {
        Self(Ok(d), sid)
    }
}
impl From<(ErrPacket, u8)> for AuthMoreDataResponse {
    fn from((d, sid): (ErrPacket, u8)) -> Self {
        Self(Err(d), sid)
    }
}
impl AuthMoreDataResponse {
    /// Converts into `Result`.
    #[inline]
    pub fn into_result(self) -> Result<(AuthMoreData, u8), ErrPacket> {
        self.0.map(|x| (x, self.1))
    }
}
impl ReceivePacket for AuthMoreDataResponse {
    fn read_packet(mut reader: impl Read, client_capability: CapabilityFlags) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(&mut reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let heading = format::U8.read_sync(&mut reader)?;

        match heading {
            0xff => ErrPacket::read_sync(packet_header.payload_length as _, &mut reader, client_capability)
                .map(|e| (e, packet_header.sequence_id).into()),
            0x01 => AuthMoreData::read_sync(packet_header.payload_length as _, &mut reader)
                .map(|x| (x, packet_header.sequence_id).into()),
            _ => unreachable!("unexpected head byte for AuthMoreData response: 0x{heading:02x}"),
        }
    }
}
impl<'r, R> AsyncReceivePacket<'r, R> for AuthMoreDataResponse
where
    R: AsyncRead + Unpin + Send + Sync + 'r,
{
    type ReceiveF = BoxFuture<'r, std::io::Result<Self>>;

    fn read_packet_async(mut reader: R, client_capability: CapabilityFlags) -> Self::ReceiveF {
        async move {
            let packet_header = format::PacketHeader.read_format(&mut reader).await?;
            let mut reader = ReadCounted::new(reader);
            let heading = format::U8.read_format(&mut reader).await?;

            match heading {
                0xff => ErrPacket::read(packet_header.payload_length as _, &mut reader, client_capability)
                    .await
                    .map(|e| (e, packet_header.sequence_id).into()),
                0x01 => AuthMoreData::read(packet_header.payload_length as _, &mut reader)
                    .await
                    .map(|x| (x, packet_header.sequence_id).into()),
                _ => {
                    unreachable!("unexpected head byte for AuthMoreData response: 0x{heading:02x}")
                }
            }
        }
        .boxed()
    }
}

/// Final packet of Handshake flow
pub type HandshakeResult = super::GenericOKErrPacket;
