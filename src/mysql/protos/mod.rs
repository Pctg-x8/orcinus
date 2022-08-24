use std::io::Read;
use std::io::Write;

use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use futures_util::TryFutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::DefFormatStruct;
use crate::ReadCounted;
use crate::ReadCountedSync;

#[derive(Debug)]
pub struct PacketHeader {
    pub payload_length: u32,
    pub sequence_id: u8,
}
impl PacketHeader {
    #[inline]
    pub const fn serialize_bytes(&self) -> [u8; 4] {
        [
            (self.payload_length & 0xff) as u8,
            ((self.payload_length >> 8) & 0xff) as _,
            ((self.payload_length >> 16) & 0xff) as _,
            self.sequence_id,
        ]
    }

    #[inline]
    pub const fn from_fixed_bytes(bytes: [u8; 4]) -> Self {
        Self {
            payload_length: u32::from_le_bytes(bytes) & 0x00ff_ffff,
            sequence_id: bytes[3],
        }
    }
}

pub async fn write_packet(
    mut writer: impl AsyncWrite + Unpin,
    payload: &(impl ClientPacket + ?Sized),
    sequence_id: u8,
) -> std::io::Result<()> {
    let payload = payload.serialize_payload();

    writer
        .write_all(
            &PacketHeader {
                payload_length: payload.len() as _,
                sequence_id,
            }
            .serialize_bytes(),
        )
        .await?;
    writer.write_all(&payload).await
}
pub fn write_packet_sync(
    writer: &mut (impl Write + ?Sized),
    payload: &(impl ClientPacket + ?Sized),
    sequence_id: u8,
) -> std::io::Result<()> {
    let payload = payload.serialize_payload();

    writer.write_all(
        &PacketHeader {
            payload_length: payload.len() as _,
            sequence_id,
        }
        .serialize_bytes(),
    )?;
    writer.write_all(&payload)
}

pub async fn drop_packet(mut reader: impl AsyncRead + Send + Unpin) -> std::io::Result<()> {
    let header = format::PacketHeader.read_format(&mut reader).await?;
    let _discard = format::Bytes(header.payload_length as _)
        .read_format(&mut reader)
        .await?;

    Ok(())
}
pub fn drop_packet_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<()> {
    let header = format::PacketHeader.read_sync(reader)?;
    let _discard = format::Bytes(header.payload_length as _).read_sync(reader)?;

    Ok(())
}

/// The client-side packet serialization.
pub trait ClientPacket {
    fn serialize_payload(&self) -> Vec<u8>;
}
impl<T: ClientPacket + ?Sized> ClientPacket for Box<T> {
    fn serialize_payload(&self) -> Vec<u8> {
        T::serialize_payload(self)
    }
}
impl ClientPacket for [u8] {
    fn serialize_payload(&self) -> Vec<u8> {
        self.to_owned()
    }
}
impl ClientPacket for Vec<u8> {
    fn serialize_payload(&self) -> Vec<u8> {
        self.to_owned()
    }
}
/// A packet that knows how to receive it from server synchronously.
pub trait ReceivePacket: Sized {
    /// Read a packet from reader.
    fn read_packet(
        reader: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self>;
}
/// A packet that knows how to receive it from server asynchronously.
pub trait AsyncReceivePacket<'r, R>: Sized
where
    R: AsyncRead + Unpin + Send + 'r,
{
    /// Reading task implementation.
    type ReceiveF: std::future::Future<Output = std::io::Result<Self>> + Send + 'r;

    /// Read a packet.
    fn read_packet_async(reader: R, client_capability: CapabilityFlags) -> Self::ReceiveF;
}

/// Client Packet(Self) - Server Packet Communication Definition.
pub trait ClientPacketIO: ClientPacket {
    /// Client expects this type of packet will be returned from server.
    type Receiver: ReceivePacket;
}
/// Synchronous communication between client and server.
pub fn request<P: ClientPacketIO + ?Sized>(
    msg: &P,
    stream: &mut (impl Read + Write + ?Sized),
    sequence_id: u8,
    client_capability: CapabilityFlags,
) -> std::io::Result<P::Receiver>
where
    P::Receiver: ReceivePacket,
{
    write_packet_sync(stream, msg, sequence_id)?;
    stream.flush()?;
    P::Receiver::read_packet(stream, client_capability)
}
/// Asynchronous communication between client and server.
pub async fn request_async<'r, R, P: ClientPacketIO>(
    msg: P,
    mut stream: R,
    sequence_id: u8,
    client_capability: CapabilityFlags,
) -> std::io::Result<P::Receiver>
where
    P::Receiver: AsyncReceivePacket<'r, R>,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'r,
{
    write_packet(&mut stream, &msg, sequence_id).await?;
    stream.flush().await?;
    P::Receiver::read_packet_async(stream, client_capability).await
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

    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        let mut first_byte = [0u8; 1];
        reader.read_exact(&mut first_byte)?;
        Self::read_ahead_sync(first_byte[0], reader)
    }

    pub fn read_ahead_sync(
        first_byte: u8,
        reader: &mut (impl Read + ?Sized),
    ) -> std::io::Result<Self> {
        match first_byte {
            x if x < 251 => Ok(Self(first_byte as _)),
            0xfc => {
                let mut value = [0u8; 2];
                reader.read_exact(&mut value)?;
                Ok(Self(u16::from_le_bytes(value) as _))
            }
            0xfd => {
                let mut bytes = [0u8; 4];
                reader.read_exact(&mut bytes[..3])?;
                Ok(Self(u32::from_le_bytes(bytes) as _))
            }
            0xfe => {
                let mut value = [0u8; 8];
                reader.read_exact(&mut value)?;
                Ok(Self(u64::from_le_bytes(value)))
            }
            _ => unreachable!("invalid lenenc heading: 0x{first_byte:02x}"),
        }
    }

    pub async fn read(reader: &mut (impl AsyncRead + Unpin + ?Sized)) -> std::io::Result<Self> {
        let first_byte = reader.read_u8().await?;
        Self::read_ahead(first_byte, reader).await
    }

    pub async fn read_ahead(
        first_byte: u8,
        reader: &mut (impl AsyncRead + Unpin + ?Sized),
    ) -> std::io::Result<Self> {
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

    pub fn write_sync(&self, writer: &mut (impl Write + ?Sized)) -> std::io::Result<()> {
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

    pub async fn write(
        &self,
        writer: &mut (impl AsyncWrite + Unpin + ?Sized),
    ) -> std::io::Result<()> {
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

#[derive(Debug)]
pub enum OKPacketCapabilityExtraData {
    Protocol41 {
        status_flags: StatusFlags,
        warnings: u16,
    },
    Transactions {
        status_flags: StatusFlags,
    },
}
DefFormatStruct!(RawOKPacket41Ext(RawOKPacket41ExtFormat) {
    status_flags(StatusFlags) <- format::U16.map(StatusFlags),
    warnings(u16) <- format::U16
});
impl From<RawOKPacket41Ext> for OKPacketCapabilityExtraData {
    fn from(r: RawOKPacket41Ext) -> Self {
        Self::Protocol41 {
            status_flags: r.status_flags,
            warnings: r.warnings,
        }
    }
}
DefFormatStruct!(RawOKPacketTransactionsExt(RawOKPacketTransactionsExtFormat) {
    status_flags(StatusFlags) <- format::U16.map(StatusFlags)
});
impl From<RawOKPacketTransactionsExt> for OKPacketCapabilityExtraData {
    fn from(r: RawOKPacketTransactionsExt) -> Self {
        Self::Transactions {
            status_flags: r.status_flags,
        }
    }
}

#[derive(Debug)]
pub struct OKPacket {
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub capability_extra: Option<OKPacketCapabilityExtraData>,
    pub info: String,
    pub session_state_changes: Option<String>,
}
DefFormatStruct!(RawOKPacketCommonHeader(RawOKPacketCommonHeaderFormat) {
    affected_rows(u64) <- format::LengthEncodedInteger,
    last_insert_id(u64) <- format::LengthEncodedInteger
});
impl OKPacket {
    pub async fn expected_read(
        mut reader: &mut (impl AsyncRead + Sync + Send + Unpin + ?Sized),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_format(&mut reader).await?;
        let mut reader = ReadCounted::new(reader);
        let header = format::U8.read_format(&mut reader).await?;
        assert_eq!(header, 0x00, "unexpected response packet header");

        Self::read(
            packet_header.payload_length as _,
            &mut reader,
            client_capability,
        )
        .await
    }

    pub fn expected_read_packet_sync(
        reader: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let header = format::U8.read_sync(&mut reader)?;
        assert_eq!(header, 0x00, "unexpected response packet header");

        Self::read_sync(
            packet_header.payload_length as _,
            &mut reader,
            client_capability,
        )
    }

    pub async fn read(
        payload_size: usize,
        mut reader: &mut ReadCounted<impl AsyncRead + Send + Unpin>,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let ch = RawOKPacketCommonHeaderFormat
            .read_format(&mut reader)
            .await?;
        let capability_extra = if client_capability.support_41_protocol() {
            RawOKPacket41ExtFormat
                .read_format(&mut reader)
                .await
                .map(|x| Some(x.into()))?
        } else if client_capability.support_transaction() {
            RawOKPacketTransactionsExtFormat
                .read_format(&mut reader)
                .await
                .map(|x| Some(x.into()))?
        } else {
            None
        };
        let st = match capability_extra {
            Some(OKPacketCapabilityExtraData::Protocol41 { status_flags, .. })
            | Some(OKPacketCapabilityExtraData::Transactions { status_flags }) => status_flags,
            _ => StatusFlags::new(),
        };

        let (info, session_state_changes);
        if client_capability.support_session_track() {
            info = format::LengthEncodedString.read_format(&mut reader).await?;
            session_state_changes = if st.has_state_changed() {
                format::LengthEncodedString
                    .read_format(&mut reader)
                    .await
                    .map(Some)?
            } else {
                None
            };
        } else {
            info = format::FixedLengthString(payload_size - reader.read_bytes())
                .read_format(reader)
                .await?;
            session_state_changes = None;
        };

        Ok(Self {
            affected_rows: ch.affected_rows,
            last_insert_id: ch.last_insert_id,
            capability_extra,
            info,
            session_state_changes,
        })
    }

    pub fn read_sync(
        payload_length: usize,
        reader: &mut ReadCountedSync<impl Read>,
        client_capability: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let ch = RawOKPacketCommonHeaderFormat.read_sync(reader)?;

        let capability_extra = if client_capability.support_41_protocol() {
            RawOKPacket41ExtFormat
                .read_sync(reader)
                .map(|x| Some(x.into()))?
        } else if client_capability.support_transaction() {
            RawOKPacketTransactionsExtFormat
                .read_sync(reader)
                .map(|x| Some(x.into()))?
        } else {
            None
        };
        let st = match capability_extra {
            Some(OKPacketCapabilityExtraData::Protocol41 { status_flags, .. })
            | Some(OKPacketCapabilityExtraData::Transactions { status_flags }) => status_flags,
            _ => StatusFlags::new(),
        };

        let (info, session_state_changes);
        if client_capability.support_session_track() {
            info = format::LengthEncodedString.read_sync(reader)?;
            session_state_changes = if st.has_state_changed() {
                format::LengthEncodedString.read_sync(reader).map(Some)?
            } else {
                None
            };
        } else {
            info = format::FixedLengthString(payload_length - reader.read_bytes())
                .read_sync(reader)?;
            session_state_changes = None;
        };

        Ok(Self {
            affected_rows: ch.affected_rows,
            last_insert_id: ch.last_insert_id,
            capability_extra,
            info,
            session_state_changes,
        })
    }

    #[inline]
    pub fn status_flags(&self) -> Option<StatusFlags> {
        match self.capability_extra {
            Some(OKPacketCapabilityExtraData::Protocol41 { status_flags, .. })
            | Some(OKPacketCapabilityExtraData::Transactions { status_flags }) => {
                Some(status_flags)
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ErrPacket {
    pub code: u16,
    pub sql_state: Option<[u8; 5]>,
    pub error_message: String,
}
impl ErrPacket {
    pub async fn read(
        payload_size: usize,
        mut reader: &mut ReadCounted<impl AsyncRead + Send + Unpin>,
        client_capabilities: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let code = format::U16.read_format(&mut reader).await?;
        let sql_state = if client_capabilities.support_41_protocol() {
            let _ = format::FixedBytes::<1>.read_format(&mut reader).await?;
            format::FixedBytes::<5>
                .map(Some)
                .read_format(&mut reader)
                .await?
        } else {
            None
        };
        let error_message = format::FixedLengthString(payload_size - reader.read_bytes())
            .read_format(reader)
            .await?;

        Ok(Self {
            code,
            sql_state,
            error_message,
        })
    }

    pub fn read_sync(
        payload_size: usize,
        reader: &mut ReadCountedSync<impl Read>,
        client_capabilities: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let code = format::U16.read_sync(reader)?;
        let sql_state = if client_capabilities.support_41_protocol() {
            let _ = format::FixedBytes::<1>.read_sync(reader)?;
            format::FixedBytes::<5>.map(Some).read_sync(reader)?
        } else {
            None
        };
        let error_message =
            format::FixedLengthString(payload_size - reader.read_bytes()).read_sync(reader)?;

        Ok(Self {
            code,
            sql_state,
            error_message,
        })
    }
}

#[derive(Debug)]
pub struct EOFPacket41 {
    pub warnings: u16,
    pub status_flags: StatusFlags,
}
DefFormatStruct!(pub RawEOFPacket41(RawEOFPacket41Format) {
    warnings(u16) <- format::U16,
    status_flags(StatusFlags) <- format::U16.map(StatusFlags)
});
impl From<RawEOFPacket41> for EOFPacket41 {
    fn from(r: RawEOFPacket41) -> Self {
        Self {
            warnings: r.warnings,
            status_flags: r.status_flags,
        }
    }
}
DefFormatStruct!(RawEOFPacket41ExpectHeader(RawEOFPacket41ExpectHeaderFormat) {
    _packet_header(PacketHeader) <- format::PacketHeader,
    _mark(u8) <- format::U8.assert_eq(0xfe)
});
impl EOFPacket41 {
    pub async fn expected_read_packet(
        mut reader: impl AsyncRead + Send + Unpin,
    ) -> std::io::Result<Self> {
        let _ = RawEOFPacket41ExpectHeaderFormat
            .read_format(&mut reader)
            .await?;
        EOFPacket41Format.read_format(reader).await
    }

    pub fn expected_read_packet_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        let _ = RawEOFPacket41ExpectHeaderFormat.read_sync(reader)?;
        EOFPacket41Format.read_sync(reader)
    }
}

pub struct EOFPacket41Format;
impl format::ProtocolFormatFragment for EOFPacket41Format {
    type Output = EOFPacket41;

    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        RawEOFPacket41Format.read_sync(reader).map(From::from)
    }
}
impl<'r, R: 'r + AsyncRead + Send + Unpin> format::AsyncProtocolFormatFragment<'r, R>
    for EOFPacket41Format
{
    type ReaderF = futures_util::future::MapOk<
        <RawEOFPacket41Format as format::AsyncProtocolFormatFragment<'r, R>>::ReaderF,
        fn(RawEOFPacket41) -> EOFPacket41,
    >;

    fn read_format(self, reader: R) -> Self::ReaderF {
        RawEOFPacket41Format.read_format(reader).map_ok(From::from)
    }
}

#[derive(Debug)]
pub struct GenericOKErrPacket(Result<OKPacket, ErrPacket>, u8);
impl From<(OKPacket, u8)> for GenericOKErrPacket {
    fn from((d, sid): (OKPacket, u8)) -> Self {
        Self(Ok(d), sid)
    }
}
impl From<(ErrPacket, u8)> for GenericOKErrPacket {
    fn from((d, sid): (ErrPacket, u8)) -> Self {
        Self(Err(d), sid)
    }
}
impl GenericOKErrPacket {
    #[inline]
    pub fn into_result(self) -> Result<(OKPacket, u8), ErrPacket> {
        match self.0 {
            Ok(e) => Ok((e, self.1)),
            Err(e) => Err(e),
        }
    }
}
impl ReceivePacket for GenericOKErrPacket {
    fn read_packet(
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
            .map(|x| (x, packet_header.sequence_id).into()),
            0x00 => OKPacket::read_sync(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .map(|x| (x, packet_header.sequence_id).into()),
            _ => unreachable!("unexpected payload header: 0x{first_byte:02x}"),
        }
    }
}
impl<'r, R> AsyncReceivePacket<'r, R> for GenericOKErrPacket
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
                .map(|x| (x, packet_header.sequence_id).into()),
                0x00 => OKPacket::read(
                    packet_header.payload_length as _,
                    &mut reader,
                    client_capabilities,
                )
                .await
                .map(|x| (x, packet_header.sequence_id).into()),
                _ => unreachable!("unexpected payload header: 0x{first_byte:02x}"),
            }
        }
        .boxed()
    }
}

mod capabilities;
pub use self::capabilities::*;
mod handshake;
use self::format::AsyncProtocolFormatFragment;
use self::format::ProtocolFormatFragment;
pub use self::handshake::*;
mod status;
pub use self::status::*;
mod text;
pub use self::text::*;
mod prepared;
pub use self::prepared::*;
mod binary;
pub use self::binary::*;
mod value;
pub use self::value::*;
pub mod format;
