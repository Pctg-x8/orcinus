//! Binary Protocol

use std::io::Read;

use tokio::io::AsyncRead;

use crate::{ReadCounted, ReadCountedSync};

use super::{
    format::{self, AsyncProtocolFormatFragment, ProtocolFormatFragment},
    CapabilityFlags, ColumnType, EOFPacket41, EOFPacket41Format, ErrPacket, LengthEncodedInteger,
    OKPacket, Value,
};

#[repr(transparent)]
pub struct ByteString<'s>(pub &'s [u8]);
impl ByteString<'_> {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.reserve(1 + self.0.len());
        unsafe {
            LengthEncodedInteger(self.0.len() as _)
                .write_sync(sink)
                .unwrap_unchecked();
        }
        sink.extend(self.0);
    }
}
impl<'s> ByteString<'s> {
    pub fn slice_from(reader: &mut std::io::Cursor<&'s [u8]>) -> std::io::Result<Self> {
        let len = format::LengthEncodedInteger.read_sync(reader)?;
        let s = &reader.get_ref()[reader.position() as usize..(reader.position() + len) as usize];
        reader.set_position(reader.position() + len);
        Ok(Self(s))
    }

    pub unsafe fn as_str_unchecked(&self) -> &'s str {
        std::str::from_utf8_unchecked(self.0)
    }
}

#[repr(transparent)]
pub struct LongLong(pub u64);
impl LongLong {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }

    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        let mut bs = [0u8; 8];
        reader.read_exact(&mut bs)?;
        Ok(Self(u64::from_le_bytes(bs)))
    }
}

#[repr(transparent)]
pub struct Int(pub u32);
impl Int {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }

    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        format::U32.read_sync(reader).map(Self)
    }
}

#[repr(transparent)]
pub struct Short(pub u16);
impl Short {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }

    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        format::U16.read_sync(reader).map(Self)
    }
}

#[repr(transparent)]
pub struct Tiny(pub u8);
impl Tiny {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.push(self.0);
    }

    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        format::U8.read_sync(reader).map(Self)
    }
}

#[repr(transparent)]
pub struct Double(pub f64);
impl Double {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }

    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        let mut bs = [0u8; 8];
        reader.read_exact(&mut bs)?;
        Ok(Self(f64::from_le_bytes(bs)))
    }
}

#[repr(transparent)]
pub struct Float(pub f32);
impl Float {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }

    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        let mut bs = [0u8; 4];
        reader.read_exact(&mut bs)?;
        Ok(Self(f32::from_le_bytes(bs)))
    }
}

// TODO: date time formats

pub trait BinaryProtocolValueDeconstructor {
    fn serialize_into(&self, sink: &mut Vec<u8>);
    fn column_type(&self) -> ColumnType;

    #[inline]
    fn is_null(&self) -> bool {
        self.column_type() == ColumnType::Null
    }
}
impl<'d, T> BinaryProtocolValueDeconstructor for &'d T
where
    T: BinaryProtocolValueDeconstructor,
{
    #[inline]
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        T::serialize_into(self, sink)
    }

    #[inline]
    fn column_type(&self) -> ColumnType {
        T::column_type(self)
    }

    #[inline]
    fn is_null(&self) -> bool {
        T::is_null(self)
    }
}

impl BinaryProtocolValueDeconstructor for Value<'_> {
    #[inline]
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        match self {
            Self::String(s)
            | Self::Varchar(s)
            | Self::VarString(s)
            | Self::Enum(s)
            | Self::Set(s)
            | Self::Decimal(s)
            | Self::NewDecimal(s) => ByteString(s.as_bytes()).serialize_into(sink),
            Self::LongBlob(b)
            | Self::MediumBlob(b)
            | Self::Blob(b)
            | Self::TinyBlob(b)
            | Self::Geometry(b)
            | Self::Bit(b) => ByteString(b).serialize_into(sink),
            Self::LongLong(l) => LongLong(*l).serialize_into(sink),
            Self::Long(v) | Self::Int24(v) => Int(*v).serialize_into(sink),
            Self::Short(v) | Self::Year(v) => Short(*v).serialize_into(sink),
            Self::Tiny(v) => Tiny(*v).serialize_into(sink),
            Self::Double(v) => Double(*v).serialize_into(sink),
            Self::Float(v) => Float(*v).serialize_into(sink),
            Self::Null => (/* No serialization to bytes */),
        }
    }

    #[inline]
    fn column_type(&self) -> ColumnType {
        match self {
            Self::String(_) => ColumnType::String,
            Self::Varchar(_) => ColumnType::Varchar,
            Self::VarString(_) => ColumnType::VarString,
            Self::Enum(_) => ColumnType::Enum,
            Self::Set(_) => ColumnType::Set,
            Self::Decimal(_) => ColumnType::Decimal,
            Self::NewDecimal(_) => ColumnType::NewDecimal,
            Self::LongBlob(_) => ColumnType::LongBlob,
            Self::MediumBlob(_) => ColumnType::MediumBlob,
            Self::Blob(_) => ColumnType::Blob,
            Self::TinyBlob(_) => ColumnType::TinyBlob,
            Self::Geometry(_) => ColumnType::Geometry,
            Self::Bit(_) => ColumnType::Bit,
            Self::LongLong(_) => ColumnType::LongLong,
            Self::Long(_) => ColumnType::Long,
            Self::Int24(_) => ColumnType::Int24,
            Self::Short(_) => ColumnType::Short,
            Self::Year(_) => ColumnType::Year,
            Self::Tiny(_) => ColumnType::Tiny,
            Self::Double(_) => ColumnType::Double,
            Self::Float(_) => ColumnType::Float,
            Self::Null => ColumnType::Null,
        }
    }

    #[inline]
    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}
impl<A> BinaryProtocolValueDeconstructor for (Value<'_>, A) {
    #[inline]
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        self.0.serialize_into(sink)
    }

    #[inline]
    fn column_type(&self) -> ColumnType {
        self.0.column_type()
    }

    #[inline]
    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

pub fn serialize_null_bitmap(values: &[impl BinaryProtocolValueDeconstructor], sink: &mut Vec<u8>) {
    fn cv(b: bool, x: u8) -> u8 {
        if b {
            x
        } else {
            0x00
        }
    }

    sink.reserve((values.len() + 7) / 8);
    for vs in values.chunks(8) {
        let mut f = 0u8;
        f |= cv(
            vs.get(0)
                .map_or(false, BinaryProtocolValueDeconstructor::is_null),
            0x01,
        );
        f |= cv(
            vs.get(1)
                .map_or(false, BinaryProtocolValueDeconstructor::is_null),
            0x02,
        );
        f |= cv(
            vs.get(2)
                .map_or(false, BinaryProtocolValueDeconstructor::is_null),
            0x04,
        );
        f |= cv(
            vs.get(3)
                .map_or(false, BinaryProtocolValueDeconstructor::is_null),
            0x08,
        );
        f |= cv(
            vs.get(4)
                .map_or(false, BinaryProtocolValueDeconstructor::is_null),
            0x10,
        );
        f |= cv(
            vs.get(5)
                .map_or(false, BinaryProtocolValueDeconstructor::is_null),
            0x20,
        );
        f |= cv(
            vs.get(6)
                .map_or(false, BinaryProtocolValueDeconstructor::is_null),
            0x40,
        );
        f |= cv(
            vs.get(7)
                .map_or(false, BinaryProtocolValueDeconstructor::is_null),
            0x80,
        );

        sink.push(f);
    }
}
/// values: iterator of (value, unsigned_flag)
pub fn serialize_value_types<'d>(
    values: impl Iterator<Item = (&'d Value<'d>, bool)>,
    sink: &mut Vec<u8>,
) {
    let (l, h) = values.size_hint();
    sink.reserve(h.unwrap_or(l));
    for (v, uf) in values {
        sink.extend([v.column_type() as u8, if uf { 0x80 } else { 0x00 }]);
    }
}
pub fn serialize_values<'d>(
    values: impl Iterator<Item = impl BinaryProtocolValueDeconstructor>,
    sink: &mut Vec<u8>,
) {
    for v in values {
        v.serialize_into(sink);
    }
}

#[derive(Debug)]
pub struct BinaryResultsetRow {
    pub null_bitmap: Vec<u8>,
    pub values: Vec<u8>,
}
impl BinaryResultsetRow {
    pub async fn read(
        payload_length: usize,
        column_count: usize,
        mut reader: &mut ReadCounted<impl AsyncRead + Sync + Send + Unpin>,
    ) -> std::io::Result<Self> {
        let null_bitmap = format::Bytes((column_count + 7 + 2) / 8)
            .read_format(&mut reader)
            .await?;
        let values = format::Bytes(payload_length - reader.read_bytes())
            .read_format(&mut reader)
            .await?;

        Ok(Self {
            null_bitmap,
            values,
        })
    }

    pub fn read_sync(
        payload_length: usize,
        column_count: usize,
        reader: &mut ReadCountedSync<impl Read>,
    ) -> std::io::Result<Self> {
        let null_bitmap = format::Bytes((column_count + 7 + 2) / 8).read_sync(reader)?;
        let values = format::Bytes(payload_length - reader.read_bytes()).read_sync(reader)?;

        Ok(Self {
            null_bitmap,
            values,
        })
    }

    #[inline]
    pub fn decode_values<'r, 'cs>(
        &'r self,
        column_types: &'cs [ColumnType],
    ) -> BinaryResultsetRowValues<'r, 'cs> {
        BinaryResultsetRowValues {
            null_bitmap: &self.null_bitmap,
            values: std::io::Cursor::new(&self.values),
            columns: column_types,
            element_counter: 0,
        }
    }
}

pub struct BinaryResultsetRowValues<'r, 'cs> {
    null_bitmap: &'r [u8],
    values: std::io::Cursor<&'r [u8]>,
    columns: &'cs [ColumnType],
    element_counter: usize,
}
impl<'r> Iterator for BinaryResultsetRowValues<'r, '_> {
    type Item = std::io::Result<Value<'r>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.element_counter == self.columns.len() {
            return None;
        }

        let null_bit_position = self.element_counter + 2; // 謎に+2されてるぶん
        let is_null_value =
            (self.null_bitmap[null_bit_position / 8] & (0x01 << (null_bit_position % 8))) != 0;
        let ty = if is_null_value {
            ColumnType::Null
        } else {
            self.columns[self.element_counter]
        };
        match ty.slice_value(&mut self.values) {
            Err(e) => Some(Err(e)),
            Ok(v) => {
                self.element_counter += 1;
                Some(Ok(v))
            }
        }
    }
}

#[derive(Debug)]
pub enum BinaryResultset41 {
    Row(BinaryResultsetRow),
    Ok(OKPacket),
    Err(ErrPacket),
    EOF(EOFPacket41),
}
impl BinaryResultset41 {
    const EOF_FORMAT: format::Mapped<EOFPacket41Format, fn(EOFPacket41) -> Self> =
        format::Mapped(EOFPacket41Format, Self::EOF);

    pub async fn read_packet(
        mut reader: &mut (impl AsyncRead + Sync + Send + Unpin + ?Sized),
        client_capabilities: CapabilityFlags,
        column_count: usize,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_format(&mut reader).await?;
        let mut reader = ReadCounted::new(reader);
        let r1 = format::U8.read_format(&mut reader).await?;

        match r1 {
            // treat as OK Packet for client supports DEPRECATE_EOF capability
            0xfe if client_capabilities.support_deprecate_eof() => OKPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capabilities,
            )
            .await
            .map(Self::Ok),
            0xfe => Self::EOF_FORMAT.read_format(reader.into_inner()).await,
            0xff => ErrPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capabilities,
            )
            .await
            .map(Self::Err),
            // 0x00 is a normal resultset row in binary protocol(terminal packet is OK packet started with 0xfe)
            0x00 => BinaryResultsetRow::read(
                packet_header.payload_length as _,
                column_count,
                &mut reader,
            )
            .await
            .map(Self::Row),
            _ => unreachable!("invalid heading byte for binary protocol resultset: 0x{r1:02x}"),
        }
    }

    pub fn read_packet_sync(
        reader: &mut (impl Read + ?Sized),
        client_capability: CapabilityFlags,
        column_count: usize,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let head_byte = format::U8.read_sync(&mut reader)?;

        match head_byte {
            // treat as OK Packet for client supports DEPRECATE_EOF capability
            0xfe if client_capability.support_deprecate_eof() => OKPacket::read_sync(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .map(Self::Ok),
            0xfe => Self::EOF_FORMAT.read_sync(reader.into_inner()),
            0xff => ErrPacket::read_sync(
                packet_header.payload_length as _,
                &mut reader,
                client_capability,
            )
            .map(Self::Err),
            // 0x00 is a normal resultset row in binary protocol(terminal packet is OK packet started with 0xfe)
            0x00 => BinaryResultsetRow::read_sync(
                packet_header.payload_length as _,
                column_count,
                &mut reader,
            )
            .map(Self::Row),
            _ => unreachable!(
                "invalid heading byte for binary protocol resultset: 0x{head_byte:02x}"
            ),
        }
    }
}
