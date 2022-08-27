//! Binary Protocol Implementation

use std::io::Read;

use tokio::io::AsyncRead;

use crate::counted_read::{ReadCounted, ReadCountedSync};

use super::{
    format::{self, AsyncProtocolFormatFragment, ProtocolFormatFragment},
    CapabilityFlags, ColumnType, EOFPacket41, EOFPacket41Format, ErrPacket, LengthEncodedInteger,
    OKPacket, Value,
};

/// Binary Protocol Value format: https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
pub trait ValueFormat {
    /// Serialize value into bytes
    fn serialize_into(&self, sink: &mut Vec<u8>);
}

#[repr(transparent)]
/// ByteString style format: https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
pub struct ByteString<'s>(pub &'s [u8]);
impl ValueFormat for ByteString<'_> {
    fn serialize_into(&self, sink: &mut Vec<u8>) {
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
    /// Slice from preloaded payload
    ///
    /// This operation is copyless
    pub fn slice_from(mut reader: &mut std::io::Cursor<&'s [u8]>) -> std::io::Result<Self> {
        let len = format::LengthEncodedInteger.read_sync(&mut reader)?;
        let s = &reader.get_ref()[reader.position() as usize..(reader.position() + len) as usize];
        reader.set_position(reader.position() + len);
        Ok(Self(s))
    }

    /// Treat content as str
    ///
    /// This function does not check whether the content is a valid UTF-8 sequence
    pub unsafe fn as_str_unchecked(&self) -> &'s str {
        std::str::from_utf8_unchecked(self.0)
    }
}

#[repr(transparent)]
/// LongLong style format: https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
pub struct LongLong(pub u64);
impl ValueFormat for LongLong {
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }
}
impl LongLong {
    /// Read a value
    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        let mut bs = [0u8; 8];
        reader.read_exact(&mut bs)?;
        Ok(Self(u64::from_le_bytes(bs)))
    }
}

#[repr(transparent)]
/// Int style format: https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
pub struct Int(pub u32);
impl ValueFormat for Int {
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }
}
impl Int {
    /// Read a value
    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        format::U32.read_sync(reader).map(Self)
    }
}

#[repr(transparent)]
/// Short style format: https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
pub struct Short(pub u16);
impl ValueFormat for Short {
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }
}
impl Short {
    /// Read a value
    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        format::U16.read_sync(reader).map(Self)
    }
}

#[repr(transparent)]
/// Tiny style format: https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
pub struct Tiny(pub u8);
impl ValueFormat for Tiny {
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.push(self.0);
    }
}
impl Tiny {
    /// Read a value
    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        format::U8.read_sync(reader).map(Self)
    }
}

#[repr(transparent)]
/// Double style format: https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
pub struct Double(pub f64);
impl ValueFormat for Double {
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }
}
impl Double {
    /// Read a value
    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        let mut bs = [0u8; 8];
        reader.read_exact(&mut bs)?;
        Ok(Self(f64::from_le_bytes(bs)))
    }
}

#[repr(transparent)]
/// Float style format: https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
pub struct Float(pub f32);
impl ValueFormat for Float {
    fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.extend(self.0.to_le_bytes());
    }
}
impl Float {
    /// Read a value
    pub fn read_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        let mut bs = [0u8; 4];
        reader.read_exact(&mut bs)?;
        Ok(Self(f32::from_le_bytes(bs)))
    }
}

// TODO: date time formats

/// An value of binary protocol
pub trait BinaryProtocolValue {
    /// Serialize value into bytes
    fn serialize_into(&self, sink: &mut Vec<u8>);
    /// A column type of the value
    fn column_type(&self) -> ColumnType;

    /// Returns whether self is a null value
    #[inline]
    fn is_null(&self) -> bool {
        self.column_type() == ColumnType::Null
    }
}
impl<'d, T> BinaryProtocolValue for &'d T
where
    T: BinaryProtocolValue,
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

impl BinaryProtocolValue for Value<'_> {
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
impl<A> BinaryProtocolValue for (Value<'_>, A) {
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

/// Serialize a [null bitmap](https://dev.mysql.com/doc/internals/en/binary-protocol-resultset-row.html) into bytes
pub fn serialize_null_bitmap(values: &[impl BinaryProtocolValue], sink: &mut Vec<u8>) {
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
        f |= cv(vs.get(0).map_or(false, BinaryProtocolValue::is_null), 0x01);
        f |= cv(vs.get(1).map_or(false, BinaryProtocolValue::is_null), 0x02);
        f |= cv(vs.get(2).map_or(false, BinaryProtocolValue::is_null), 0x04);
        f |= cv(vs.get(3).map_or(false, BinaryProtocolValue::is_null), 0x08);
        f |= cv(vs.get(4).map_or(false, BinaryProtocolValue::is_null), 0x10);
        f |= cv(vs.get(5).map_or(false, BinaryProtocolValue::is_null), 0x20);
        f |= cv(vs.get(6).map_or(false, BinaryProtocolValue::is_null), 0x40);
        f |= cv(vs.get(7).map_or(false, BinaryProtocolValue::is_null), 0x80);

        sink.push(f);
    }
}

/// Serialize value types into bytes
///
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

/// Serialize values into bytes
pub fn serialize_values<'d>(
    values: impl Iterator<Item = impl BinaryProtocolValue>,
    sink: &mut Vec<u8>,
) {
    for v in values {
        v.serialize_into(sink);
    }
}

/// Single row in binary protocol representation: https://dev.mysql.com/doc/internals/en/binary-protocol-resultset-row.html
#[derive(Debug)]
pub struct BinaryResultsetRow {
    /// bitmap of null values(extra 2 bits at head)
    pub null_bitmap: Vec<u8>,
    /// values in binary format
    pub values: Vec<u8>,
}
impl BinaryResultsetRow {
    /// Reads the payload
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

    /// Reads the payload
    pub fn read_sync(
        payload_length: usize,
        column_count: usize,
        mut reader: &mut ReadCountedSync<impl Read>,
    ) -> std::io::Result<Self> {
        let null_bitmap = format::Bytes((column_count + 7 + 2) / 8).read_sync(&mut reader)?;
        let values = format::Bytes(payload_length - reader.read_bytes()).read_sync(reader)?;

        Ok(Self {
            null_bitmap,
            values,
        })
    }

    /// Decode values following passed column types.
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

/// An iterator decoding values from a binary protocol row
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

/// Resultset packet in binary protocol
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

    /// Reads the packet
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

    /// Reads the packet
    pub fn read_packet_sync(
        mut reader: impl Read,
        client_capability: CapabilityFlags,
        column_count: usize,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(&mut reader)?;
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
