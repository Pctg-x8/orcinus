//! Binary Protocol

use tokio::io::AsyncReadExt;

use crate::{PacketReader, ReadCounted};

use super::{CapabilityFlags, ColumnType, EOFPacket41, ErrPacket, LengthEncodedInteger, OKPacket};

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

#[repr(transparent)]
pub struct LongLong(pub u64);
impl LongLong {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.reserve(8);
        sink.extend(self.0.to_le_bytes());
    }
}

#[repr(transparent)]
pub struct Int(pub u32);
impl Int {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.reserve(4);
        sink.extend(self.0.to_le_bytes());
    }
}

#[repr(transparent)]
pub struct Short(pub u16);
impl Short {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.reserve(2);
        sink.extend(self.0.to_le_bytes());
    }
}

#[repr(transparent)]
pub struct Tiny(pub u8);
impl Tiny {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.push(self.0);
    }
}

#[repr(transparent)]
pub struct Double(pub f64);
impl Double {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.reserve(8);
        sink.extend(self.0.to_le_bytes());
    }
}

#[repr(transparent)]
pub struct Float(pub f32);
impl Float {
    pub fn serialize_into(&self, sink: &mut Vec<u8>) {
        sink.reserve(4);
        sink.extend(self.0.to_le_bytes());
    }
}

// TODO: date time formats

pub enum BinaryProtocolValue<'s> {
    String(&'s str),
    Varchar(&'s str),
    VarString(&'s str),
    Enum(&'s str),
    Set(&'s str),
    LongBlob(&'s [u8]),
    MediumBlob(&'s [u8]),
    Blob(&'s [u8]),
    TinyBlob(&'s [u8]),
    Geometry(&'s [u8]),
    Bit(&'s [u8]),
    Decimal(&'s str),
    NewDecimal(&'s str),
    LongLong(u64),
    Long(u32),
    Int24(u32),
    Short(u16),
    Year(u16),
    Tiny(u8),
    Double(f64),
    Float(f32),
    Null,
}
pub trait BinaryProtocolValueDeconstructor {
    fn serialize_into(&self, sink: &mut Vec<u8>);
    fn column_type(&self) -> ColumnType;
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
impl BinaryProtocolValueDeconstructor for BinaryProtocolValue<'_> {
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
impl<A> BinaryProtocolValueDeconstructor for (BinaryProtocolValue<'_>, A) {
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
    values: impl Iterator<Item = (&'d BinaryProtocolValue<'d>, bool)>,
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
        reader: &mut ReadCounted<impl AsyncReadExt + Unpin>,
    ) -> std::io::Result<Self> {
        let mut null_bitmap = Vec::with_capacity((column_count + 7) / 8);
        unsafe {
            null_bitmap.set_len((column_count + 7) / 8);
        }
        reader.read_exact(&mut null_bitmap).await?;
        let rest_length = payload_length - reader.read_bytes();
        let mut values = Vec::with_capacity(rest_length);
        unsafe {
            values.set_len(rest_length);
        }
        reader.read_exact(&mut values).await?;

        Ok(Self {
            null_bitmap,
            values,
        })
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
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin + ?Sized),
        client_capabilities: CapabilityFlags,
        column_count: usize,
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut reader = ReadCounted::new(reader);
        let r1 = reader.read_u8().await?;

        match r1 {
            0xfe if !client_capabilities.support_deprecate_eof() => {
                EOFPacket41::read(&mut reader).await.map(Self::EOF)
            }
            // treat as OK Packet for client supports DEPRECATE_EOF capability
            0xfe if client_capabilities.support_deprecate_eof() => OKPacket::read(
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
            // 0x00 is a normal resultset row in binary protocol(terminal packet is OK packet started with 0xfe)
            0x00 => BinaryResultsetRow::read(
                packet_header.payload_length as _,
                column_count,
                &mut reader,
            )
            .await
            .map(Self::Row),
            _ => unreachable!("invalid heading byte for binary protocol resultset: 0x{r1:02x}")
        }
    }
}
