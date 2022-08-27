use super::binary;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
/// A Column Type byte: https://dev.mysql.com/doc/internals/en/com-query-response.html#column-type
pub enum ColumnType {
    Decimal = 0x00,
    Tiny = 0x01,
    Short = 0x02,
    Long = 0x03,
    Float = 0x04,
    Double = 0x05,
    Null = 0x06,
    Timestamp = 0x07,
    LongLong = 0x08,
    Int24 = 0x09,
    Date = 0x0a,
    Time = 0x0b,
    DateTime = 0x0c,
    Year = 0x0d,
    NewDate = 0x0e,
    Varchar = 0x0f,
    Bit = 0x10,
    Timestamp2 = 0x11,
    DateTime2 = 0x12,
    Time2 = 0x13,
    NewDecimal = 0xf6,
    Enum = 0xf7,
    Set = 0xf8,
    TinyBlob = 0xf9,
    MediumBlob = 0xfa,
    LongBlob = 0xfb,
    Blob = 0xfc,
    VarString = 0xfd,
    String = 0xfe,
    Geometry = 0xff,
}
impl ColumnType {
    /// Converts from raw byte value
    ///
    /// this function does not check whether the passed value is valid `ColumnType` value.
    pub unsafe fn from_u8_unchecked(value: u8) -> Self {
        std::mem::transmute(value)
    }

    /// Slices a value from preloaded binary row
    ///
    /// This operation is less-copy(taking references for `ByteString`-encoded types)
    pub fn slice_value<'s>(
        &self,
        reader: &mut std::io::Cursor<&'s [u8]>,
    ) -> std::io::Result<Value<'s>> {
        match self {
            Self::Decimal => binary::ByteString::slice_from(reader)
                .map(|x| Value::Decimal(unsafe { x.as_str_unchecked() })),
            Self::Tiny => binary::Tiny::read_sync(reader).map(|x| Value::Tiny(x.0)),
            Self::Short => binary::Short::read_sync(reader).map(|x| Value::Short(x.0)),
            Self::Long => binary::Int::read_sync(reader).map(|x| Value::Long(x.0)),
            Self::Float => binary::Float::read_sync(reader).map(|x| Value::Float(x.0)),
            Self::Double => binary::Double::read_sync(reader).map(|x| Value::Double(x.0)),
            Self::Null => Ok(Value::Null),
            Self::Timestamp => todo!("read timestamp"),
            Self::LongLong => binary::LongLong::read_sync(reader).map(|x| Value::LongLong(x.0)),
            Self::Int24 => binary::Int::read_sync(reader).map(|x| Value::Int24(x.0)),
            Self::Date => todo!("read date"),
            Self::Time => todo!("read time"),
            Self::DateTime => todo!("read datetime"),
            Self::Year => binary::Short::read_sync(reader).map(|x| Value::Year(x.0)),
            Self::NewDate => todo!("read new date"),
            Self::Varchar => binary::ByteString::slice_from(reader)
                .map(|x| Value::Varchar(unsafe { x.as_str_unchecked() })),
            Self::Bit => binary::ByteString::slice_from(reader).map(|x| Value::Bit(x.0)),
            Self::Timestamp2 => todo!("read timestamp2"),
            Self::DateTime2 => todo!("read datetime2"),
            Self::Time2 => todo!("read time2"),
            Self::NewDecimal => binary::ByteString::slice_from(reader)
                .map(|x| Value::NewDecimal(unsafe { x.as_str_unchecked() })),
            Self::Enum => binary::ByteString::slice_from(reader)
                .map(|x| Value::Enum(unsafe { x.as_str_unchecked() })),
            Self::Set => binary::ByteString::slice_from(reader)
                .map(|x| Value::Set(unsafe { x.as_str_unchecked() })),
            Self::TinyBlob => binary::ByteString::slice_from(reader).map(|x| Value::TinyBlob(x.0)),
            Self::MediumBlob => {
                binary::ByteString::slice_from(reader).map(|x| Value::MediumBlob(x.0))
            }
            Self::LongBlob => binary::ByteString::slice_from(reader).map(|x| Value::LongBlob(x.0)),
            Self::Blob => binary::ByteString::slice_from(reader).map(|x| Value::Blob(x.0)),
            Self::VarString => binary::ByteString::slice_from(reader)
                .map(|x| Value::VarString(unsafe { x.as_str_unchecked() })),
            Self::String => binary::ByteString::slice_from(reader)
                .map(|x| Value::String(unsafe { x.as_str_unchecked() })),
            Self::Geometry => binary::ByteString::slice_from(reader).map(|x| Value::Geometry(x.0)),
        }
    }
}
impl TryFrom<u8> for ColumnType {
    type Error = InvalidColumnTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= Self::Time2 as u8
            || (Self::NewDecimal as u8 <= value && value <= Self::Geometry as u8)
        {
            Ok(unsafe { Self::from_u8_unchecked(value) })
        } else {
            Err(InvalidColumnTypeError(value))
        }
    }
}

#[derive(Debug)]
/// A value in resultset/sql
pub enum Value<'s> {
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

pub struct InvalidColumnTypeError(u8);
impl std::fmt::Debug for InvalidColumnTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid column type: 0x{:02x}", self.0)
    }
}
impl std::fmt::Display for InvalidColumnTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for InvalidColumnTypeError {}
