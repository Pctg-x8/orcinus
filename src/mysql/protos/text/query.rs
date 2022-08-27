use std::io::Read;

use futures_util::{future::BoxFuture, FutureExt};
use tokio::io::AsyncRead;

use crate::{
    counted_read::{ReadCounted, ReadCountedSync},
    protos::{
        format::{self, AsyncProtocolFormatFragment, ProtocolFormatFragment},
        AsyncReceivePacket, CapabilityFlags, ClientPacket, ClientPacketIO, ColumnType, EOFPacket41, EOFPacket41Format,
        ErrPacket, InvalidColumnTypeError, LengthEncodedInteger, OKPacket, PacketHeader, ReceivePacket,
    },
    DefFormatStruct,
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
impl ClientPacketIO for QueryCommand<'_> {
    type Receiver = QueryCommandResponse;
}

#[derive(Debug)]
pub enum QueryCommandResponse {
    Ok(OKPacket),
    Err(ErrPacket),
    LocalInfileRequest { filename: String },
    Resultset { column_count: u64 },
}
impl QueryCommandResponse {
    #[inline]
    const fn resultset_format(
        head_byte: u8,
    ) -> format::Mapped<format::LengthEncodedIntegerAhead, fn(u64) -> QueryCommandResponse> {
        fn make(column_count: u64) -> QueryCommandResponse {
            QueryCommandResponse::Resultset { column_count }
        }

        format::Mapped(format::LengthEncodedIntegerAhead(head_byte), make)
    }
    #[inline]
    const fn local_infile_format(
        string_length: usize,
    ) -> format::Mapped<format::FixedLengthString, fn(String) -> QueryCommandResponse> {
        fn make(filename: String) -> QueryCommandResponse {
            QueryCommandResponse::LocalInfileRequest { filename }
        }

        format::Mapped(format::FixedLengthString(string_length), make)
    }
}
impl ReceivePacket for QueryCommandResponse {
    fn read_packet(mut reader: impl Read, client_capability: CapabilityFlags) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(&mut reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let head_value = format::U8.read_sync(&mut reader)?;

        match head_value {
            0x00 => {
                OKPacket::read_sync(packet_header.payload_length as _, &mut reader, client_capability).map(Self::Ok)
            }
            0xff => {
                ErrPacket::read_sync(packet_header.payload_length as _, &mut reader, client_capability).map(Self::Err)
            }
            0xfb => Self::local_infile_format(packet_header.payload_length as usize - reader.read_bytes())
                .read_sync(reader.into_inner()),
            _ => Self::resultset_format(head_value).read_sync(reader.into_inner()),
        }
    }
}
impl<'r, R> AsyncReceivePacket<'r, R> for QueryCommandResponse
where
    R: AsyncRead + Unpin + Send + Sync + 'r,
{
    type ReceiveF = BoxFuture<'r, std::io::Result<Self>>;

    fn read_packet_async(mut reader: R, client_capability: CapabilityFlags) -> Self::ReceiveF {
        async move {
            let packet_header = format::PacketHeader.read_format(&mut reader).await?;
            let mut reader = ReadCounted::new(reader);
            let head_value = format::U8.read_format(&mut reader).await?;

            match head_value {
                0x00 => OKPacket::read(packet_header.payload_length as _, &mut reader, client_capability)
                    .await
                    .map(Self::Ok),
                0xff => ErrPacket::read(packet_header.payload_length as _, &mut reader, client_capability)
                    .await
                    .map(Self::Err),
                0xfb => {
                    Self::local_infile_format(packet_header.payload_length as usize - reader.read_bytes())
                        .read_format(reader.into_inner())
                        .await
                }
                _ => {
                    Self::resultset_format(head_value)
                        .read_format(reader.into_inner())
                        .await
                }
            }
        }
        .boxed()
    }
}

#[derive(Debug)]
pub struct ColumnDefinition41 {
    pub catalog: String,
    pub schema: String,
    pub table: String,
    pub org_table: String,
    pub name: String,
    pub org_name: String,
    pub character_set: u16,
    pub column_length: u32,
    pub type_byte: u8,
    pub flags: u16,
    pub decimals: u8,
    pub default_values: Option<String>,
}
DefFormatStruct!(pub RawColumnDefinition41(RawColumnDefinition41Format) {
    _packet_header(PacketHeader) <- format::PacketHeader,
    catalog(String) <- format::LengthEncodedString,
    schema(String) <- format::LengthEncodedString,
    table(String) <- format::LengthEncodedString,
    org_table(String) <- format::LengthEncodedString,
    name(String) <- format::LengthEncodedString,
    org_name(String) <- format::LengthEncodedString,
    _fixed_length_fields_len(u64) <- format::LengthEncodedInteger.assert_eq(0x0c),
    character_set(u16) <- format::U16,
    column_length(u32) <- format::U32,
    type_byte(u8) <- format::U8,
    flags(u16) <- format::U16,
    decimals(u8) <- format::U8,
    _filler([u8; 2]) <- format::FixedBytes::<2>
});
impl From<RawColumnDefinition41> for ColumnDefinition41 {
    fn from(r: RawColumnDefinition41) -> Self {
        Self {
            catalog: r.catalog,
            schema: r.schema,
            table: r.table,
            org_table: r.org_table,
            name: r.name,
            org_name: r.org_name,
            character_set: r.character_set,
            column_length: r.column_length,
            type_byte: r.type_byte,
            flags: r.flags,
            decimals: r.decimals,
            default_values: None,
        }
    }
}
DefFormatStruct!(RawColumnDefinition41ForFieldList(RawColumnDefinition41ForFieldListFormat) {
    base(RawColumnDefinition41) <- RawColumnDefinition41Format,
    default_values(String) <- format::LengthEncodedString
});
impl From<RawColumnDefinition41ForFieldList> for ColumnDefinition41 {
    fn from(r: RawColumnDefinition41ForFieldList) -> Self {
        Self {
            default_values: Some(r.default_values),
            ..r.base.into()
        }
    }
}
impl ColumnDefinition41 {
    pub async fn read_packet_for_field_list(
        reader: &mut (impl AsyncRead + Sync + Send + Unpin + ?Sized),
    ) -> std::io::Result<Self> {
        RawColumnDefinition41ForFieldListFormat
            .read_format(reader)
            .await
            .map(From::from)
    }

    pub fn read_packet_for_field_list_sync(reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self> {
        RawColumnDefinition41ForFieldListFormat
            .read_sync(reader)
            .map(From::from)
    }

    #[inline]
    pub fn r#type(&self) -> Result<ColumnType, InvalidColumnTypeError> {
        self.type_byte.try_into()
    }

    #[inline]
    pub unsafe fn type_unchecked(&self) -> ColumnType {
        ColumnType::from_u8_unchecked(self.type_byte)
    }
}
impl ReceivePacket for ColumnDefinition41 {
    fn read_packet(reader: impl Read, _client_capability: CapabilityFlags) -> std::io::Result<Self> {
        RawColumnDefinition41Format.read_sync(reader).map(From::from)
    }
}
impl<'r, R> AsyncReceivePacket<'r, R> for ColumnDefinition41
where
    R: AsyncRead + Unpin + Send + 'r,
{
    type ReceiveF = <format::Mapped<
        RawColumnDefinition41Format,
        fn(RawColumnDefinition41) -> ColumnDefinition41,
    > as AsyncProtocolFormatFragment<'r, &'r mut R>>::ReaderF;

    fn read_packet_async(reader: R, _client_capability: CapabilityFlags) -> Self::ReceiveF {
        RawColumnDefinition41Format.map(Self::from as _).read_format(reader)
    }
}

#[derive(Debug)]
pub enum ResultsetValue<'s> {
    Null,
    Value(&'s str),
}
#[repr(transparent)]
#[derive(Debug)]
pub struct ResultsetRow(Vec<u8>);
impl ResultsetRow {
    pub fn decompose_values<'s>(&'s self) -> ResultsetValueDecomposer<'s> {
        ResultsetValueDecomposer(std::io::Cursor::new(&self.0))
    }
}

pub struct ResultsetValueDecomposer<'s>(std::io::Cursor<&'s [u8]>);
impl<'s> Iterator for ResultsetValueDecomposer<'s> {
    type Item = ResultsetValue<'s>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.get_ref().len() == self.0.position() as usize {
            return None;
        }

        match self.0.get_ref()[self.0.position() as usize] {
            0xfb => {
                self.0.set_position(self.0.position() + 1);
                Some(ResultsetValue::Null)
            }
            _ => {
                let LengthEncodedInteger(len) =
                    LengthEncodedInteger::read_sync(&mut self.0).expect("Failed to read resultset bytes");
                let s = &self.0.get_ref()[self.0.position() as usize..(self.0.position() + len) as usize];
                self.0.set_position(self.0.position() + len);
                Some(ResultsetValue::Value(unsafe { std::str::from_utf8_unchecked(s) }))
            }
        }
    }
}

pub enum Resultset41 {
    Row(ResultsetRow),
    Err(ErrPacket),
    Ok(OKPacket),
    EOF(EOFPacket41),
}
impl Resultset41 {
    #[inline]
    const fn row_format(
        head_byte: u8,
        payload_length: usize,
    ) -> format::Mapped<format::BytesAhead, fn(Vec<u8>) -> Resultset41> {
        fn make(b: Vec<u8>) -> Resultset41 {
            Resultset41::Row(ResultsetRow(b))
        }

        format::Mapped(format::BytesAhead(head_byte, payload_length), make)
    }
    const EOF_FORMAT: format::Mapped<EOFPacket41Format, fn(EOFPacket41) -> Self> =
        format::Mapped(EOFPacket41Format, Self::EOF);

    pub async fn read_packet(
        mut reader: &mut (impl AsyncRead + Unpin + Sync + Send + ?Sized),
        client_capabilities: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_format(&mut reader).await?;
        let mut reader = ReadCounted::new(reader);
        let head_byte = format::U8.read_format(&mut reader).await?;

        match head_byte {
            // treat as OK Packet for client supports DEPRECATE_EOF capability
            0xfe if client_capabilities.support_deprecate_eof() => {
                OKPacket::read(packet_header.payload_length as _, &mut reader, client_capabilities)
                    .await
                    .map(Self::Ok)
            }
            0xfe => Self::EOF_FORMAT.read_format(reader.into_inner()).await,
            0x00 => OKPacket::read(packet_header.payload_length as _, &mut reader, client_capabilities)
                .await
                .map(Self::Ok),
            0xff => ErrPacket::read(packet_header.payload_length as _, &mut reader, client_capabilities)
                .await
                .map(Self::Err),
            _ => {
                Self::row_format(head_byte, packet_header.payload_length as _)
                    .read_format(reader.into_inner())
                    .await
            }
        }
    }

    pub fn read_packet_sync(mut reader: impl Read, client_capability: CapabilityFlags) -> std::io::Result<Self> {
        let packet_header = format::PacketHeader.read_sync(&mut reader)?;
        let mut reader = ReadCountedSync::new(reader);
        let head_byte = format::U8.read_sync(&mut reader)?;

        match head_byte {
            // treat as OK Packet for client supports DEPRECATE_EOF capability
            0xfe if client_capability.support_deprecate_eof() => {
                OKPacket::read_sync(packet_header.payload_length as _, &mut reader, client_capability).map(Self::Ok)
            }
            0xfe => Self::EOF_FORMAT.read_sync(reader.into_inner()),
            0x00 => {
                OKPacket::read_sync(packet_header.payload_length as _, &mut reader, client_capability).map(Self::Ok)
            }
            0xff => {
                ErrPacket::read_sync(packet_header.payload_length as _, &mut reader, client_capability).map(Self::Err)
            }
            _ => Self::row_format(head_byte, packet_header.payload_length as _).read_sync(reader.into_inner()),
        }
    }
}
