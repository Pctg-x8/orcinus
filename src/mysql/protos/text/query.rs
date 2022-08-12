use tokio::io::AsyncReadExt;

use crate::{
    protos::{
        read_lenenc_str, CapabilityFlags, ClientPacket, EOFPacket41, ErrPacket,
        LengthEncodedInteger, OKPacket,
    },
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
    Resultset { column_count: u64 },
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
            }
            _ => {
                let LengthEncodedInteger(column_count) =
                    LengthEncodedInteger::read_ahead(head_value, &mut reader).await?;
                Ok(Self::Resultset { column_count })
            }
        }
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
    pub r#type: u8,
    pub flags: u16,
    pub decimals: u8,
    pub default_values: Option<String>,
}
impl ColumnDefinition41 {
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin + ?Sized),
    ) -> std::io::Result<Self> {
        let _ = reader.read_packet_header().await?;

        let catalog = read_lenenc_str(reader).await?;
        let schema = read_lenenc_str(reader).await?;
        let table = read_lenenc_str(reader).await?;
        let org_table = read_lenenc_str(reader).await?;
        let name = read_lenenc_str(reader).await?;
        let org_name = read_lenenc_str(reader).await?;
        let LengthEncodedInteger(fixed_length_fields_len) =
            LengthEncodedInteger::read(reader).await?;
        assert_eq!(fixed_length_fields_len, 0x0c);
        let character_set = reader.read_u16_le().await?;
        let column_length = reader.read_u32_le().await?;
        let r#type = reader.read_u8().await?;
        let flags = reader.read_u16_le().await?;
        let decimals = reader.read_u8().await?;
        let mut _filler = [0u8; 2];
        reader.read_exact(&mut _filler).await?;

        Ok(Self {
            catalog,
            schema,
            table,
            org_table,
            name,
            org_name,
            character_set,
            column_length,
            r#type,
            flags,
            decimals,
            default_values: None,
        })
    }

    pub async fn read_packet_for_field_list(
        reader: &mut (impl PacketReader + Unpin + ?Sized),
    ) -> std::io::Result<Self> {
        let org = Self::read_packet(reader).await?;
        let default_values = read_lenenc_str(reader).await?;

        Ok(Self {
            default_values: Some(default_values),
            ..org
        })
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
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin + ?Sized),
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut packet_content = Vec::with_capacity(packet_header.payload_length as _);
        unsafe {
            packet_content.set_len(packet_header.payload_length as _);
        }
        reader.read_exact(&mut packet_content).await?;

        Ok(Self(packet_content))
    }

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
                let LengthEncodedInteger(len) = LengthEncodedInteger::read_sync(&mut self.0)
                    .expect("Failed to read resultset bytes");
                let s = &self.0.get_ref()
                    [self.0.position() as usize..(self.0.position() + len) as usize];
                self.0.set_position(self.0.position() + len);
                Some(ResultsetValue::Value(unsafe {
                    std::str::from_utf8_unchecked(s)
                }))
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
    pub async fn read_packet(
        reader: &mut (impl PacketReader + Unpin + ?Sized),
        client_capabilities: CapabilityFlags,
    ) -> std::io::Result<Self> {
        let packet_header = reader.read_packet_header().await?;
        let mut reader = ReadCounted::new(reader);
        let r1 = reader.read_u8().await?;

        match r1 {
            0x00 => OKPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capabilities,
            )
            .await
            .map(Self::Ok),
            0xfe => EOFPacket41::read(&mut reader).await.map(Self::EOF),
            0xff => ErrPacket::read(
                packet_header.payload_length as _,
                &mut reader,
                client_capabilities,
            )
            .await
            .map(Self::Err),
            _ => {
                let mut contents = Vec::with_capacity(packet_header.payload_length as _);
                unsafe {
                    contents.set_len(packet_header.payload_length as _);
                }
                contents[0] = r1;
                reader.read_exact(&mut contents[1..]).await?;
                Ok(Self::Row(ResultsetRow(contents)))
            }
        }
    }
}
