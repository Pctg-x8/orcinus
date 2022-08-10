use std::io::Write;

use tokio::io::AsyncWriteExt;

pub struct PacketHeader {
    pub payload_length: u32,
    pub sequence_id: u8,
}
impl PacketHeader {
    pub async fn write(&self, writer: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
        writer
            .write_all(&[
                (self.payload_length & 0xff) as u8,
                ((self.payload_length >> 8) & 0xff) as _,
                ((self.payload_length >> 16) & 0xff) as _,
                self.sequence_id,
            ])
            .await
    }
}
pub async fn write_packet(
    writer: &mut (impl AsyncWriteExt + Unpin),
    payload: &[u8],
    sequence_id: u8,
) -> std::io::Result<()> {
    PacketHeader {
        payload_length: payload.len() as _,
        sequence_id
    }.write(writer).await?;
    writer.write_all(payload).await
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

    pub fn write_sync(&self, writer: &mut impl Write) -> std::io::Result<()> {
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

    pub async fn write(&self, writer: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
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

mod capabilities;
mod handshake;
