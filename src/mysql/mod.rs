use std::task::Poll;

use futures_util::{future::LocalBoxFuture, pin_mut, FutureExt, TryFutureExt};
use tokio::io::{AsyncReadExt, Result as IOResult};

mod authentication;
mod protos;

fn decompose_packet_header(bytes: u32) -> self::protos::PacketHeader {
    self::protos::PacketHeader {
        payload_length: bytes & 0x00ff_ffff,
        sequence_id: (bytes >> 24) as _,
    }
}

pub type ReadPacketHeader<'a> = futures_util::future::MapOk<
    LocalBoxFuture<'a, IOResult<u32>>,
    fn(u32) -> self::protos::PacketHeader,
>;

pub struct ReadNullTerminatedString<R> {
    reader: R,
    collected: Vec<u8>,
}
impl<R> std::future::Future for ReadNullTerminatedString<R>
where
    R: AsyncReadExt + Unpin,
{
    type Output = IOResult<String>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let reading = this.reader.read_u8();
            pin_mut!(reading);

            match reading.poll(cx) {
                Poll::Pending => break Poll::Pending,
                Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    break Poll::Ready(Ok(unsafe {
                        String::from_utf8_unchecked(std::mem::replace(
                            &mut this.collected,
                            Vec::new(),
                        ))
                    }))
                }
                Poll::Ready(Ok(c)) => {
                    this.collected.push(c);
                }
            }
        }
    }
}

pub trait PacketReader: AsyncReadExt {
    fn read_packet_header<'a>(&'a mut self) -> ReadPacketHeader<'a>
    where
        Self: Unpin,
    {
        self.read_u32_le()
            .boxed_local()
            .map_ok(decompose_packet_header)
    }

    fn read_null_terminated_string<'a>(&'a mut self) -> ReadNullTerminatedString<&'a mut Self>
    where
        Self: Unpin,
    {
        ReadNullTerminatedString {
            reader: self,
            collected: Vec::new(),
        }
    }
}
