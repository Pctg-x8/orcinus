use std::{pin::Pin, task::Poll};

use futures_util::{future::LocalBoxFuture, pin_mut, FutureExt, TryFutureExt};
use tokio::io::{AsyncRead, AsyncReadExt, Result as IOResult};

pub mod authentication;
pub mod protos;

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

pub struct ReadCounted<R> {
    inner: R,
    counter: std::sync::atomic::AtomicUsize,
}
impl<R> ReadCounted<R> {
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn read_bytes(&self) -> usize {
        self.counter.load(std::sync::atomic::Ordering::Acquire)
    }
}
impl<R> AsyncRead for ReadCounted<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        match unsafe { Pin::new_unchecked(&mut this.inner).poll_read(cx, buf) } {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(Ok(())) => {
                this.counter
                    .fetch_add(buf.filled().len(), std::sync::atomic::Ordering::AcqRel);
                std::task::Poll::Ready(Ok(()))
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
impl<R> PacketReader for R where R: AsyncReadExt {}
