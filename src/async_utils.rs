use std::{future::Future, pin::Pin, task::Poll};

use futures_util::ready;
use tokio::io::AsyncRead;

// TODO: ほんとうはassociated constでもちたい
pub trait ByteRepresentation<const N: usize> {
    fn from_le(bytes: [u8; N]) -> Self;
}
impl ByteRepresentation<1> for u8 {
    #[inline(always)]
    fn from_le(bytes: [u8; 1]) -> Self {
        bytes[0]
    }
}
impl ByteRepresentation<2> for u16 {
    #[inline(always)]
    fn from_le(bytes: [u8; 2]) -> Self {
        u16::from_le_bytes(bytes)
    }
}
impl ByteRepresentation<4> for u32 {
    #[inline(always)]
    fn from_le(bytes: [u8; 4]) -> Self {
        u32::from_le_bytes(bytes)
    }
}

pub struct ReadF<const N: usize, R, RP: ByteRepresentation<N>> {
    reader: R,
    buf: [u8; N],
    read_bytes: usize,
    _ph: std::marker::PhantomData<RP>,
}
impl<const N: usize, R, RP: ByteRepresentation<N>> ReadF<N, R, RP> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            buf: [0; N],
            read_bytes: 0,
            _ph: std::marker::PhantomData,
        }
    }
}
impl<const N: usize, R, RP: ByteRepresentation<N> + Unpin> Future for ReadF<N, R, RP>
where
    R: AsyncRead + Unpin,
{
    type Output = std::io::Result<RP>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match ready!(poll_read_until(
            &mut this.reader,
            cx,
            &mut this.buf,
            &mut this.read_bytes
        )) {
            Err(e) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(RP::from_le(this.buf))),
        }
    }
}

pub struct ReadLengthEncodedIntegerF<R> {
    reader: R,
    first_byte: Option<u8>,
    extra_bytes: [u8; 8],
    extra_read_bytes: usize,
}
impl<R> ReadLengthEncodedIntegerF<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            first_byte: None,
            extra_bytes: [0u8; 8],
            extra_read_bytes: 0,
        }
    }

    pub(crate) fn new_ahead(first_byte: u8, reader: R) -> Self {
        Self {
            reader,
            first_byte: Some(first_byte),
            extra_bytes: [0u8; 8],
            extra_read_bytes: 0,
        }
    }
}
impl<R> Future for ReadLengthEncodedIntegerF<R>
where
    R: AsyncRead + Unpin,
{
    type Output = std::io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let first_byte = match this.first_byte {
            Some(v) => v,
            None => {
                let mut buf = [0u8; 1];
                let mut buf = tokio::io::ReadBuf::new(&mut buf);
                match ready!(Pin::new(&mut this.reader).poll_read(cx, &mut buf)) {
                    Err(e) => {
                        return Poll::Ready(Err(e));
                    }
                    _ => {
                        let filled = buf.filled();
                        if filled.len() == 0 {
                            return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                        }
                        this.first_byte = Some(filled[0]);
                        filled[0]
                    }
                }
            }
        };

        match first_byte {
            x if x < 251 => Poll::Ready(Ok(x as _)),
            0xfc => match ready!(poll_read_until(
                &mut this.reader,
                cx,
                &mut this.extra_bytes[..2],
                &mut this.extra_read_bytes,
            )) {
                Err(e) => Poll::Ready(Err(e)),
                _ => Poll::Ready(Ok(
                    u16::from_le_bytes([this.extra_bytes[0], this.extra_bytes[1]]) as _,
                )),
            },
            0xfd => match ready!(poll_read_until(
                &mut this.reader,
                cx,
                &mut this.extra_bytes[..3],
                &mut this.extra_read_bytes,
            )) {
                Err(e) => Poll::Ready(Err(e)),
                _ => Poll::Ready(Ok(u32::from_le_bytes([
                    this.extra_bytes[0],
                    this.extra_bytes[1],
                    this.extra_bytes[2],
                    0x00,
                ]) as _)),
            },
            0xfe => match ready!(poll_read_until(
                &mut this.reader,
                cx,
                &mut this.extra_bytes,
                &mut this.extra_read_bytes,
            )) {
                Err(e) => Poll::Ready(Err(e)),
                _ => Poll::Ready(Ok(u64::from_le_bytes(this.extra_bytes))),
            },
            _ => unreachable!("unknown length encoded integer prefix: 0x{first_byte:02x}"),
        }
    }
}

pub struct ReadFixedBytesF<const N: usize, R> {
    reader: R,
    buf: Option<[u8; N]>,
    read_bytes: usize,
}
impl<const N: usize, R> ReadFixedBytesF<N, R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Some([0u8; N]),
            read_bytes: 0,
        }
    }
}
impl<const N: usize, R: AsyncRead + Unpin> Future for ReadFixedBytesF<N, R> {
    type Output = std::io::Result<[u8; N]>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let buf = this.buf.as_mut().expect("Future was resolved");

        match ready!(poll_read_until(
            &mut this.reader,
            cx,
            buf,
            &mut this.read_bytes
        )) {
            Err(e) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(unsafe { this.buf.take().unwrap_unchecked() })),
        }
    }
}

pub struct ReadBytesF<R> {
    reader: R,
    buf: Vec<u8>,
    read_bytes: usize,
}
impl<R> ReadBytesF<R> {
    pub(crate) fn new(reader: R, required_bytes: usize) -> Self {
        let mut buf = Vec::with_capacity(required_bytes);
        unsafe { buf.set_len(required_bytes) };

        Self {
            reader,
            buf,
            read_bytes: 0,
        }
    }

    pub(crate) fn new_ahead(reader: R, head: u8, required_bytes: usize) -> Self {
        let mut buf = Vec::with_capacity(required_bytes);
        unsafe {
            buf.set_len(required_bytes);
        }
        buf[0] = head;

        Self {
            reader,
            buf,
            read_bytes: 1,
        }
    }
}
impl<R: AsyncRead + Unpin> Future for ReadBytesF<R> {
    type Output = std::io::Result<Vec<u8>>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match ready!(poll_read_until(
            &mut this.reader,
            cx,
            &mut this.buf,
            &mut this.read_bytes
        )) {
            Err(e) => Poll::Ready(Err(e)),
            _ => {
                let r = std::mem::replace(&mut this.buf, Vec::new());
                this.read_bytes = 0;
                Poll::Ready(Ok(r))
            }
        }
    }
}

pub struct ReadNullTerminatedStringF<R> {
    reader: R,
    collected: Vec<u8>,
}
impl<R> ReadNullTerminatedStringF<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            collected: Vec::new(),
        }
    }
}
impl<R> Future for ReadNullTerminatedStringF<R>
where
    R: AsyncRead + Unpin,
{
    type Output = std::io::Result<String>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let mut buf = [0u8; 1];
            let mut buf = tokio::io::ReadBuf::new(&mut buf);

            match ready!(Pin::new(&mut this.reader).poll_read(cx, &mut buf)) {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(_) => {
                    let filled = buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                    }

                    if filled[0] == 0 {
                        return Poll::Ready(Ok(unsafe {
                            String::from_utf8_unchecked(std::mem::replace(
                                &mut this.collected,
                                Vec::new(),
                            ))
                        }));
                    } else {
                        this.collected.push(filled[0]);
                    }
                }
            }
        }
    }
}

fn poll_read_until(
    mut reader: &mut (impl AsyncRead + Unpin + ?Sized),
    cx: &mut std::task::Context,
    buf: &mut [u8],
    filled_bytes: &mut usize,
) -> Poll<std::io::Result<()>> {
    while *filled_bytes < buf.len() {
        let mut buf = tokio::io::ReadBuf::new(&mut buf[*filled_bytes..]);
        match Pin::new(&mut reader).poll_read(cx, &mut buf) {
            Poll::Pending => {
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(e));
            }
            Poll::Ready(_) => {
                let filled = buf.filled();
                if filled.len() == 0 {
                    return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                }
                *filled_bytes += filled.len();
            }
        }
    }

    Poll::Ready(Ok(()))
}
