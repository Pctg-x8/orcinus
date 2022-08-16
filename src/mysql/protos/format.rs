//! Protocol Serialization Format Fragments

use std::{io::Read, pin::Pin};

use futures_util::{future::LocalBoxFuture, FutureExt};
use tokio::io::{AsyncRead, AsyncReadExt};

pub trait ProtocolFormatFragment<'r, R> {
    type Output;
    type ReaderF: 'r + std::future::Future<Output = std::io::Result<Self::Output>>;

    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output>;
    fn read(self, reader: &'r mut R) -> Self::ReaderF;
}

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
}
impl<const N: usize, R, RP: ByteRepresentation<N>> ReadF<N, R, RP> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buf: [0; 1],
            read_bytes: 0,
        }
    }
}
impl<const N: usize, R, RP: ByteRepresentation<N>> std::future::Future for ReadF<N, R, RP>
where
    R: AsyncRead + Unpin,
{
    type Output = std::io::Result<u8>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        while self.read_bytes < N {
            let mut buf = tokio::io::ReadBuf::new(&mut self.buf[self.read_bytes..]);

            match Pin::new(&mut self.reader).poll_read(cx, &mut buf) {
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Ready(_) => {
                    let r = buf.filled().len();
                    if r == 0 {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "",
                        )));
                    }
                    self.read_bytes += buf.filled().len();
                }
            }
        }

        std::task::Poll::Ready(Ok(RP::form_le(self.buf)))
    }
}

pub struct ReadLengthEncodedIntegerF<R> {
    reader: R,
    first_byte: Option<u8>,
    extra_bytes: [u8; 8],
    extra_read_bytes: usize,
}
impl<R> ReadLengthEncodedIntegerF<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            first_byte: None,
            extra_bytes: [0u8; 8],
            extra_read_bytes: 0,
        }
    }
}
impl<R> std::future::Future for ReadLengthEncodedIntegerF<R>
where
    R: AsyncRead + Unpin,
{
    type Output = std::io::Result<u8>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let first_byte = match self.first_byte {
            Some(v) => v,
            None => {
                let mut buf = tokio::io::ReadBuf::new(&mut [0u8; 1]);
                match Pin::new(&mut self.reader).poll_read(cx, &mut buf) {
                    std::task::Poll::Pending => {
                        return std::task::Poll::Pending;
                    }
                    std::task::Poll::Ready(Err(e)) => {
                        return std::task::Poll::Ready(Err(e));
                    }
                    std::task::Poll::Ready(_) => {
                        let filled = buf.filled();
                        if filled.len() == 0 {
                            return std::task::Poll::Ready(Err(
                                std::io::ErrorKind::UnexpectedEof.into()
                            ));
                        }
                        self.first_byte = Some(filled[0]);
                        filled[0]
                    }
                }
            }
        };

        match first_byte {
            x if x < 251 => std::task::Poll::Ready(x as _),
            0xfc => match poll_read_until(
                Pin::new(&mut self.reader),
                cx,
                &mut self.extra_bytes[..2],
                &mut self.extra_read_bytes,
            ) {
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Ready(_) => {
                    std::task::Poll::Ready(Ok(u16::from_le_bytes(self.extra_bytes[..2]) as _))
                }
            },
            0xfd => match poll_read_until(
                Pin::new(&mut self.reader),
                cx,
                &mut self.extra_bytes[..3],
                &mut self.extra_read_bytes,
            ) {
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Ready(_) => {
                    self.extra_bytes[3] = 0x00;
                    std::task::Poll::Ready(Ok(u32::from_le_bytes(self.extra_bytes[..4]) as _))
                }
            },
            0xfe => match poll_read_until(
                Pin::new(&mut self.reader),
                cx,
                &mut self.extra_bytes,
                &mut self.extra_read_bytes,
            ) {
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Ready(_) => {
                    std::task::Poll::Ready(Ok(u16::from_le_bytes(self.extra_bytes) as _))
                }
            },
            _ => unreachable!("unknown length encoded integer prefix: 0x{first_byte:02x}"),
        }
    }
}

pub struct ReadFixedBytesF<const N: usize, R> {
    reader: R,
    buf: [u8; N],
    read_bytes: usize,
}
impl<const N: usize, R> ReadFixedBytesF<N, R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buf: [0u8; N],
            read_bytes: 0,
        }
    }
}
impl<const N: usize, R: AsyncRead + Unpin> std:::future::Future for ReadFixedBytesF<N, R> {
    type Output = std::io::Result<>;
}

fn poll_read_until(
    reader: Pin<&mut (impl AsyncRead + Unpin + ?Sized)>,
    cx: &mut std::task::Context,
    buf: &mut [u8],
    filled_bytes: &mut usize,
) -> std::task::Poll<std::io::Result<()>> {
    while *filled_bytes < buf.len() {
        let mut buf = tokio::io::ReadBuf::new(&mut buf[*filled_bytes..]);
        match reader.poll_read(cx, &mut buf) {
            std::task::Poll::Pending => {
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(Err(e)) => {
                return std::task::Poll::Ready(Err(e));
            }
            std::task::Poll::Ready(_) => {
                let filled = buf.filled();
                if filled.len() == 0 {
                    return std::task::Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                }
                filled_bytes += filled.len();
            }
        }
    }

    std::task::Poll::Ready(Ok(()))
}

pub struct U8;
impl<'r, R: AsyncRead + Unpin> ProtocolFormatFragment<'r, R> for U8 {
    type Output = u8;
    type ReaderF = ReadF<1, &'r mut R, u8>;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        Ok(b[0])
    }

    #[inline]
    fn read(self, reader: &'r mut R) -> Self::ReaderF {
        ReadF::new(reader)
    }
}

pub struct U16;
impl<'r, R: AsyncRead + Unpin> ProtocolFormatFragment<'r, R> for U16 {
    type Output = u16;
    type ReaderF = ReadF<2, &'r mut R, u16>;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 2];
        reader.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    #[inline]
    fn read(self, reader: &'r mut R) -> Self::ReaderF {
        reader.read_u16_le().boxed_local()
    }
}

pub struct U32;
impl<'r, R: AsyncRead + Unpin> ProtocolFormatFragment<'r, R> for U32 {
    type Output = u32;
    type ReaderF = ReadF<4, &'r mut R, u32>;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 4];
        reader.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    #[inline]
    fn read(self, reader: &'r mut R) -> Self::ReaderF {
        ReadF::new(reader)
    }
}

pub struct LengthEncodedInteger;
impl<'r, R: AsyncRead + Unpin> ProtocolFormatFragment<'r, R> for LengthEncodedInteger {
    type Output = u64;
    type ReaderF = ReadLengthEncodedIntegerF<&'r mut R>;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        super::LengthEncodedInteger::read_sync(reader).map(|x| x.0)
    }

    #[inline]
    fn read(self, reader: &'r mut R) -> Self::ReaderF {
        ReadLengthEncodedIntegerF::new(reader)
    }
}

pub struct FixedBytes<const L: usize>;
impl<const L: usize> ProtocolFormatFragment for FixedBytes<L> {
    type Output = [u8; L];

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = [0u8; L];
        reader.read_exact(&mut b)?;
        Ok(b)
    }
}

pub struct Bytes(pub usize);
impl ProtocolFormatFragment for Bytes {
    type Output = Vec<u8>;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = Vec::with_capacity(self.0);
        unsafe {
            b.set_len(self.0);
        }
        reader.read_exact(&mut b)?;
        Ok(b)
    }
}

pub struct NullTerminatedString;
impl ProtocolFormatFragment for NullTerminatedString {
    type Output = String;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut collected = Vec::new();
        let mut rb = [0u8; 1];

        loop {
            reader.read_exact(&mut rb)?;
            if rb[0] == 0 {
                return Ok(unsafe { String::from_utf8_unchecked(collected) });
            } else {
                collected.push(rb[0]);
            }
        }
    }
}

pub struct FixedLengthString(pub usize);
impl ProtocolFormatFragment for FixedLengthString {
    type Output = String;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = Vec::with_capacity(self.0);
        unsafe {
            b.set_len(self.0);
        }
        reader.read_exact(&mut b)?;
        Ok(unsafe { String::from_utf8_unchecked(b) })
    }
}

pub struct LengthEncodedString;
impl ProtocolFormatFragment for LengthEncodedString {
    type Output = String;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let len = LengthEncodedInteger.read_sync(reader)?;
        FixedLengthString(len as _).read_sync(reader)
    }
}

pub struct PacketHeader;
impl ProtocolFormatFragment for PacketHeader {
    type Output = super::PacketHeader;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut ph = [0u8; 4];
        reader.read_exact(&mut ph)?;

        Ok(super::PacketHeader {
            payload_length: u32::from_le_bytes(ph) & 0x00ff_ffff,
            sequence_id: ph[3],
        })
    }
}

macro_rules! ProtocolFormatFragmentGroup {
    ($($a: ident: $n: tt),+) => {
        impl<$($a),+> ProtocolFormatFragment for ($($a),+) where $($a: ProtocolFormatFragment),+ {
            type Output = ($($a::Output),+);

            #[inline]
            fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
                #![allow(non_snake_case)]
                $(let $a = self.$n.read_sync(reader)?;)+

                Ok(($($a),+))
            }
        }
    }
}

ProtocolFormatFragmentGroup!(A: 0, B: 1);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19, U: 20);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19, U: 20, V: 21);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19, U: 20, V: 21, W: 22);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19, U: 20, V: 21, W: 22, X: 23);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19, U: 20, V: 21, W: 22, X: 23, Y: 24);
ProtocolFormatFragmentGroup!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19, U: 20, V: 21, W: 22, X: 23, Y: 24, Z: 25);

#[macro_export]
macro_rules! ReadSync {
    ($reader: expr => { $($val: ident <- $fmt: expr),* }) => {
        #[allow(unused_parens)]
        let ($($val),*) = ($($fmt),*).read_sync($reader)?;
    }
}
