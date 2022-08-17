//! Protocol Serialization Format Fragments

use std::{io::Read, pin::Pin};

use futures_util::{future::LocalBoxFuture, FutureExt, TryFutureExt};
use tokio::io::AsyncRead;

use crate::ReadNullTerminatedString;

pub trait ProtocolFormatFragment {
    type Output;

    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output>;

    #[inline]
    fn map<F, R>(self, mapper: F) -> Mapped<Self, F>
    where
        Self: Sized,
        F: FnOnce(Self::Output) -> R,
    {
        Mapped(self, mapper)
    }
}

pub trait AsyncProtocolFormatFragment<'r, R: 'r + ?Sized>: ProtocolFormatFragment {
    type ReaderF: 'r + std::future::Future<Output = std::io::Result<Self::Output>>;

    fn read_format(self, reader: &'r mut R) -> Self::ReaderF;
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
    _ph: std::marker::PhantomData<RP>,
}
impl<const N: usize, R, RP: ByteRepresentation<N>> ReadF<N, R, RP> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buf: [0; N],
            read_bytes: 0,
            _ph: std::marker::PhantomData,
        }
    }
}
impl<const N: usize, R, RP: ByteRepresentation<N> + Unpin> std::future::Future for ReadF<N, R, RP>
where
    R: AsyncRead + Unpin,
{
    type Output = std::io::Result<RP>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();

        match poll_read_until(&mut this.reader, cx, &mut this.buf, &mut this.read_bytes) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(_) => std::task::Poll::Ready(Ok(RP::from_le(this.buf))),
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
    fn new(reader: R) -> Self {
        Self {
            reader,
            first_byte: None,
            extra_bytes: [0u8; 8],
            extra_read_bytes: 0,
        }
    }

    fn new_ahead(first_byte: u8, reader: R) -> Self {
        Self {
            reader,
            first_byte: Some(first_byte),
            extra_bytes: [0u8; 8],
            extra_read_bytes: 0,
        }
    }
}
impl<R> std::future::Future for ReadLengthEncodedIntegerF<R>
where
    R: AsyncRead + Unpin,
{
    type Output = std::io::Result<u64>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();

        let first_byte = match this.first_byte {
            Some(v) => v,
            None => {
                let mut buf = [0u8; 1];
                let mut buf = tokio::io::ReadBuf::new(&mut buf);
                match Pin::new(&mut this.reader).poll_read(cx, &mut buf) {
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
                        this.first_byte = Some(filled[0]);
                        filled[0]
                    }
                }
            }
        };

        match first_byte {
            x if x < 251 => std::task::Poll::Ready(Ok(x as _)),
            0xfc => match poll_read_until(
                &mut this.reader,
                cx,
                &mut this.extra_bytes[..2],
                &mut this.extra_read_bytes,
            ) {
                std::task::Poll::Pending => std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(Ok(u16::from_le_bytes([
                    this.extra_bytes[0],
                    this.extra_bytes[1],
                ]) as _)),
            },
            0xfd => match poll_read_until(
                &mut this.reader,
                cx,
                &mut this.extra_bytes[..3],
                &mut this.extra_read_bytes,
            ) {
                std::task::Poll::Pending => std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(Ok(u32::from_le_bytes([
                    this.extra_bytes[0],
                    this.extra_bytes[1],
                    this.extra_bytes[2],
                    0x00,
                ]) as _)),
            },
            0xfe => match poll_read_until(
                &mut this.reader,
                cx,
                &mut this.extra_bytes,
                &mut this.extra_read_bytes,
            ) {
                std::task::Poll::Pending => std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(_) => {
                    std::task::Poll::Ready(Ok(u64::from_le_bytes(this.extra_bytes)))
                }
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
    fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Some([0u8; N]),
            read_bytes: 0,
        }
    }
}
impl<const N: usize, R: AsyncRead + Unpin> std::future::Future for ReadFixedBytesF<N, R> {
    type Output = std::io::Result<[u8; N]>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let buf = this.buf.as_mut().expect("Future was resolved");

        match poll_read_until(&mut this.reader, cx, buf, &mut this.read_bytes) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(_) => {
                std::task::Poll::Ready(Ok(unsafe { this.buf.take().unwrap_unchecked() }))
            }
        }
    }
}

pub struct ReadBytes<R> {
    reader: R,
    buf: Vec<u8>,
    read_bytes: usize,
}
impl<R> ReadBytes<R> {
    fn new(reader: R, required_bytes: usize) -> Self {
        let mut buf = Vec::with_capacity(required_bytes);
        unsafe { buf.set_len(required_bytes) };

        Self {
            reader,
            buf,
            read_bytes: 0,
        }
    }
}
impl<R: AsyncRead + Unpin> std::future::Future for ReadBytes<R> {
    type Output = std::io::Result<Vec<u8>>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();

        match poll_read_until(&mut this.reader, cx, &mut this.buf, &mut this.read_bytes) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(_) => {
                let r = std::mem::replace(&mut this.buf, Vec::new());
                this.read_bytes = 0;
                std::task::Poll::Ready(Ok(r))
            }
        }
    }
}

fn poll_read_until(
    mut reader: &mut (impl AsyncRead + Unpin + ?Sized),
    cx: &mut std::task::Context,
    buf: &mut [u8],
    filled_bytes: &mut usize,
) -> std::task::Poll<std::io::Result<()>> {
    while *filled_bytes < buf.len() {
        let mut buf = tokio::io::ReadBuf::new(&mut buf[*filled_bytes..]);
        match Pin::new(&mut reader).poll_read(cx, &mut buf) {
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
                *filled_bytes += filled.len();
            }
        }
    }

    std::task::Poll::Ready(Ok(()))
}

pub struct U8;
impl ProtocolFormatFragment for U8 {
    type Output = u8;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        Ok(b[0])
    }
}
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R> for U8 {
    type ReaderF = ReadF<1, &'r mut R, u8>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadF::new(reader)
    }
}

pub struct U16;
impl ProtocolFormatFragment for U16 {
    type Output = u16;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 2];
        reader.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }
}
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R> for U16 {
    type ReaderF = ReadF<2, &'r mut R, u16>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadF::new(reader)
    }
}

pub struct U32;
impl ProtocolFormatFragment for U32 {
    type Output = u32;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 4];
        reader.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
}
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R> for U32 {
    type ReaderF = ReadF<4, &'r mut R, u32>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadF::new(reader)
    }
}

pub struct LengthEncodedInteger;
impl ProtocolFormatFragment for LengthEncodedInteger {
    type Output = u64;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        super::LengthEncodedInteger::read_sync(reader).map(|x| x.0)
    }
}
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R>
    for LengthEncodedInteger
{
    type ReaderF = ReadLengthEncodedIntegerF<&'r mut R>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadLengthEncodedIntegerF::new(reader)
    }
}

pub struct LengthEncodedIntegerAhead(pub u8);
impl ProtocolFormatFragment for LengthEncodedIntegerAhead {
    type Output = u64;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        super::LengthEncodedInteger::read_ahead_sync(self.0, reader).map(|x| x.0)
    }
}
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R>
    for LengthEncodedIntegerAhead
{
    type ReaderF = ReadLengthEncodedIntegerF<&'r mut R>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadLengthEncodedIntegerF::new_ahead(self.0, reader)
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
impl<'r, const L: usize, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R>
    for FixedBytes<L>
{
    type ReaderF = ReadFixedBytesF<L, &'r mut R>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadFixedBytesF::new(reader)
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
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R> for Bytes {
    type ReaderF = ReadBytes<&'r mut R>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadBytes::new(reader, self.0)
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
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R>
    for NullTerminatedString
{
    type ReaderF = ReadNullTerminatedString<&'r mut R>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadNullTerminatedString::new(reader)
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
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R>
    for FixedLengthString
{
    type ReaderF = futures_util::future::MapOk<ReadBytes<&'r mut R>, fn(Vec<u8>) -> String>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadBytes::new(reader, self.0).map_ok(unsafe_recover_string_from_u8s)
    }
}
fn unsafe_recover_string_from_u8s(v: Vec<u8>) -> String {
    unsafe { String::from_utf8_unchecked(v) }
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
impl<'r, R> AsyncProtocolFormatFragment<'r, R> for LengthEncodedString
where
    R: AsyncRead + Unpin + ?Sized + 'r,
{
    // TODO: できればBoxつかいたくない
    type ReaderF = LocalBoxFuture<'r, std::io::Result<String>>;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        async move {
            let len = LengthEncodedInteger.read_format(reader).await?;
            FixedLengthString(len as _).read_format(reader).await
        }
        .boxed_local()
    }
}

pub struct PacketHeader;
impl ProtocolFormatFragment for PacketHeader {
    type Output = super::PacketHeader;

    #[inline]
    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        let mut ph = [0u8; 4];
        reader.read_exact(&mut ph)?;

        Ok(super::PacketHeader::from_fixed_bytes(ph))
    }
}
impl<'r, R: AsyncRead + Unpin + ?Sized + 'r> AsyncProtocolFormatFragment<'r, R> for PacketHeader {
    type ReaderF = futures_util::future::MapOk<
        ReadFixedBytesF<4, &'r mut R>,
        fn([u8; 4]) -> super::PacketHeader,
    >;

    #[inline]
    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        ReadFixedBytesF::new(reader).map_ok(super::PacketHeader::from_fixed_bytes)
    }
}

pub struct Mapped<PF, F>(pub PF, pub F);
impl<PF, F, R> ProtocolFormatFragment for Mapped<PF, F>
where
    PF: ProtocolFormatFragment,
    F: FnOnce(PF::Output) -> R,
{
    type Output = R;

    fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
        self.0.read_sync(reader).map(self.1)
    }
}
impl<'r, R, PF, F, Ret> AsyncProtocolFormatFragment<'r, R> for Mapped<PF, F>
where
    PF: AsyncProtocolFormatFragment<'r, R>,
    F: FnOnce(<PF as ProtocolFormatFragment>::Output) -> Ret,
    R: AsyncRead + Unpin + ?Sized + 'r,
    F: 'r,
{
    type ReaderF = futures_util::future::MapOk<PF::ReaderF, F>;

    fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
        self.0.read_format(reader).map_ok(self.1)
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
        impl<'r, Reader, $($a),+> AsyncProtocolFormatFragment<'r, Reader> for ($($a),+)
        where
            Reader: AsyncRead + Unpin + ?Sized + 'r,
            $($a: AsyncProtocolFormatFragment<'r, Reader>,)+
            $($a: 'static,)+
        {
            type ReaderF = LocalBoxFuture<'r, std::io::Result<($($a::Output),+)>>;

            #[inline]
            fn read_format(self, reader: &'r mut Reader) -> Self::ReaderF {
                async move {
                    #![allow(non_snake_case)]
                    $(let $a = self.$n.read_format(unsafe { std::ptr::read(&reader) }).await?;)+

                    Ok(($($a),+))
                }.boxed_local()
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

#[macro_export]
macro_rules! ReadAsync {
    ($reader: expr => { $($val: ident <- $fmt: expr),* }) => {
        #[allow(unused_parens)]
        let ($($val),*) = ($($fmt),*).read_format($reader).await?;
    }
}

#[macro_export]
macro_rules! DefFormatStruct {
    ($struct_name: ident($pf_name: ident) { $($val: ident($vty: ty) <- $fmt: expr),* }) => {
        struct $struct_name {
            $($val: $vty),*
        }

        DefProtocolFormat!($pf_name for $struct_name { $($val <- $fmt),* });
    }
}
#[macro_export]
macro_rules! DefProtocolFormat {
    ($pf_name: ident for $struct_name: ident { $($val: ident <- $fmt: expr),* }) => {
        struct $pf_name;
        impl ProtocolFormatFragment for $pf_name {
            type Output = $struct_name;

            #[inline]
            fn read_sync(self, reader: &mut (impl Read + ?Sized)) -> std::io::Result<Self::Output> {
                ReadSync!(reader => { $($val <- $fmt),* });

                Ok($struct_name { $($val),* })
            }
        }
        impl<'r, R> AsyncProtocolFormatFragment<'r, R> for $pf_name where R: tokio::io::AsyncRead + Unpin + ?Sized + 'r {
            type ReaderF = futures_util::future::LocalBoxFuture<'r, std::io::Result<$struct_name>>;

            #[inline]
            fn read_format(self, reader: &'r mut R) -> Self::ReaderF {
                use futures_util::future::FutureExt;

                async move {
                    ReadAsync!(reader => { $($val <- $fmt),* });

                    Ok($struct_name { $($val),* })
                }.boxed_local()
            }
        }
    }
}
