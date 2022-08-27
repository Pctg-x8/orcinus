//! Protocol Serialization Format Fragments

use std::io::Read;

use futures_util::{future::BoxFuture, FutureExt, TryFutureExt};
use tokio::io::AsyncRead;

use crate::async_utils::{ReadBytesF, ReadF, ReadFixedBytesF, ReadLengthEncodedIntegerF, ReadNullTerminatedStringF};

/// A fragment of Protocol Format
///
/// Most protocols are constructed as group of Format Fragments.
/// This allows unified implementation of readers both synchronous and asynchronous.
pub trait ProtocolFormatFragment {
    /// Output value type of the format
    type Output;

    /// Reads a value
    fn read_sync(self, reader: impl Read) -> std::io::Result<Self::Output>;

    /// `(<$>)` operator
    #[inline]
    fn map<F, R>(self, mapper: F) -> Mapped<Self, F>
    where
        Self: Sized,
        F: FnOnce(Self::Output) -> R,
    {
        Mapped(self, mapper)
    }

    /// Asserts the value using [`assert_eq!`]
    #[inline]
    fn assert_eq(self, right: Self::Output) -> AssertEq<Self>
    where
        Self: Sized,
        Self::Output: std::fmt::Debug + Eq,
    {
        AssertEq(self, right)
    }
}

/// Asynchronous reader implementation for Format Fragments
pub trait AsyncProtocolFormatFragment<'r, R: 'r + Send>: ProtocolFormatFragment {
    /// Future type of reading the format
    type ReaderF: std::future::Future<Output = std::io::Result<Self::Output>> + Send + 'r;

    /// Read a value asynchronously
    fn read_format(self, reader: R) -> Self::ReaderF;
}

/// u8(byte) format
pub struct U8;
impl ProtocolFormatFragment for U8 {
    type Output = u8;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        Ok(b[0])
    }
}
impl<'r, R> AsyncProtocolFormatFragment<'r, R> for U8
where
    R: AsyncRead + Send + Unpin + 'r,
{
    type ReaderF = ReadF<1, R, u8>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadF::new(reader)
    }
}

// u16(unsigned short) format
pub struct U16;
impl ProtocolFormatFragment for U16 {
    type Output = u16;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 2];
        reader.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }
}
impl<'r, R> AsyncProtocolFormatFragment<'r, R> for U16
where
    R: AsyncRead + Send + Unpin + 'r,
{
    type ReaderF = ReadF<2, R, u16>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadF::new(reader)
    }
}

/// u32(unsigned int) format
pub struct U32;
impl ProtocolFormatFragment for U32 {
    type Output = u32;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 4];
        reader.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
}
impl<'r, R> AsyncProtocolFormatFragment<'r, R> for U32
where
    R: AsyncRead + Send + Unpin + 'r,
{
    type ReaderF = ReadF<4, R, u32>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadF::new(reader)
    }
}

/// Length-encoded integer format
pub struct LengthEncodedInteger;
impl ProtocolFormatFragment for LengthEncodedInteger {
    type Output = u64;

    #[inline]
    fn read_sync(self, reader: impl Read) -> std::io::Result<Self::Output> {
        super::LengthEncodedInteger::read_sync(reader).map(|x| x.0)
    }
}
impl<'r, R> AsyncProtocolFormatFragment<'r, R> for LengthEncodedInteger
where
    R: AsyncRead + Send + Unpin + 'r,
{
    type ReaderF = ReadLengthEncodedIntegerF<R>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadLengthEncodedIntegerF::new(reader)
    }
}

/// Length-encoded integer format with prefetched first byte
pub struct LengthEncodedIntegerAhead(pub u8);
impl ProtocolFormatFragment for LengthEncodedIntegerAhead {
    type Output = u64;

    #[inline]
    fn read_sync(self, reader: impl Read) -> std::io::Result<Self::Output> {
        super::LengthEncodedInteger::read_ahead_sync(self.0, reader).map(|x| x.0)
    }
}
impl<'r, R> AsyncProtocolFormatFragment<'r, R> for LengthEncodedIntegerAhead
where
    R: AsyncRead + Send + Unpin + 'r,
{
    type ReaderF = ReadLengthEncodedIntegerF<R>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadLengthEncodedIntegerF::new_ahead(self.0, reader)
    }
}

/// Compile-time determined fixed length byte string format
pub struct FixedBytes<const L: usize>;
impl<const L: usize> ProtocolFormatFragment for FixedBytes<L> {
    type Output = [u8; L];

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let mut b = [0u8; L];
        reader.read_exact(&mut b)?;
        Ok(b)
    }
}
impl<'r, const L: usize, R: 'r + AsyncRead + Send + Unpin> AsyncProtocolFormatFragment<'r, R> for FixedBytes<L> {
    type ReaderF = ReadFixedBytesF<L, R>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadFixedBytesF::new(reader)
    }
}

/// Runtime determined fixed length byte string format
pub struct Bytes(pub usize);
impl ProtocolFormatFragment for Bytes {
    type Output = Vec<u8>;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let mut b = Vec::with_capacity(self.0);
        unsafe {
            b.set_len(self.0);
        }
        reader.read_exact(&mut b)?;
        Ok(b)
    }
}
impl<'r, R: 'r + AsyncRead + Send + Unpin> AsyncProtocolFormatFragment<'r, R> for Bytes {
    type ReaderF = ReadBytesF<R>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadBytesF::new(reader, self.0)
    }
}

/// Runtime determined fixed length byte string format with prefetched first byte
pub struct BytesAhead(pub u8, pub usize);
impl ProtocolFormatFragment for BytesAhead {
    type Output = Vec<u8>;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let mut b = Vec::with_capacity(self.1);
        unsafe {
            b.set_len(self.1);
        }
        b[0] = self.0;
        reader.read_exact(&mut b[1..])?;
        Ok(b)
    }
}
impl<'r, R: 'r + AsyncRead + Send + Unpin> AsyncProtocolFormatFragment<'r, R> for BytesAhead {
    type ReaderF = ReadBytesF<R>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadBytesF::new_ahead(reader, self.0, self.1)
    }
}

/// Null terminated string format
pub struct NullTerminatedString;
impl ProtocolFormatFragment for NullTerminatedString {
    type Output = String;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
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
impl<'r, R: 'r + AsyncRead + Send + Unpin> AsyncProtocolFormatFragment<'r, R> for NullTerminatedString {
    type ReaderF = ReadNullTerminatedStringF<R>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadNullTerminatedStringF::new(reader)
    }
}

/// Runtime determined fixed length string format
pub struct FixedLengthString(pub usize);
impl ProtocolFormatFragment for FixedLengthString {
    type Output = String;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let mut b = Vec::with_capacity(self.0);
        unsafe {
            b.set_len(self.0);
        }
        reader.read_exact(&mut b)?;
        Ok(unsafe { String::from_utf8_unchecked(b) })
    }
}
impl<'r, R: 'r + AsyncRead + Send + Unpin> AsyncProtocolFormatFragment<'r, R> for FixedLengthString {
    type ReaderF = futures_util::future::MapOk<ReadBytesF<R>, fn(Vec<u8>) -> String>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadBytesF::new(reader, self.0).map_ok(unsafe_recover_string_from_u8s)
    }
}
fn unsafe_recover_string_from_u8s(v: Vec<u8>) -> String {
    unsafe { String::from_utf8_unchecked(v) }
}

/// Variable string format preceded with Length-Encoded integer as its length
pub struct LengthEncodedString;
impl ProtocolFormatFragment for LengthEncodedString {
    type Output = String;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let len = LengthEncodedInteger.read_sync(&mut reader)?;
        FixedLengthString(len as _).read_sync(reader)
    }
}
impl<'r, R: 'r + AsyncRead + Send + Unpin> AsyncProtocolFormatFragment<'r, R> for LengthEncodedString {
    // TODO: できればBoxつかいたくない
    type ReaderF = BoxFuture<'r, std::io::Result<String>>;

    #[inline]
    fn read_format(self, mut reader: R) -> Self::ReaderF {
        async move {
            let len = LengthEncodedInteger.read_format(&mut reader).await?;
            FixedLengthString(len as _).read_format(&mut reader).await
        }
        .boxed()
    }
}

/// Packet header format
pub struct PacketHeader;
impl ProtocolFormatFragment for PacketHeader {
    type Output = super::PacketHeader;

    #[inline]
    fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
        let mut ph = [0u8; 4];
        reader.read_exact(&mut ph)?;

        Ok(super::PacketHeader::from_fixed_bytes(ph))
    }
}
impl<'r, R: 'r + AsyncRead + Send + Unpin> AsyncProtocolFormatFragment<'r, R> for PacketHeader {
    type ReaderF = futures_util::future::MapOk<ReadFixedBytesF<4, R>, fn([u8; 4]) -> super::PacketHeader>;

    #[inline]
    fn read_format(self, reader: R) -> Self::ReaderF {
        ReadFixedBytesF::new(reader).map_ok(super::PacketHeader::from_fixed_bytes)
    }
}

/// Mapped format; Applies conversion after reading the value
pub struct Mapped<PF, F>(pub PF, pub F);
impl<PF, F, R> ProtocolFormatFragment for Mapped<PF, F>
where
    PF: ProtocolFormatFragment,
    F: FnOnce(PF::Output) -> R,
{
    type Output = R;

    fn read_sync(self, reader: impl Read) -> std::io::Result<Self::Output> {
        self.0.read_sync(reader).map(self.1)
    }
}
impl<'r, R: 'r, PF, F, Ret: 'static> AsyncProtocolFormatFragment<'r, R> for Mapped<PF, F>
where
    PF: AsyncProtocolFormatFragment<'r, R>,
    PF::Output: 'static,
    F: FnOnce(<PF as ProtocolFormatFragment>::Output) -> Ret + Send + 'r,
    R: AsyncRead + Send,
{
    type ReaderF = futures_util::future::MapOk<PF::ReaderF, F>;

    fn read_format(self, reader: R) -> Self::ReaderF {
        self.0.read_format(reader).map_ok(self.1)
    }
}

/// AssertEq format; Assertion the value by [`assert_eq!`] after reading
pub struct AssertEq<PF: ProtocolFormatFragment>(PF, PF::Output);
impl<PF> ProtocolFormatFragment for AssertEq<PF>
where
    PF: ProtocolFormatFragment,
    PF::Output: std::fmt::Debug + Eq,
{
    type Output = PF::Output;

    fn read_sync(self, reader: impl Read) -> std::io::Result<Self::Output> {
        let v = self.0.read_sync(reader)?;
        assert_eq!(v, self.1);
        Ok(v)
    }
}
impl<'r, R: 'r, PF> AsyncProtocolFormatFragment<'r, R> for AssertEq<PF>
where
    PF: AsyncProtocolFormatFragment<'r, R> + Send + 'r,
    R: AsyncRead + Send + Unpin,
    PF::Output: std::fmt::Debug + Eq + Send + 'r,
{
    type ReaderF = BoxFuture<'r, std::io::Result<PF::Output>>;

    fn read_format(self, reader: R) -> Self::ReaderF {
        async move {
            let v = self.0.read_format(reader).await?;
            assert_eq!(v, self.1);
            Ok(v)
        }
        .boxed()
    }
}

macro_rules! ProtocolFormatFragmentGroup {
    ($($a: ident: $n: tt),+) => {
        impl<$($a),+> ProtocolFormatFragment for ($($a),+) where $($a: ProtocolFormatFragment),+ {
            type Output = ($($a::Output),+);

            #[inline]
            fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
                #![allow(non_snake_case)]
                $(let $a = self.$n.read_sync(&mut reader)?;)+

                Ok(($($a),+))
            }
        }
        // 実装できないやつ
        /*impl<'r, Reader, $($a),+> AsyncProtocolFormatFragment<'r, Reader> for ($($a),+)
        where
            Reader: AsyncRead + Send + Unpin + ?Sized + 'r,
            $($a: AsyncProtocolFormatFragment<'r, Reader>,)+
            $($a::Output: Send + 'static,)+
            $($a: Send + 'static,)+
        {
            type ReaderF = BoxFuture<'r, std::io::Result<($($a::Output),+)>>;

            #[inline]
            fn read_format(self, reader: &'r mut Reader) -> Self::ReaderF {
                async move {
                    #![allow(non_snake_case)]
                    $crate::ReadAsync!(reader => { $($a <- self.$n),* });

                    Ok(($($a),+))
                }.boxed()
            }
        }*/
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

/// Read multiple values synchronously
///
/// ## Example
///
/// ```
/// ReadSync!(reader => {
///     hdr <- PacketHeader,
///     value1 <- U8,
///     value2 <- U16
/// });
/// ```
#[macro_export]
macro_rules! ReadSync {
    ($reader: expr => { $($val: ident <- $fmt: expr),* }) => {
        $(
            let $val = $fmt.read_sync(&mut $reader)?;
        )*
    }
}

/// Read multiple values asynchronously
///
/// ## Example
///
/// ```
/// ReadAsync!(reader => {
///     hdr <- PacketHeader,
///     value1 <- U8,
///     value2 <- U16
/// });
/// ```
#[macro_export]
macro_rules! ReadAsync {
    ($reader: expr => { $($val: ident <- $fmt: expr),* }) => {
        $(
            let $val = $fmt.read_format(&mut $reader).await?;
        )*
    }
}

/// Defines Format Fragment structure
///
/// ## Example
///
/// ```
/// DefFormatStruct!(pub RawPacketAStruct(RawPacketAStructFormat) {
///     hdr(PacketHeader) <- format::PacketHeader,
///     v1(u8) <- format::U8,
///     v2([u8; 4]) <- format::FixedBytes::<4>
/// });
/// ```
#[macro_export]
macro_rules! DefFormatStruct {
    ($struct_name: ident($pf_name: ident) { $($val: ident($vty: ty) <- $fmt: expr),* }) => {
        struct $struct_name {
            $($val: $vty),*
        }

        $crate::DefProtocolFormat!($pf_name for $struct_name { $($val <- $fmt),* });
    };
    ($vis: vis $struct_name: ident($pf_name: ident) { $($val: ident($vty: ty) <- $fmt: expr),* }) => {
        $vis struct $struct_name {
            $($val: $vty),*
        }

        $crate::DefProtocolFormat!($vis $pf_name for $struct_name { $($val <- $fmt),* });
    }
}
/// Defines Format Fragment implementation for a structure
#[macro_export]
macro_rules! DefProtocolFormat {
    ($pf_name: ident for $struct_name: ident { $($val: ident <- $fmt: expr),* }) => {
        struct $pf_name;
        impl $crate::mysql::protos::format::ProtocolFormatFragment for $pf_name {
            type Output = $struct_name;

            #[inline]
            fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
                $crate::ReadSync!(reader => { $($val <- $fmt),* });

                Ok($struct_name { $($val),* })
            }
        }
        impl<'r, R: 'r> $crate::mysql::protos::format::AsyncProtocolFormatFragment<'r, R> for $pf_name
        where
            R: tokio::io::AsyncRead + Send + Unpin
        {
            type ReaderF = futures_util::future::BoxFuture<'r, std::io::Result<$struct_name>>;

            #[inline]
            fn read_format(self, mut reader: R) -> Self::ReaderF {
                use futures_util::future::FutureExt;

                async move {
                    $crate::ReadAsync!(reader => { $($val <- $fmt),* });

                    Ok($struct_name { $($val),* })
                }.boxed()
            }
        }
    };
    ($vis: vis $pf_name: ident for $struct_name: ident { $($val: ident <- $fmt: expr),* }) => {
        $vis struct $pf_name;
        impl $crate::mysql::protos::format::ProtocolFormatFragment for $pf_name {
            type Output = $struct_name;

            #[inline]
            fn read_sync(self, mut reader: impl Read) -> std::io::Result<Self::Output> {
                $crate::ReadSync!(reader => { $($val <- $fmt),* });

                Ok($struct_name { $($val),* })
            }
        }
        impl<'r, R: 'r> $crate::mysql::protos::format::AsyncProtocolFormatFragment<'r, R> for $pf_name
        where
            R: tokio::io::AsyncRead + Send + Unpin
        {
            type ReaderF = futures_util::future::BoxFuture<'r, std::io::Result<$struct_name>>;

            #[inline]
            fn read_format(self, mut reader: R) -> Self::ReaderF {
                use futures_util::future::FutureExt;

                async move {
                    $crate::ReadAsync!(reader => { $($val <- $fmt),* });

                    Ok($struct_name { $($val),* })
                }.boxed()
            }
        }
    }
}
