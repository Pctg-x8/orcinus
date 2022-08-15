//! Protocol Serialization Format Fragments

use std::io::Read;

pub trait ProtocolFormatFragment {
    type Output;

    fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output>;
}

pub struct U8;
impl ProtocolFormatFragment for U8 {
    type Output = u8;

    #[inline]
    fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        Ok(b[0])
    }
}

pub struct U16;
impl ProtocolFormatFragment for U16 {
    type Output = u16;

    #[inline]
    fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 2];
        reader.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }
}

pub struct U32;
impl ProtocolFormatFragment for U32 {
    type Output = u32;

    #[inline]
    fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output> {
        let mut b = [0u8; 4];
        reader.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
}

pub struct FixedBytes<const L: usize>;
impl<const L: usize> ProtocolFormatFragment for FixedBytes<L> {
    type Output = [u8; L];

    #[inline]
    fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output> {
        let mut b = [0u8; L];
        reader.read_exact(&mut b)?;
        Ok(b)
    }
}

pub struct Bytes(pub usize);
impl ProtocolFormatFragment for Bytes {
    type Output = Vec<u8>;

    #[inline]
    fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output> {
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
    fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output> {
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

pub struct PacketHeader;
impl ProtocolFormatFragment for PacketHeader {
    type Output = super::PacketHeader;

    #[inline]
    fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output> {
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
            fn read_sync(self, reader: &mut impl Read) -> std::io::Result<Self::Output> {
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
