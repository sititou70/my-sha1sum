#![allow(arithmetic_overflow)]

use std::{io::*, ops, panic};

#[derive(Clone, Copy, Debug)]
pub struct Word(u32);
impl Word {
    pub fn rotate_left(self, n: u32) -> Self {
        Self(self.0.rotate_left(n))
    }

    pub fn add(self, y: Self) -> Self {
        let ans = (u64::from(self.0) + u64::from(y.0)) % 0x100000000;
        match u32::try_from(ans) {
            Ok(u) => Word(u),
            Err(e) => panic!("add error: {}", e),
        }
    }
}
impl ops::Add for Word {
    type Output = Word;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}
impl ops::AddAssign for Word {
    fn add_assign(&mut self, other: Self) {
        *self = self.add(other);
    }
}
impl ops::BitAnd for Word {
    type Output = Word;

    fn bitand(self, rhs: Self) -> Self::Output {
        Word(self.0 & rhs.0)
    }
}
impl ops::BitOr for Word {
    type Output = Word;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
impl ops::BitXor for Word {
    type Output = Word;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}
impl ops::Not for Word {
    type Output = Word;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

type BlockBytes = [u8; 64];

struct SHA1Pad {
    reader: Box<dyn Read>,
    size: u64,
    need_additional_block: bool,
    done: bool,
}
impl SHA1Pad {
    pub fn new(reader: Box<dyn Read>) -> Self {
        Self {
            reader: reader,
            size: 0,
            need_additional_block: false,
            done: false,
        }
    }
    fn assignSize(&mut self, block: &mut BlockBytes) {
        for i in 56..=63 {
            block[i] = ((self.size * 8) >> (63 - i) * 8) as u8;
        }
    }
}
impl Iterator for SHA1Pad {
    type Item = BlockBytes;

    fn next(&mut self) -> Option<BlockBytes> {
        if self.done {
            return None;
        }
        if self.need_additional_block {
            self.done = true;
            let mut block: BlockBytes = [0; 64];
            self.assignSize(&mut block);
            return Some(block);
        }

        let mut block: BlockBytes = [0; 64];
        let read_bytes = self.reader.read(&mut block).unwrap();
        self.size += read_bytes as u64;

        if read_bytes < 64 {
            // last read
            block[read_bytes] = 0x80;

            if read_bytes < 56 {
                self.assignSize(&mut block);
                self.done = true;
                return Some(block);
            } else {
                self.need_additional_block = true;
                return Some(block);
            }
        }

        Some(block)
    }
}

fn f(t: usize, B: Word, C: Word, D: Word) -> Word {
    match t {
        0..=19 => (B & C) | ((!B) & D),
        20..=39 => B ^ C ^ D,
        40..=59 => (B & C) | (B & D) | (C & D),
        60..=79 => B ^ C ^ D,
        _ => panic!("unexpected t: {}", t),
    }
}

fn K(t: usize) -> Word {
    match t {
        0..=19 => Word(0x5A827999),
        20..=39 => Word(0x6ED9EBA1),
        40..=59 => Word(0x8F1BBCDC),
        60..=79 => Word(0xCA62C1D6),
        _ => panic!("unexpected t: {}", t),
    }
}

pub fn sha1(reader: Box<dyn Read>) -> [Word; 5] {
    let (mut H0, mut H1, mut H2, mut H3, mut H4) = (
        Word(0x67452301),
        Word(0xEFCDAB89),
        Word(0x98BADCFE),
        Word(0x10325476),
        Word(0xC3D2E1F0),
    );

    let pad = SHA1Pad::new(reader);
    for m in pad {
        let mut W: [Word; 80] = [Word(0); 80];
        for i in 0..=15 {
            let mi = i * 4;
            W[i] = Word(u32::from(
                u32::from(m[mi]) << 24
                    | u32::from(m[mi + 1]) << 16
                    | u32::from(m[mi + 2]) << 8
                    | u32::from(m[mi + 3]),
            ))
        }

        for i in 16..=79 {
            W[i] = (W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]).rotate_left(1)
        }

        let (mut A, mut B, mut C, mut D, mut E) = (H0, H1, H2, H3, H4);
        for i in 0..=79 {
            let temp: Word = (A).rotate_left(5) + f(i, B, C, D) + E + W[i] + K(i);
            E = D;
            D = C;
            C = (B).rotate_left(30);
            B = A;
            A = temp;
        }

        H0 += A;
        H1 += B;
        H2 += C;
        H3 += D;
        H4 += E;
    }

    [H0, H1, H2, H3, H4]
}

pub fn printHash(hash: [Word; 5]) {
    print!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}",
        hash[0].0, hash[1].0, hash[2].0, hash[3].0, hash[4].0,
    )
}
