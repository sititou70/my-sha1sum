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
    fn assign_size(&mut self, block: &mut BlockBytes) {
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
            self.assign_size(&mut block);
            return Some(block);
        }

        let mut block: BlockBytes = [0; 64];
        let read_bytes = self.reader.read(&mut block).unwrap();
        self.size += read_bytes as u64;

        if read_bytes < 64 {
            // last read
            block[read_bytes] = 0x80;

            if read_bytes < 56 {
                self.assign_size(&mut block);
                self.done = true;
            } else {
                self.need_additional_block = true;
            }
        }

        Some(block)
    }
}

fn f(t: usize, b: Word, c: Word, d: Word) -> Word {
    match t {
        0..=19 => (b & c) | ((!b) & d),
        20..=39 => b ^ c ^ d,
        40..=59 => (b & c) | (b & d) | (c & d),
        60..=79 => b ^ c ^ d,
        _ => panic!("unexpected t: {}", t),
    }
}

fn k(t: usize) -> Word {
    match t {
        0..=19 => Word(0x5A827999),
        20..=39 => Word(0x6ED9EBA1),
        40..=59 => Word(0x8F1BBCDC),
        60..=79 => Word(0xCA62C1D6),
        _ => panic!("unexpected t: {}", t),
    }
}

pub fn sha1(reader: Box<dyn Read>) -> [Word; 5] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
        Word(0x67452301),
        Word(0xEFCDAB89),
        Word(0x98BADCFE),
        Word(0x10325476),
        Word(0xC3D2E1F0),
    );

    let pad = SHA1Pad::new(reader);
    for m in pad {
        let mut w: [Word; 80] = [Word(0); 80];
        for i in 0..=15 {
            let mi = i * 4;
            w[i] = Word(u32::from(
                u32::from(m[mi]) << 24
                    | u32::from(m[mi + 1]) << 16
                    | u32::from(m[mi + 2]) << 8
                    | u32::from(m[mi + 3]),
            ))
        }

        for i in 16..=79 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1)
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..=79 {
            let temp: Word = (a).rotate_left(5) + f(i, b, c, d) + e + w[i] + k(i);
            e = d;
            d = c;
            c = (b).rotate_left(30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    [h0, h1, h2, h3, h4]
}

pub fn format_hash(hash: [Word; 5]) -> String {
    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}",
        hash[0].0, hash[1].0, hash[2].0, hash[3].0, hash[4].0,
    )
}
