use aes::cipher::generic_array::{typenum::U16, GenericArray};

use crate::crypto::{BLOCK_SIZE, IV_SIZE};

#[derive(Debug, Clone, Copy, Default)]
pub struct Block([u8; BLOCK_SIZE]);

pub const REDUCTION_POLYNOMIAL: Block =
    Block([0b1110_0001, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

impl<'a> From<&'a mut Block> for &'a mut GenericArray<u8, U16> {
    fn from(value: &'a mut Block) -> Self {
        GenericArray::from_mut_slice(&mut value.0)
    }
}

impl<'a> From<&'a Block> for &'a [u8; BLOCK_SIZE] {
    fn from(value: &'a Block) -> Self {
        &value.0
    }
}

#[cfg(test)]
impl From<[u8; BLOCK_SIZE]> for Block {
    fn from(buf: [u8; BLOCK_SIZE]) -> Self {
        Self(buf)
    }
}

#[cfg(test)]
impl From<[u8; IV_SIZE]> for Block {
    fn from(iv: [u8; IV_SIZE]) -> Self {
        let mut buf = [0_u8; BLOCK_SIZE];
        buf[..IV_SIZE].copy_from_slice(iv.as_ref());
        Self(buf)
    }
}

impl Block {
    pub fn new_iv() -> Self {
        use rand::RngCore;

        let mut buf = Block::default();
        rand::thread_rng().fill_bytes(&mut buf.0[..IV_SIZE]);

        buf
    }

    pub fn bytes_mut(&mut self) -> &mut [u8; BLOCK_SIZE] {
        &mut self.0
    }

    pub fn bytes(&self) -> &[u8; BLOCK_SIZE] {
        &self.0
    }

    pub fn iv_bytes(&self) -> &[u8] {
        &self.0[..IV_SIZE]
    }

    pub fn inc_counter(&mut self) {
        let ctr_bytes = self.0[IV_SIZE..].as_mut();
        let ctr_bound = ctr_bytes.len();
        for i in 0..ctr_bound {
            let byte = &mut ctr_bytes[ctr_bound - i - 1];
            if *byte == 255 {
                *byte = 0;
                continue;
            }
            *byte += 1;
            break;
        }
    }

    pub fn xor(&mut self, other: &Block) {
        for i in 0..BLOCK_SIZE {
            self.0[i] ^= &other.0[i]
        }
    }

    pub fn bin_shift_left(&mut self) {
        let bytes = self.bytes_mut();
        let mut carry_bit = 0_u8;

        bytes.iter_mut().rev().for_each(|byte| {
            let new_carry = *byte & 0b1000_0000;
            *byte <<= 1;
            *byte |= carry_bit >> 7;
            carry_bit = new_carry;
        });
    }

    pub fn bitset(&self, bit: u8) -> bool {
        let byte_blocks = bit / 8;
        let byte_blocks = BLOCK_SIZE - 1 - (byte_blocks as usize);

        let bit_mask = (1 << (bit % 8)) as u8;
        self.0[byte_blocks] & bit_mask != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn block_bin_left_shift() {
        let mut bytes = Block::from([
            0b1101_0110,
            0b0010_1101,
            0b1011_1000,
            0b0101_0011,
            0b0110_1110,
            0b1001_0111,
            0b1110_0001,
            0b0001_1100,
            0b0111_1010,
            0b1000_1001,
            0b1010_0110,
            0b0100_1111,
            0b1100_1010,
            0b0011_0001,
            0b1001_1111,
            0b0110_0110,
        ]);

        let expected: [u8; 16] = [
            0b1010_1100,
            0b0101_1011,
            0b0111_0000,
            0b1010_0110,
            0b1101_1101,
            0b0010_1111,
            0b1100_0010,
            0b0011_1000,
            0b1111_0101,
            0b0001_0011,
            0b0100_1100,
            0b1001_1111,
            0b1001_0100,
            0b0110_0011,
            0b0011_1110,
            0b1100_1100,
        ];

        bytes.bin_shift_left();
        for (i, byte) in expected.iter().enumerate() {
            assert_eq!(bytes.0[i], *byte);
        }
    }

    #[test]
    fn bitset_in_blocks() {
        let mut buf = Block::default();
        buf.0[BLOCK_SIZE - 1] = 1;

        for i in 0..128 {
            assert!(buf.bitset(i));
            buf.bin_shift_left();
        }
    }

    #[test]
    fn bytes_xor() {
        let mut rng = rand::thread_rng();

        let mut left = Block::default();
        left.bytes_mut()
            .iter_mut()
            .for_each(|byte| *byte = rng.gen());

        let mut right = Block::default();
        right
            .bytes_mut()
            .iter_mut()
            .for_each(|byte| *byte = rng.gen());

        let mut data = left;
        data.xor(&right);
        for i in 0..BLOCK_SIZE {
            let expected = left.0[i] ^ right.0[i];
            assert_eq!(data.0[i], expected);
        }
    }
}
