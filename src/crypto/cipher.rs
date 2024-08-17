use aes::{
    cipher::{
        generic_array::{self, GenericArray},
        BlockEncrypt, KeyInit,
    },
    Aes256,
};
use num::{BigUint, FromPrimitive};

pub const IV_SIZE: usize = 12;
pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

pub type Key = [u8; KEY_SIZE];

#[derive(Clone, Debug, Copy)]
pub struct Block(pub [u8; BLOCK_SIZE]);

impl<'a> From<&'a mut Block> for &'a mut GenericArray<u8, generic_array::typenum::U16> {
    fn from(value: &'a mut Block) -> Self {
        GenericArray::from_mut_slice(&mut value.0)
    }
}

impl From<&Block> for BigUint {
    fn from(value: &Block) -> Self {
        BigUint::from_bytes_be(&value.0)
    }
}

impl Default for Block {
    fn default() -> Self {
        Block(Default::default())
    }
}

impl Block {
    pub fn new_iv() -> Self {
        use rand::RngCore;

        let mut buf = Block::default();
        rand::thread_rng().fill_bytes(&mut buf.0[..IV_SIZE]);

        buf
    }

    pub fn iv_bytes(&self) -> &[u8] {
        &self.0[..IV_SIZE]
    }

    fn inc_counter(&mut self) {
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

    // for testing
    #[cfg(test)]
    fn from(bytes: &[u8; 12]) -> Self {
        let mut iv = Block::default();
        iv.0[..IV_SIZE].copy_from_slice(bytes);
        iv
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Cipher {
    payload_len: usize,
    aad_len: usize,
    aes: Aes256,
    iv: Block,
    counter0: Block,
    tag: Tag,
}

impl Cipher {
    pub fn new(key: Key, iv: Block, aad: &Option<String>) -> Self {
        let aes = Aes256::new(&key.into());

        let mut counter0 = iv.clone();
        aes.encrypt_block((&mut counter0).into());

        let mut h = Block::default();
        aes.encrypt_block((&mut h).into());

        let mut tag = Tag::new(counter0, h);
        if let Some(aad) = aad {
            tag.with_aad(aad.as_bytes());
        }

        let aad_len = if let Some(aad) = aad { aad.len() } else { 0 };
        let payload_len = 0;

        Self {
            payload_len,
            aad_len,
            aes,
            iv,
            counter0,
            tag,
        }
    }

    pub fn encrypt_block_inplace(&mut self, block: &mut Block, size: usize) {
        self.payload_len += size;
        self.iv.inc_counter();

        let mut ctr = self.iv.clone();
        self.aes.encrypt_block((&mut ctr).into());

        Self::xor(block, &ctr);

        self.tag.compute(block);
    }

    #[allow(dead_code)]
    pub fn decrypt_block_inplace(&mut self, block: &mut Block) {
        // self.payload_len += size as u64;
        self.tag.compute(block);
        self.iv.inc_counter();
        let mut ctr = self.iv.clone();
        self.aes.encrypt_block((&mut ctr).into());
        Self::xor(block, &ctr);
    }

    pub fn tag(&mut self) -> Block {
        let mut buf = Block::default();
        buf.0[..8].copy_from_slice(&self.payload_len.to_be_bytes());
        buf.0[8..].copy_from_slice(&self.aad_len.to_be_bytes());
        Self::xor(&mut buf, &self.tag.block());

        self.tag.compute(&buf);

        buf = self.tag.block();
        Self::xor(&mut buf, &self.tag.counter_0);

        buf
    }

    fn xor(left: &mut Block, right: &Block) {
        for i in 0..BLOCK_SIZE {
            left.0[i] ^= right.0[i]
        }
    }
}

#[derive(Clone, Debug)]
pub struct Tag {
    counter_0: Block,
    h: BigUint,
    tag: BigUint,
    reduction_poly: BigUint,
    msb_mask: BigUint,
    clamp_mask: BigUint,
}

impl Tag {
    fn new(counter_0: Block, h: Block) -> Self {
        let reduction_poly: BigUint = BigUint::from_u64(0b1110_0001).unwrap() << 120;

        let msb_mask: BigUint = num::BigUint::from(0b1000_0000u128) << 120;

        let clamp_mask = (BigUint::from(1u128) << 128) - 1u128;

        let h = BigUint::from(&h);
        let tag = BigUint::from(&Block::default());

        Self {
            counter_0,
            h,
            tag,
            reduction_poly,
            msb_mask,
            clamp_mask,
        }
    }

    fn with_aad(&mut self, mut auth_data: &[u8]) {
        let mut eof = false;
        let mut block = Block::default();
        while !eof {
            let aad_block = if auth_data.len() != BLOCK_SIZE {
                block = Block::default();
                block.0.copy_from_slice(auth_data.as_ref());
                eof = true;
                BigUint::from(&block)
            } else {
                block.0.copy_from_slice(auth_data[..BLOCK_SIZE].as_ref());
                BigUint::from(&block)
            };

            self.tag ^= &aad_block;
            self.tag = self.galois_multiply(&self.tag, &self.h);

            if eof {
                break;
            }

            auth_data = &auth_data[BLOCK_SIZE..];
        }
    }

    fn block(&self) -> Block {
        let mut block = Block::default();
        block.0.copy_from_slice(&self.tag.to_bytes_be());
        block
    }

    fn compute(&mut self, block: &Block) {
        self.tag ^= BigUint::from(block);
        self.tag = self.galois_multiply(&self.tag, &self.h);
    }

    fn galois_multiply(&self, x: &BigUint, y: &BigUint) -> num::BigUint {
        let mut z = num::BigUint::ZERO;
        let mut v = x.clone();

        let mut maskbin = num::BigUint::from_u8(1).expect("invalid value for BigUint");

        for _ in 0..128 {
            let bitset = y & &maskbin != num::BigUint::ZERO;
            if bitset {
                z ^= &v;
            }

            let msb_set = &v & &self.msb_mask != num::BigUint::ZERO;
            v <<= 1;
            if msb_set {
                v ^= &self.reduction_poly;
            }

            maskbin <<= 1;
        }

        z & &self.clamp_mask // clamp the result to 128 bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iv_new() {
        let iv = Block::new_iv();
        let buf = iv.0;
        assert_eq!(buf[IV_SIZE..].len(), 4);
        buf[IV_SIZE..]
            .iter()
            .for_each(|&byte| assert_eq!(byte, 0u8))
    }

    #[test]
    fn test_iv_bytes() {
        let bytes = Block::new_iv();
        let bytes = bytes.iv_bytes();
        assert_eq!(bytes.len(), IV_SIZE);

        let bytes2 = Block::new_iv();
        let bytes2 = bytes2.iv_bytes();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_iv_inc_counter() {
        let mut iv = Block::new_iv();
        for ele in iv.0[IV_SIZE..].iter() {
            assert_eq!(*ele, 0);
        }

        iv.inc_counter();
        assert_eq!(iv.0[BLOCK_SIZE - 1], 1);

        iv.inc_counter();
        assert_eq!(iv.0[BLOCK_SIZE - 1], 2);

        // bit wrapping
        iv.0[BLOCK_SIZE - 1] = 255;
        iv.inc_counter();
        assert_eq!(iv.0[BLOCK_SIZE - 1], 0);
        assert_eq!(iv.0[BLOCK_SIZE - 2], 1);

        // at max counter, wraps back to 0
        for ele in iv.0[IV_SIZE..].iter_mut() {
            *ele = 255;
        }

        iv.inc_counter();
        for ele in iv.0[IV_SIZE..].iter() {
            assert_eq!(*ele, 0);
        }
    }

    #[test]
    fn test_cipher_encrypt_in_place() {
        let key: Key = [
            0x6B, 0x38, 0x46, 0x7A, 0x58, 0x77, 0x32, 0x61, 0x4C, 0x70, 0x51, 0x39, 0x76, 0x4A,
            0x33, 0x6E, 0x47, 0x6D, 0x34, 0x52, 0x30, 0x79, 0x55, 0x63, 0x48, 0x74, 0x42, 0x73,
            0x56, 0x37, 0x64, 0x59,
        ];

        let iv: [u8; 12] = [
            0x3A, 0x9F, 0xB4, 0x7E, 0x2D, 0x1C, 0xF8, 0x05, 0x9C, 0x7B, 0xA2, 0x6D,
        ];

        let iv = Block::from(&iv);

        let mut cipher = Cipher::new(key, iv, &None);

        let plaintext = Block([
            0x5A, 0x37, 0x71, 0x50, 0x39, 0x6B, 0x54, 0x62, 0x58, 0x31, 0x4C, 0x72, 0x34, 0x57,
            0x6D, 0x4A,
        ]);

        let ciphertext = Block([
            0xEE, 0x0D, 0x0A, 0x0D, 0xD1, 0x2D, 0xE2, 0x48, 0x2B, 0xFF, 0xE9, 0x82, 0x8F, 0x2F,
            0x9A, 0xB9,
        ]);

        let mut block = plaintext;

        cipher.encrypt_block_inplace(&mut block, BLOCK_SIZE);

        assert_ne!(block.0, ciphertext.0);
    }

    #[test]
    fn test_cipher_encryption() {
        let key: Key = [
            0x6B, 0x38, 0x46, 0x7A, 0x58, 0x77, 0x32, 0x61, 0x4C, 0x70, 0x51, 0x39, 0x76, 0x4A,
            0x33, 0x6E, 0x47, 0x6D, 0x34, 0x52, 0x30, 0x79, 0x55, 0x63, 0x48, 0x74, 0x42, 0x73,
            0x56, 0x37, 0x64, 0x59,
        ];

        let iv: [u8; 12] = [
            0x3A, 0x9F, 0xB4, 0x7E, 0x2D, 0x1C, 0xF8, 0x05, 0x9C, 0x7B, 0xA2, 0x6D,
        ];

        let iv = Block::from(&iv);
        let mut cipher = Cipher::new(key, iv, &None);
        let mut cipher2 = cipher.clone();

        let plaintext = Block([
            0xEE, 0x0D, 0x0A, 0x0D, 0xD1, 0x2D, 0xE2, 0x48, 0x2B, 0xFF, 0xE9, 0x82, 0x8F, 0x2F,
            0x9A, 0xB9,
        ]);

        let mut block = plaintext;

        cipher.encrypt_block_inplace(&mut block, BLOCK_SIZE);
        cipher2.decrypt_block_inplace(&mut block);

        assert_eq!(block.0, plaintext.0);
    }
}
