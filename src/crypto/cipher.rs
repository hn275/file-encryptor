use crate::crypto::{
    block::{Block, REDUCTION_POLYNOMIAL},
    Key, BLOCK_SIZE,
};
use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};

use super::pkcs7;

#[derive(Clone)]
#[allow(dead_code)]
pub struct Cipher {
    payload_len: usize,
    aad_len: usize,
    aes: Aes256,
    iv: Block,
    counter0: Block,
    pub tag: Tag,
}

impl Cipher {
    pub fn new(key: Key, iv: Block, aad: &Option<String>) -> Self {
        let aes = Aes256::new(&key.into());

        let mut counter0 = iv;
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

        let mut ctr = self.iv;
        self.encrypt_block(&mut ctr);

        block.xor(&ctr);
    }

    pub fn decrypt_block_inplace(&mut self, block: &mut Block) -> usize {
        self.iv.inc_counter();
        let mut ctr = self.iv;
        self.aes.encrypt_block((&mut ctr).into());
        block.xor(&ctr);

        let size = BLOCK_SIZE - pkcs7::unpad(block);
        self.payload_len += size;

        size
    }

    pub fn finalize(&mut self) -> &Block {
        let mut block = Block::default();
        block.bytes_mut()[..8].copy_from_slice(&self.payload_len.to_be_bytes());
        block.bytes_mut()[8..].copy_from_slice(&self.aad_len.to_be_bytes());
        block.xor(self.tag.block());
        self.tag.compute(&block);

        self.tag.tag_buf.xor(&self.tag.counter_0);

        &self.tag.tag_buf
    }

    fn encrypt_block(&self, block: &mut Block) {
        self.aes
            .encrypt_block(GenericArray::from_mut_slice(block.bytes_mut()));
    }
}

#[derive(Clone, Debug)]
pub struct Tag {
    counter_0: Block,
    h: Block,
    tag_buf: Block,
}

impl Tag {
    fn new(counter_0: Block, h: Block) -> Self {
        Self {
            counter_0,
            h,
            tag_buf: Block::default(),
        }
    }

    fn with_aad(&mut self, mut auth_data: &[u8]) {
        let mut eof = false;
        let mut block = Block::default();
        while !eof {
            let aad_block = if auth_data.len() < BLOCK_SIZE {
                block = Block::default();
                block.bytes_mut()[..auth_data.len()].copy_from_slice(auth_data.as_ref());
                eof = true;
                block
            } else {
                block
                    .bytes_mut()
                    .copy_from_slice(auth_data[..BLOCK_SIZE].as_ref());
                block
            };

            self.compute(&aad_block);

            if eof {
                break;
            }

            auth_data = &auth_data[BLOCK_SIZE..];
        }
    }

    fn block(&self) -> &Block {
        &self.tag_buf
    }

    pub fn compute(&mut self, block: &Block) {
        self.tag_buf.xor(block);
        self.tag_buf = Self::galois_multiply(&self.tag_buf, &self.h);
    }

    fn galois_multiply(x: &Block, y: &Block) -> Block {
        let mut z = Block::default();
        let mut v = *x;

        for i in 0..128 {
            if y.bitset(i) {
                z.xor(&v);
            }

            let msb_set = v.bitset(127);
            v.bin_shift_left();
            if msb_set {
                v.xor(&REDUCTION_POLYNOMIAL);
            }
        }

        z
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{BLOCK_SIZE, IV_SIZE};

    #[test]
    fn test_iv_new() {
        let iv = Block::new_iv();
        let buf: &[u8; BLOCK_SIZE] = (&iv).into();
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
        for ele in iv.bytes()[IV_SIZE..].iter() {
            assert_eq!(*ele, 0);
        }

        iv.inc_counter();
        assert_eq!(iv.bytes()[BLOCK_SIZE - 1], 1);

        iv.inc_counter();
        assert_eq!(iv.bytes()[BLOCK_SIZE - 1], 2);

        // bit wrapping
        iv.bytes_mut()[BLOCK_SIZE - 1] = 255;
        iv.inc_counter();
        assert_eq!(iv.bytes()[BLOCK_SIZE - 1], 0);
        assert_eq!(iv.bytes()[BLOCK_SIZE - 2], 1);

        // at max counter, wraps back to 0
        for ele in iv.bytes_mut()[IV_SIZE..].iter_mut() {
            *ele = 255;
        }

        iv.inc_counter();
        for ele in iv.bytes()[IV_SIZE..].iter() {
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

        let iv = Block::from([
            0x3A, 0x9F, 0xB4, 0x7E, 0x2D, 0x1C, 0xF8, 0x05, 0x9C, 0x7B, 0xA2, 0x6D,
        ]);

        let mut cipher = Cipher::new(key, iv, &None);

        let plaintext = Block::from([
            0x5A, 0x37, 0x71, 0x50, 0x39, 0x6B, 0x54, 0x62, 0x58, 0x31, 0x4C, 0x72, 0x34, 0x57,
            0x6D, 0x4A,
        ]);

        let ciphertext = Block::from([
            0xEE, 0x0D, 0x0A, 0x0D, 0xD1, 0x2D, 0xE2, 0x48, 0x2B, 0xFF, 0xE9, 0x82, 0x8F, 0x2F,
            0x9A, 0xB9,
        ]);

        let mut block = plaintext;

        cipher.encrypt_block_inplace(&mut block, BLOCK_SIZE);

        assert_ne!(block.bytes(), ciphertext.bytes());
    }

    #[test]
    fn test_cipher_encryption() {
        let key: Key = [
            0x6B, 0x38, 0x46, 0x7A, 0x58, 0x77, 0x32, 0x61, 0x4C, 0x70, 0x51, 0x39, 0x76, 0x4A,
            0x33, 0x6E, 0x47, 0x6D, 0x34, 0x52, 0x30, 0x79, 0x55, 0x63, 0x48, 0x74, 0x42, 0x73,
            0x56, 0x37, 0x64, 0x59,
        ];

        let iv = Block::from([
            0x3A, 0x9F, 0xB4, 0x7E, 0x2D, 0x1C, 0xF8, 0x05, 0x9C, 0x7B, 0xA2, 0x6D,
        ]);

        let mut cipher = Cipher::new(key, iv, &None);
        let mut cipher2 = cipher.clone();

        let plaintext = Block::from([
            0xEE, 0x0D, 0x0A, 0x0D, 0xD1, 0x2D, 0xE2, 0x48, 0x2B, 0xFF, 0xE9, 0x82, 0x8F, 0x2F,
            0x9A, 0xB9,
        ]);

        let mut block = plaintext;

        cipher.encrypt_block_inplace(&mut block, BLOCK_SIZE);
        cipher2.decrypt_block_inplace(&mut block);

        assert_eq!(block.bytes(), plaintext.bytes());
    }
}
