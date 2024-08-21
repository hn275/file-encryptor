use crate::crypto::{
    block::{Block, REDUCTION_POLYNOMIAL},
    BLOCK_SIZE,
};
use aes::{cipher::BlockEncrypt, Aes256};

#[derive(Clone, Debug)]
pub struct Tag {
    counter_0: Block,
    h: Block,
    state: Block,
    ciphertext_len: u64,
    aad_len: u64,
}

impl Tag {
    pub fn new(aes: &Aes256, iv: &Block) -> Self {
        let mut counter_0 = *iv;
        aes.encrypt_block(counter_0.bytes_mut().into());

        let mut h = Block::default();
        aes.encrypt_block(h.bytes_mut().into());

        let state = Block::default();

        let ciphertext_len = 0;

        let aad_len = 0;

        Self {
            counter_0,
            h,
            state,
            ciphertext_len,
            aad_len,
        }
    }

    pub fn update_state(&mut self, ciphertext: &Block) {
        self.ciphertext_len += BLOCK_SIZE as u64;
        self.compute(ciphertext);
    }

    pub fn authenticate(&mut self) -> &Block {
        let mut block = Block::default();

        block.bytes_mut()[..8].copy_from_slice(&self.ciphertext_len.to_be_bytes());
        block.bytes_mut()[8..].copy_from_slice(&self.aad_len.to_be_bytes());

        block.xor(&self.state);

        self.compute(&block);

        self.state.xor(&self.counter_0);

        &self.state
    }

    pub fn with_aad(&mut self, mut auth_data: &[u8]) {
        self.aad_len += auth_data.len() as u64;

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

    fn compute(&mut self, block: &Block) {
        self.state.xor(block);
        self.state = Self::galois_multiply(&self.state, &self.h);
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
}
