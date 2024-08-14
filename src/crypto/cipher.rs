use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};

pub const IV_SIZE: usize = 12;
pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

pub type Key = [u8; KEY_SIZE];
pub type Block = [u8; BLOCK_SIZE];

#[derive(Clone)]
pub struct IV(Block);

impl IV {
    pub fn new() -> Self {
        use rand::RngCore;

        let mut buf = Block::default();
        rand::thread_rng().fill_bytes(&mut buf[..IV_SIZE]);

        IV(buf)
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
        iv[..IV_SIZE].copy_from_slice(bytes);
        Self(iv)
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Cipher<'a> {
    aes: Aes256,
    iv: IV,
    aad: Option<&'a [u8]>,
    counter0: Block,
}

impl<'a> Cipher<'a> {
    pub fn new(key: Key, iv: IV, aad: Option<&'a [u8]>) -> Self {
        let aes = Aes256::new(&key.into());

        let mut counter0 = Block::default();
        let buf = GenericArray::from_mut_slice(&mut counter0);
        aes.encrypt_block(buf);

        Self {
            aes,
            iv,
            aad,
            counter0,
        }
    }

    pub fn encrypt_block_inplace(&mut self, block: &mut Block) {
        self.iv.inc_counter();
        let mut ctr = GenericArray::from(self.iv.0);
        self.aes.encrypt_block(&mut ctr);
        Self::xor(block, ctr.as_ref());
        self.galois_mult(block);
    }

    #[allow(dead_code)]
    pub fn decrypt_block_inplace(&mut self, block: &mut Block) {
        self.galois_mult(block);
        self.iv.inc_counter();
        let mut ctr = GenericArray::from(self.iv.0);
        self.aes.encrypt_block(&mut ctr);
        Self::xor(block, ctr.as_ref());
    }

    pub fn tag(&mut self) -> Block {
        Default::default()
    }

    fn galois_mult(&mut self, _block: &Block) {}

    fn xor(left: &mut Block, right: &Block) {
        for i in 0..BLOCK_SIZE {
            left[i] ^= right[i]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iv_new() {
        let iv = IV::new();
        let buf = iv.0;
        assert_eq!(buf[IV_SIZE..].len(), 4);
        buf[IV_SIZE..]
            .iter()
            .for_each(|&byte| assert_eq!(byte, 0u8))
    }

    #[test]
    fn test_iv_bytes() {
        let bytes = IV::new();
        let bytes = bytes.iv_bytes();
        assert_eq!(bytes.len(), IV_SIZE);

        let bytes2 = IV::new();
        let bytes2 = bytes2.iv_bytes();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_iv_inc_counter() {
        let mut iv = IV::new();
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

        let iv = IV::from(&iv);

        let mut cipher = Cipher::new(key, iv, None);

        let plaintext: Block = [
            0x5A, 0x37, 0x71, 0x50, 0x39, 0x6B, 0x54, 0x62, 0x58, 0x31, 0x4C, 0x72, 0x34, 0x57,
            0x6D, 0x4A,
        ];

        let ciphertext: Block = [
            0xEE, 0x0D, 0x0A, 0x0D, 0xD1, 0x2D, 0xE2, 0x48, 0x2B, 0xFF, 0xE9, 0x82, 0x8F, 0x2F,
            0x9A, 0xB9,
        ];

        let mut block = plaintext;

        cipher.encrypt_block_inplace(&mut block);

        assert_ne!(block, ciphertext);
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

        let iv = IV::from(&iv);
        let mut cipher = Cipher::new(key, iv, None);
        let mut cipher2 = cipher.clone();

        let plaintext: Block = [
            0xEE, 0x0D, 0x0A, 0x0D, 0xD1, 0x2D, 0xE2, 0x48, 0x2B, 0xFF, 0xE9, 0x82, 0x8F, 0x2F,
            0x9A, 0xB9,
        ];

        let mut block = plaintext;

        cipher.encrypt_block_inplace(&mut block);
        cipher2.decrypt_block_inplace(&mut block);

        assert_eq!(block, plaintext);
    }
}
