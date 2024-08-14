#![allow(dead_code)]

pub const IV_SIZE: usize = 12;
pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

pub type Key = [u8; KEY_SIZE];
pub type Block = [u8; BLOCK_SIZE];

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
}

pub struct Cipher<'a> {
    key: Key,
    iv: IV,
    aad: Option<&'a [u8]>,
}

impl<'a> Cipher<'a> {
    pub fn new(key: Key, iv: IV, aad: Option<&'a [u8]>) -> Self {
        Self { key, iv, aad }
    }

    pub fn encrypt_block_inplace(&mut self, _block: &mut Block) {
        self.iv.inc_counter();
    }

    pub fn decrypt_block_inplace(&mut self, _block: &mut Block) {}

    pub fn tag(&mut self) -> Block {
        Default::default()
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
}
