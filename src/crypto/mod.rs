pub mod block;
pub mod cipher;
pub mod pkcs7;

pub const IV_SIZE: usize = 12;
pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

pub type Key = [u8; KEY_SIZE];
