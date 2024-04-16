use aes_gcm::{
    aead::{rand_core::RngCore, AeadInPlace, Key, KeyInit, OsRng},
    Aes256Gcm, Nonce, Tag,
};

use super::encoding::sha256;

pub struct Encryptor;

impl Encryptor {
    pub fn encrypt(buf: &mut [u8], key: &sha256::Digest, aad: &Option<String>) {
        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(key);
        dbg!(buf, key, aad);
    }
}
