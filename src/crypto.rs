use crypto::{self, digest::Digest, sha2, symmetriccipher::SymmetricCipherError};
use rand::RngCore;
use std::error::Error;

use aes_gcm::{
    aead::{Aead, AeadCore, AeadInPlace, AeadMutInPlace, Key, KeyInit, OsRng},
    aes::cipher,
    Aes256Gcm, Nonce,
};

pub const NONCE_LEN: usize = 12;
pub const AUTH_TAG_LEN: usize = 16;

pub mod encoding {
    use base64::{
        engine::general_purpose::{self, STANDARD_NO_PAD},
        Engine,
    };
    const BASE64_ENCODING: general_purpose::GeneralPurpose = STANDARD_NO_PAD;

    pub struct Base64;
    impl Base64 {
        pub fn encode(buf: &[u8]) -> String {
            return BASE64_ENCODING.encode(buf);
        }

        pub fn decode(buf: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
            return BASE64_ENCODING.decode(buf);
        }
    }
}
pub struct Encoding;
impl Encoding {
    pub fn sha256(buf: &mut [u8], data: &[u8]) {
        let mut sha256 = sha2::Sha256::new();
        sha256.input(data);
        sha256.result(buf);
    }
}

pub struct Encryptor<'a>(&'a Key<Aes256Gcm>);

impl<'a> Encryptor<'a> {
    pub fn new(key: &[u8]) -> Encryptor {
        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key);
        return Encryptor(key);
    }

    fn key(&self) -> &Key<Aes256Gcm> {
        return self.0;
    }

    /// cipher `plaintext` and write it to `buf`
    /// `buf` construction:
    ///     - 12 bytes nonce (`NONCE_LEN`)
    ///     - plaintext length
    ///     - 16 bytes auth tag (`AUTH_TAG_LEN`)
    pub fn encrypt(&self, plaintext: &'a [u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let size = plaintext.len() + NONCE_LEN + AUTH_TAG_LEN;
        let mut ciphertext = make_buffer(size);

        // make `nonce`, then copy it into the first `IV_SIZE` bytes of `buf`
        let mut nonce: [u8; 12] = [0; 12];
        OsRng.fill_bytes(&mut nonce);

        // cipher `plaintext` and write to `buf`
        nonce.clone_from_slice(&ciphertext[..NONCE_LEN]);

        ciphertext[..NONCE_LEN].clone_from_slice(&nonce);
        ciphertext[NONCE_LEN..].copy_from_slice(
            Aes256Gcm::new(&self.key())
                .encrypt(&nonce.into(), plaintext)
                .unwrap()
                .as_slice(),
        );

        return Ok(ciphertext);
    }

    pub fn decrypt(self, ciphertext: &'a [u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let nonce = &ciphertext[..NONCE_LEN];
        let auth_tag_byte = ciphertext.len() - AUTH_TAG_LEN;
        let tag = &ciphertext[auth_tag_byte..];
        let ciphertext = &ciphertext[NONCE_LEN..auth_tag_byte];

        let mut buf: Vec<u8> = make_buffer(ciphertext.len());
        buf.copy_from_slice(&ciphertext);

        Aes256Gcm::new(&self.0)
            .decrypt_in_place_detached(nonce.into(), b"", &mut buf, tag.into())
            .unwrap_or_else(|err| println!("{}", err.to_owned()));

        return Ok(buf.to_owned());
    }
}

pub fn make_buffer(size: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        buf.push(0);
    }
    return buf;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryptions() {
        let key: [u8; 32] = [
            0x2f, 0x3a, 0x0b, 0x9c, 0x8e, 0x6d, 0x7f, 0x5a, 0x01, 0xf4, 0x63, 0x21, 0x8b, 0x4c,
            0xef, 0xd2, 0x7d, 0xa8, 0x0e, 0x5b, 0xc7, 0x90, 0x6f, 0x58, 0xb2, 0x35, 0x49, 0x77,
            0xa2, 0xe9, 0xd1, 0x80,
        ];

        let plaintext = b"Hello world!";
        let cipher = Encryptor::new(&key);
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        assert_ne!(plaintext, ciphertext.as_slice());

        let pt = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, pt.as_slice());
    }
}
