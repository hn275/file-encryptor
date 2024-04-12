use crypto::{self, digest::Digest, sha2};
use rand::RngCore;
use std::{io};

use aes_gcm::{
    aead::{AeadInPlace, Key, KeyInit, OsRng},
    Aes256Gcm, Nonce, Tag,
};

pub const NONCE_LEN: usize = 12;
pub const AUTH_TAG_LEN: usize = 16;
const PLAINTEXT_BYTE: usize = 28;

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

    /// cipher `buf` in place
    /// `buf` construction:
    ///     - 12 bytes nonce (`NONCE_LEN`)
    ///     - 16 bytes auth tag (`AUTH_TAG_LEN`)
    ///     - plaintext length
    /// NOTE: The content of the ciphering message starts at the 28th byte.
    pub fn encrypt_in_place(&self, buf: &mut [u8]) -> io::Result<()> {
        if buf.len() < 28 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer to small",
            ));
        }

        OsRng.fill_bytes(&mut buf[..NONCE_LEN]);
        let nonce = Nonce::from_slice(&buf[..NONCE_LEN]).to_owned();

        let tag = Aes256Gcm::new(&self.key()).encrypt_in_place_detached(
            &nonce,
            b"",
            &mut buf[PLAINTEXT_BYTE..],
        );

        match tag {
            Ok(tag) => {
                buf[NONCE_LEN..PLAINTEXT_BYTE].copy_from_slice(&tag.as_slice());
                return Ok(());
            }
            Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err.to_string())),
        };
    }

    pub fn decrypt_in_place(self, buf: &'a mut [u8]) -> io::Result<()> {
        if buf.len() < 28 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer to small",
            ));
        }

        let nonce = Nonce::from_slice(&buf[..NONCE_LEN]).to_owned();
        let tag = Tag::from_slice(&buf[NONCE_LEN..PLAINTEXT_BYTE]).to_owned();
        Aes256Gcm::new(&self.0)
            .decrypt_in_place_detached(&nonce, b"", &mut buf[PLAINTEXT_BYTE..], &tag)
            .unwrap();
        return Ok(());
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
        let mut buf = make_buffer(plaintext.len() + NONCE_LEN + AUTH_TAG_LEN);
        buf[PLAINTEXT_BYTE..].copy_from_slice(plaintext);

        let cipher = Encryptor::new(&key);

        cipher.encrypt_in_place(&mut buf).unwrap();
        assert_ne!(buf[PLAINTEXT_BYTE..], *b"Hello world!");

        cipher.decrypt_in_place(&mut buf).unwrap();
        assert_eq!(&buf[PLAINTEXT_BYTE..], *b"Hello world!");
    }
}
