use std::io;

use aes_gcm::{
    aead::{rand_core::RngCore, AeadInPlace, Key, KeyInit, OsRng},
    Aes256Gcm, Nonce, Tag,
};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// the first byte signifies if aad was used
pub const OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

pub struct Cipher<'a>(&'a Key<Aes256Gcm>);

impl<'a> Cipher<'a> {
    pub fn new(key: &[u8]) -> Cipher {
        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key);
        return Cipher(key);
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
    pub fn encrypt(&self, buf: &mut [u8], aad: &Option<[u8; 32]>) -> io::Result<()> {
        if buf.len() < OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer to small",
            ));
        }

        let (meta, msg) = buf.split_at_mut(OVERHEAD);

        // aad
        let aad = match aad {
            Some(aad) => {
                meta[0] = 1;
                aad.as_slice()
            }
            None => {
                meta[0] = 0;
                [0 as u8; 0].as_slice()
            }
        };

        // nonce
        OsRng.fill_bytes(&mut meta[1..NONCE_LEN + 1]);
        let nonce = Nonce::from_slice(&meta[1..NONCE_LEN + 1]);

        // encrypt and copy tag
        let tag = Aes256Gcm::new(&self.key())
            .encrypt_in_place_detached(&nonce, aad, msg)
            .map_err(|err| {
                dbg!(err);
                return io::Error::new(io::ErrorKind::Other, "failed to encrypt data.");
            })?;
        buf[1 + NONCE_LEN..OVERHEAD].copy_from_slice(tag.as_slice());

        return Ok(());
    }

    pub fn decrypt(self, buf: &'a mut [u8], aad: &Option<[u8; 32]>) -> io::Result<()> {
        if buf.len() < OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer to small",
            ));
        }

        if buf[0] == 1 && aad.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ciphertext.",
            ));
        }

        let aad = match aad {
            Some(aad) => aad.as_slice(),
            None => [0 as u8; 0].as_slice(),
        };

        let (meta, buf_slize) = buf.split_at_mut(OVERHEAD);
        let meta: &[u8] = &meta;

        let nonce = Nonce::from_slice(&meta[1..NONCE_LEN + 1]);
        let tag = Tag::from_slice(&meta[1 + NONCE_LEN..OVERHEAD]);

        Aes256Gcm::new(&self.0)
            .decrypt_in_place_detached(&nonce, aad, buf_slize, &tag)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to authenticated/decrypt data.",
                )
            })?;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::make_buffer;

    #[test]
    fn test_encrypt() {
        let plaintext = "Hello world!".as_bytes();

        // some random key bytes
        let key: [u8; 32] = [
            0x2f, 0x3a, 0x0b, 0x9c, 0x8e, 0x6d, 0x7f, 0x5a, 0x01, 0xf4, 0x63, 0x21, 0x8b, 0x4c,
            0xef, 0xd2, 0x7d, 0xa8, 0x0e, 0x5b, 0xc7, 0x90, 0x6f, 0x58, 0xb2, 0x35, 0x49, 0x77,
            0xa2, 0xe9, 0xd1, 0x80,
        ];

        let mut buf = make_buffer(plaintext.len() + OVERHEAD);
        buf[OVERHEAD..].copy_from_slice(plaintext);

        let cipher = Cipher::new(&key);

        let aad: Option<[u8; 32]> = Some([0 as u8; 32]);
        cipher.encrypt(&mut buf, &aad).unwrap();

        // The first byte should be 1 since `aad` is used
        assert_eq!(buf[0], 1 as u8);

        // nonce is copied
        assert_ne!(&buf[1..NONCE_LEN + 1], [0 as u8; 12]);

        // ciphertext is not the same as plaintext
        assert_ne!(&buf[OVERHEAD..], *b"Hello world!");
    }

    #[test]
    fn test_decrypt() {
        let plaintext = "Hello world!".as_bytes();

        // some random key bytes
        let key: [u8; 32] = [
            0x2f, 0x3a, 0x0b, 0x9c, 0x8e, 0x6d, 0x7f, 0x5a, 0x01, 0xf4, 0x63, 0x21, 0x8b, 0x4c,
            0xef, 0xd2, 0x7d, 0xa8, 0x0e, 0x5b, 0xc7, 0x90, 0x6f, 0x58, 0xb2, 0x35, 0x49, 0x77,
            0xa2, 0xe9, 0xd1, 0x80,
        ];

        let mut buf = make_buffer(plaintext.len() + OVERHEAD);
        buf[OVERHEAD..].copy_from_slice(plaintext);

        let cipher = Cipher::new(&key);

        let aad: Option<[u8; 32]> = Some([0 as u8; 32]);
        cipher.encrypt(&mut buf, &aad).unwrap();

        cipher.decrypt(&mut buf, &aad).unwrap();
        assert_eq!(&buf[OVERHEAD..], plaintext);
    }
}

pub fn make_buffer(size: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        buf.push(0);
    }
    return buf;
}
