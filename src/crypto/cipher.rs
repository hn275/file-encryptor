use std::io;

use aes_gcm::{
    aead::{rand_core::RngCore, AeadInPlace, Key, KeyInit, OsRng},
    Aes256Gcm, Nonce, Tag,
};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;
pub const KEY_LEN: usize = 32;

pub struct Cipher<'a>(&'a Key<Aes256Gcm>);

impl<'a> Cipher<'a> {
    pub fn new(key: &[u8; KEY_LEN]) -> Cipher {
        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(key);
        return Cipher(key);
    }

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
            Some(aad) => aad.as_slice(),
            None => &[0_u8; 0],
        };

        // nonce
        OsRng.fill_bytes(&mut meta[..NONCE_LEN]);
        let nonce = Nonce::from_slice(&meta[..NONCE_LEN]);

        // encrypt and copy tag
        let tag = Aes256Gcm::new(self.0)
            .encrypt_in_place_detached(nonce, aad, msg)
            .map_err(|err| {
                dbg!(err);
                io::Error::new(io::ErrorKind::Other, "failed to encrypt data.")
            })?;
        buf[NONCE_LEN..OVERHEAD].copy_from_slice(tag.as_slice());

        Ok(())
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
            None => &[0_u8; 0],
        };

        let (meta, buf_slize) = buf.split_at_mut(OVERHEAD);
        let nonce = Nonce::from_slice(&meta[..NONCE_LEN]);
        let tag = Tag::from_slice(&meta[NONCE_LEN..OVERHEAD]);

        Aes256Gcm::new(self.0)
            .decrypt_in_place_detached(nonce, aad, buf_slize, tag)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to authenticated/decrypt data.",
                )
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // nonce is copied
        assert_ne!(&buf[..NONCE_LEN], [0 as u8; 12]);

        // tag is copied
        assert_ne!(&buf[NONCE_LEN..OVERHEAD], [0 as u8; 12]);

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

    #[test]
    fn test_encrypt_decrypt_no_aad() {
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

        cipher.encrypt(&mut buf, &None).unwrap();

        cipher.decrypt(&mut buf, &None).unwrap();
        assert_eq!(&buf[OVERHEAD..], plaintext);
    }
}

pub fn make_buffer(size: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(size);
    buf.fill(0);
    buf
}
