use crypto::{self, digest::Digest, sha2};
use rand::RngCore;
use std::error::Error;

use aes_gcm::{
    aead::{AeadCore, AeadInPlace, AeadMutInPlace, Key, KeyInit, OsRng},
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

    /// cipher `plaintext` and write it to `buf`
    /// buf construction:
    ///     - 12 bytes nonce (`NONCE_LEN`)
    ///     - plaintext length
    ///     - 16 bytes auth tag (`AUTH_TAG_LEN`)
    pub fn encrypt(&self, plaintext: &'a [u8], buf: &'a mut [u8]) -> Result<(), Box<dyn Error>> {
        // make `nonce`, then copy it into the first `IV_SIZE` bytes of `buf`
        OsRng.fill_bytes(&mut buf[..NONCE_LEN]);

        // cipher `plaintext` and write to `buf`
        Aes256Gcm::new(&self.0).encrypt_in_place();

        Ok(())
    }

    pub fn decrypt(self, ciphertext: &'a [u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        dbg!(ciphertext.len());
        let nonce = &ciphertext[..NONCE_LEN];
        let ciphertext = &ciphertext[NONCE_LEN..];
        dbg!(ciphertext.len());
        let mut buf: Vec<u8> = Vec::with_capacity(ciphertext.len());
        // SerpentCbcDec::new_from_slices(&self.0, nonce)?
        // .decrypt_padded_b2b_mut::<block_padding::Pkcs7>(ciphertext, &mut buf)?;
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
