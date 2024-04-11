use cbc::{
    cipher::{block_padding, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Decryptor as CBCDecryptor, Encryptor as CBCEncryptor,
};
use crypto::{self, digest::Digest, sha2};
use rand::{rngs::OsRng, RngCore};
use std::error::Error;

type SerpentCbcEnc = CBCEncryptor<serpent::Serpent>;
type SerpentCbcDec = CBCDecryptor<serpent::Serpent>;

pub type Key = [u8; 32];

pub const BLOCK_SIZE: usize = 16;
pub const IV_SIZE: usize = 16;

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
    pub fn sha256(buf: &mut [u8; 32], data: &[u8]) {
        let mut sha256 = sha2::Sha256::new();
        sha256.input(data);
        sha256.result(buf);
    }
}

pub struct Encryptor(Key);

impl<'a> Encryptor {
    pub fn new(key: Key) -> Encryptor {
        return Encryptor(key);
    }
    /// returns the overhead (padding length) of plaintext with `pt_len`
    pub fn pad_len(&self, pt_len: usize) -> usize {
        let remainder = pt_len % BLOCK_SIZE;
        return match remainder == 0 {
            true => BLOCK_SIZE,
            false => BLOCK_SIZE - remainder,
        };
    }

    /// cipher `plaintext` and write it to `buf`
    /// `buf` must be of sufficient length, which is the multiple of 16 + `IV_SIZE`.
    /// if `ciphertext.len() % 16 == 0`, then `buf.len() = ciphertext.len() + 16`
    /// pad it to a multiple of 16 otherwise.
    pub fn encrypt(self, plaintext: &'a [u8], buf: &'a mut [u8]) -> Result<(), Box<dyn Error>> {
        dbg!(plaintext.len());
        dbg!(buf.len());
        // make `iv`, then copy it into the first `IV_SIZE` bytes of `buf`
        OsRng.try_fill_bytes(&mut buf[..IV_SIZE])?;
        // cipher `plaintext` and write to `buf`
        SerpentCbcEnc::new_from_slices(&self.0, &buf[..IV_SIZE])?
            .encrypt_padded_b2b_mut::<block_padding::Pkcs7>(plaintext, &mut buf[IV_SIZE..])?;

        Ok(())
    }

    pub fn decrypt(self, ciphertext: &'a [u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        dbg!(ciphertext.len());
        let nonce = &ciphertext[..IV_SIZE];
        let ciphertext = &ciphertext[IV_SIZE..];
        dbg!(ciphertext.len());
        let mut buf: Vec<u8> = Vec::with_capacity(ciphertext.len());
        SerpentCbcDec::new_from_slices(&self.0, nonce)?
            .decrypt_padded_b2b_mut::<block_padding::Pkcs7>(ciphertext, &mut buf)?;
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
