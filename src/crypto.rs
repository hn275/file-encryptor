use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
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

pub struct Encoding;
impl Encoding {
    pub fn sha256(buf: &mut [u8; 32], data: &[u8]) {
        let mut sha256 = sha2::Sha256::new();
        sha256.input(data);
        sha256.result(buf);
    }

    pub fn base64(buf: &[u8]) -> String {
        return STANDARD_NO_PAD.encode(&buf);
    }
}

pub struct Encryptor(Key);

impl<'a> Encryptor {
    pub fn new(key: Key) -> Encryptor {
        return Encryptor(key);
    }
    /// returns the overhead (padding length) of plaintext with `pt_len`
    pub fn overhead(&self, pt_len: usize) -> usize {
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
        // make `iv`, then copy it into the first `IV_SIZE` bytes of `buf`
        let mut iv: Vec<u8> = make_buffer(IV_SIZE);
        OsRng.try_fill_bytes(&mut iv)?;
        iv.iter().enumerate().for_each(|(i, &bytes)| buf[i] = bytes);

        // cipher `plaintext` and write to `buf`
        SerpentCbcEnc::new_from_slices(&self.0, &iv)?
            .encrypt_padded_b2b_mut::<block_padding::Pkcs7>(plaintext, &mut buf[IV_SIZE..])?;

        Ok(())
    }
}

pub struct Decryptor {}
impl Decryptor {}

pub fn make_buffer(size: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        buf.push(0);
    }
    return buf;
}
