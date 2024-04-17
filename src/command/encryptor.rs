use aes_gcm::{
    aead::{rand_core::RngCore, AeadInPlace, Key, KeyInit, OsRng},
    Aes256Gcm, Nonce, Tag,
};
use clap::Parser;
use std::io::{self, Read};

use super::Command;
use crate::crypto::{cipher::Cipher, encoding::sha256};

#[derive(Parser, Debug, Clone)]
pub struct Encryptor {
    /// input file
    input_file: String,

    /// output file to write to
    #[arg(short, long)]
    write: Option<String>,

    /// additional authenticated data
    /// TODO: implement this
    #[arg(short, long)]
    aad: Option<String>,
}

impl Command for Encryptor {
    fn handle(&self) -> io::Result<()> {
        let mut key: [u8; 32] = [0; 32];
        io::stdin().lock().read_exact(&mut key)?;
        let cipher = Cipher::new(&key);
        Ok(())
        //
        // let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(key);
        // dbg!(buf, key, aad);
    }
}
