use crate::{
    crypto::{self, cipher},
    error,
};
use clap::Parser;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
};

use super::Exec;

#[derive(Parser, Debug, Clone)]
pub struct Encryptor {
    input_file: String,
    output_file: String,

    /// (optional) additional authenticated data
    #[arg(short, long)]
    aad: Option<String>,

    /// File containing the 32 byte key
    #[arg(short, long)]
    key: String,
}

impl Exec for Encryptor {
    fn handle(&self) -> error::Result<()> {
        // reads in key
        let mut key_file = OpenOptions::new().read(true).open(&self.key)?;
        if key_file.metadata()?.len() != cipher::KEY_SIZE as u64 {
            return Err(error::Error::Key);
        }

        let mut key = cipher::Key::default();
        key_file.read_exact(&mut key)?;

        let mut inputfile = fs::OpenOptions::new().read(true).open(&self.input_file)?;
        let mut outputfile = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.output_file)?;

        // iv
        let iv = cipher::Block::new_iv();
        outputfile.write_all(iv.iv_bytes())?;

        let mut cipher = cipher::Cipher::new(key, iv, &self.aad);

        let mut eof = false;
        loop {
            let mut buf = cipher::Block::default();
            let bytes_read = inputfile.read(&mut buf.0)?;
            if bytes_read != cipher::BLOCK_SIZE {
                crypto::pkcs7::pad(&mut buf, bytes_read);
                eof = true;
            }

            // cipher block
            cipher.encrypt_block_inplace(&mut buf, bytes_read);
            outputfile.write_all(&buf.0)?;

            if eof {
                break;
            }
        }

        Ok(outputfile.write_all(&cipher.tag().0)?)
    }
}
