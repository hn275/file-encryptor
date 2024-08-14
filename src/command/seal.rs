use crate::{crypto::cipher, error};
use clap::Parser;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
};

use super::Command;

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

impl Command for Encryptor {
    fn handle(&self) -> error::Result<()> {
        // reads in key
        let mut key_file = OpenOptions::new().read(true).open(&self.key)?;
        if key_file.metadata()?.len() != cipher::BLOCK_SIZE as u64 {
            return Err(error::Error::Key);
        }

        let mut key = cipher::Key::default();
        if key_file.read(&mut key)? != cipher::BLOCK_SIZE {
            return Err(error::Error::IO(format!(
                "Failed to read in key from {}",
                self.key
            )));
        }

        let mut inputfile = fs::OpenOptions::new().read(true).open(&self.input_file)?;
        let mut outputfile = fs::OpenOptions::new().read(true).open(&self.output_file)?;

        let iv = cipher::IV::new();
        outputfile.write(iv.iv_bytes())?;

        let aad = match &self.aad {
            None => None,
            Some(aad) => Some(aad.as_bytes()),
        };

        let cipher = cipher::Cipher::new(key, iv, aad);

        Ok(())
    }
}
