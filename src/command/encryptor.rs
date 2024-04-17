use clap::Parser;
use std::{
    fs,
    io::{self, Read, Write},
    path,
};

use super::Command;
use crate::crypto::{
    cipher,
    encoding,
};

#[derive(Parser, Debug, Clone)]
pub struct Encryptor {
    /// input file
    input_file: String,

    /// additional authenticated data
    #[arg(short, long)]
    aad: Option<String>,
}

impl Command for Encryptor {
    fn handle(&self) -> io::Result<()> {
        let mut key: [u8; 32] = [0; 32];
        io::stdin().lock().read_exact(&mut key)?;

        let file_len: usize = path::Path::new(&self.input_file)
            .metadata()?
            .len()
            .try_into()
            .unwrap();

        let mut buf = cipher::make_buffer(file_len + cipher::OVERHEAD);

        fs::OpenOptions::new()
            .read(true)
            .open(&self.input_file)?
            .read_exact(&mut buf[cipher::OVERHEAD..])?;

        let aad = match &self.aad {
            None => None,
            Some(aad) => {
                let mut buf: [u8; 32] = [0; 32];
                encoding::sha256::encode(&mut buf, aad.as_bytes());
                Some(buf)
            }
        };

        cipher::Cipher::new(&key).encrypt(&mut buf, &aad)?;
        io::stdout().lock().write_all(&buf)
    }
}
