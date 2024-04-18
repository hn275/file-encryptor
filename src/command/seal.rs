use clap::Parser;
use std::{
    fs,
    io::{self, Read},
    path,
};

use super::Command;
use crate::crypto::{self, cipher::OVERHEAD, encoding};

#[derive(Parser, Debug, Clone)]
pub struct Encryptor {
    /// input file
    input_file: String,

    /// (optional) output file
    #[arg(short, long)]
    write: Option<String>,

    /// (optional) additional authenticated data
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
            .expect("failed to convert u64 to usize");

        let mut file_buf = crypto::cipher::make_buffer(file_len + crypto::cipher::OVERHEAD);
        fs::OpenOptions::new()
            .read(true)
            .open(&self.input_file)?
            .read_exact(&mut file_buf[OVERHEAD..])?;

        let aad = match &self.aad {
            None => None,
            Some(aad) => {
                let mut buf: [u8; 32] = [0; 32];
                encoding::sha256::encode(&mut buf, aad.as_bytes());
                Some(buf)
            }
        };

        crypto::cipher::Cipher::new(&key).encrypt(&mut file_buf, &aad)?;

        self.output(&file_buf, &self.write)
    }
}
