use super::Command;
use crate::crypto::encoding;
use aes_gcm::aead::{rand_core::RngCore, OsRng};
use clap::Parser;
use std::io;

#[derive(Parser, Debug, Clone)]
pub struct KeyGen {
    /// output file
    #[arg(short, long)]
    write: Option<String>,

    /// password used to generate key
    #[arg(short, long)]
    password: Option<String>,
}

impl Command for KeyGen {
    fn handle(&self) -> Result<(), io::Error> {
        let mut buf: [u8; 32] = [0; 32];
        match &self.password {
            None => OsRng.fill_bytes(&mut buf),
            Some(password) => encoding::sha256::encode(&mut buf, password.as_bytes()),
        };
        self.output(&buf, &self.write)
    }
}
