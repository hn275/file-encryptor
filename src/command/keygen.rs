use super::Command;
use crate::crypto::encoding;
use aes_gcm::aead::{rand_core::RngCore, OsRng};
use clap::Parser;
use std::io::{self, Write};

#[derive(Parser, Debug, Clone)]
pub struct KeyGen {
    /// password
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
        io::stdout().lock().write_all(&buf)?;
        Ok(())
    }
}
