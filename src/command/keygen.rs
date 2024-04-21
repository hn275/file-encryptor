use super::Command;
use crate::crypto;
use aes_gcm::aead::{rand_core::RngCore, OsRng};
use clap::Parser;
use std::io::{self, Write};

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
            Some(password) => {
                crypto::kdf::generate(password.as_str(), &mut buf).map_err(|err| {
                    io::Error::new(io::ErrorKind::Other, err.to_string())
                })?
            }
        };
        io::stdout().lock().write_all(&buf)
    }
}
