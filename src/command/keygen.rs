use super::Command;
use crate::crypto;
use clap::Parser;
use std::io::{self, Read, Write};

#[derive(Parser, Debug, Clone)]
pub struct KeyGen {
    /// password used to generate key, read from stdin if not provided
    #[arg(short, long)]
    password: Option<String>,
}

impl Command for KeyGen {
    fn handle(&self) -> Result<(), io::Error> {
        let mut key_buf: [u8; 32] = [0; 32];
        if let Some(pw) = &self.password {
            crypto::kdf::generate(pw.as_bytes(), &mut key_buf)?;
        } else {
            let mut pass: Vec<u8> = Vec::new();
            io::stdin().lock().read_to_end(&mut pass)?;
            crypto::kdf::generate(pass.as_slice(), &mut key_buf)?;
        }
        io::stdout().lock().write_all(&key_buf)
    }
}
