use super::Command;
use crate::crypto::encoding;
use aes_gcm::aead::{rand_core::RngCore, OsRng};
use clap::Parser;
use std::{
    default,
    io::{self, Write},
};

#[derive(Parser, Debug, Clone)]
pub struct KeyGen {
    /// password
    #[arg(short, long)]
    password: Option<String>,

    ///
    #[arg(short, long)]
    base64: bool,
}

impl Command for KeyGen {
    fn handle(&self) -> Result<(), io::Error> {
        let mut key_buf: [u8; 32] = [0; 32];
        match &self.password {
            None => OsRng.fill_bytes(&mut key_buf),
            Some(password) => encoding::sha256::encode(&mut key_buf, password.as_bytes()),
        };
        if !self.base64 {
            io::stdout().lock().write_all(&key_buf)?;
            return Ok(());
        }

        let mut buf = [0 as u8; encoding::base64::ENCODED_LEN_32];
        encoding::base64::encode(&mut buf, &key_buf).map_err(|err| {
            dbg!(err);
            io::Error::new(io::ErrorKind::Other, "buffer to small")
        })?;
        io::stdout().lock().write_all(&buf)?;
        Ok(())
    }
}
