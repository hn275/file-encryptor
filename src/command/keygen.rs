use crate::{crypto::cipher, error, Command};
use clap::Parser;
use crypto::scrypt;
use std::io::{self, Read, Write};

type Key = [u8; cipher::KEY_LEN];

struct Scrypt {
    param: scrypt::ScryptParams,
}

impl Scrypt {
    pub fn new() -> Self {
        // https://tobtu.com/minimum-password-settings/
        let param = scrypt::ScryptParams::new(16, 8, 2);
        Scrypt { param }
    }

    pub fn gen(&self, password: &[u8], key: &mut Key) -> error::Result<()> {
        if password.len() < 8 {
            return Err(error::Error::IO(String::from("Password too short")));
        }

        let mut sub_key: Key = Default::default();
        scrypt::scrypt(password, &[], &self.param, &mut sub_key);

        Self::xor_key(key, &sub_key);

        Ok(())
    }

    pub fn xor_key(key_buf: &mut Key, sub_key: &Key) {
        for i in 0..cipher::KEY_LEN {
            key_buf[i] ^= sub_key[i];
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct KeyGen {
    /// password used to generate key, read from stdin if not provided
    #[arg(short, long)]
    password: Option<String>,
}

impl Command for KeyGen {
    fn handle(&self) -> error::Result<()> {
        const MAX_KEY_SIZE: usize = 0xff;
        let mut key_buf: Key = Default::default();

        if let Some(pw) = &self.password {
            let scrypt = Scrypt::new();
            scrypt.gen(pw.as_bytes(), &mut key_buf)?;
        } else {
            let scrypt = Scrypt::new();

            let mut buf: [u8; MAX_KEY_SIZE] = [0_u8; MAX_KEY_SIZE];
            let mut stdin = io::stdin().lock();

            loop {
                let bytes_read = stdin.read(&mut buf)?;
                scrypt.gen(buf.as_slice(), &mut key_buf)?;
                if bytes_read < MAX_KEY_SIZE {
                    break;
                }
            }
        }

        Ok(io::stdout().lock().write_all(&key_buf)?)
    }
}
