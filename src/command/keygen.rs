use crate::{
    command::Exec,
    crypto::{BLOCK_SIZE, KEY_SIZE},
    error,
};
use clap::Parser;
use scrypt;
use std::{
    io::{self, Read, Write},
    sync::{Arc, Mutex},
};

type Key = [u8; KEY_SIZE];

struct Engine {
    scrypt: scrypt::Params,
    key_buf: Key,
}

impl Engine {
    pub fn new() -> Self {
        // https://tobtu.com/minimum-password-settings/
        let scrypt = scrypt::Params::new(16, 8, 2, KEY_SIZE).expect("invalid param for scrypt");
        let key_buf: Key = Default::default();
        Engine { scrypt, key_buf }
    }

    pub fn update(&mut self, password: &[u8]) {
        let mut sub_key: Key = Default::default();
        scrypt::scrypt(password, &[], &self.scrypt, &mut sub_key).expect("invalid sub_key length");
        Self::xor_key(&mut self.key_buf, &sub_key);
    }

    pub fn bytes(&self) -> &[u8] {
        self.key_buf.as_ref()
    }

    fn xor_key(key_buf: &mut Key, sub_key: &Key) {
        for i in 0..BLOCK_SIZE {
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

impl Exec for KeyGen {
    fn handle(&self) -> error::Result<()> {
        let keygen = Arc::new(Mutex::new(Engine::new()));

        if let Some(pw) = &self.password {
            keygen
                .lock()
                .expect("unable to obtain thread lock for key generation engine")
                .update(pw.as_bytes());
        } else {
            let scope: error::Result<()> = rayon::scope(|s| {
                let mut stdin = io::stdin().lock();
                const MAX_KEY_SIZE: usize = 0xffff;

                loop {
                    let mut buf = [0_u8; MAX_KEY_SIZE];
                    let bytes_read = stdin.read(&mut buf)?;

                    let keygen = Arc::clone(&keygen);
                    s.spawn(move |_| {
                        keygen
                            .lock()
                            .expect("unable to obtain thread lock for key generation engine")
                            .update(buf.as_slice());
                    });

                    if bytes_read < MAX_KEY_SIZE {
                        break;
                    }
                }

                Ok(())
            });

            scope?;

            let keygen = keygen
                .lock()
                .expect("unable to obtain thread lock for key generation engine");

            io::stdout().lock().write_all(keygen.bytes())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let keystream = [
            String::from("Hello world 1"),
            String::from("Hello world 2"),
            String::from("Hello world 3"),
        ];

        let mut engine1 = Engine::new();
        let mut engine2 = Engine::new();

        let keystream_ctr = keystream.len();
        for i in 0..keystream_ctr {
            engine1.update(keystream[i].as_bytes());
            engine2.update(keystream[keystream_ctr - 1 - i].as_bytes());
        }

        assert_eq!(engine1.bytes(), engine2.bytes());
    }
}
