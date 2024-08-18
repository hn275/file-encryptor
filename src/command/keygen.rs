use crate::{crypto::KEY_SIZE, error, ioutils::IO};
use clap::Parser;
use rand::Rng;
use scrypt;
use std::sync::{Arc, Mutex};

type Key = [u8; KEY_SIZE];
const MAX_KEY_SIZE: usize = 0xffff;

struct Hash(scrypt::Params);

impl Default for Hash {
    fn default() -> Self {
        // https://tobtu.com/minimum-password-settings/
        Self(scrypt::Params::new(16, 8, 2, KEY_SIZE).expect("invalid param for scrypt"))
    }
}

impl Hash {
    fn hash(&self, payload: &[u8]) -> Key {
        let mut key = Key::default();
        scrypt::scrypt(payload, &[], &self.0, &mut key)
            .expect("invalid keysize buffer, use constant `KEY_SIZE`");
        key
    }
}

struct Engine {
    key_buf: Key,
}

impl Engine {
    pub fn new() -> Self {
        let key_buf: Key = Default::default();
        Engine { key_buf }
    }

    pub fn update(&mut self, subkey: &Key) -> &mut Self {
        Self::xor_key(&mut self.key_buf, subkey);
        self
    }

    pub fn bytes(&self) -> &Key {
        &self.key_buf
    }

    fn xor_key(key_buf: &mut Key, sub_key: &Key) {
        for i in 0..KEY_SIZE {
            key_buf[i] ^= sub_key[i];
        }
    }
}

/// If no option, stdin...
#[derive(Parser, Debug, Clone)]
pub struct KeyGen {
    /// (optional) a passphrase used to generate key
    #[arg(short, long)]
    password: Option<String>,

    /// Randomly generated, takes precedence over all other options
    #[arg(short, long, default_value_t = false)]
    rand: bool,

    /// (Optional) File to read in as key, default stdin
    #[arg(short, long)]
    input_file: Option<String>,

    /// (Optional) File to write out, default stdout
    #[arg(short, long)]
    output_file: Option<String>,
}

impl KeyGen {
    pub fn gen(&self) -> error::Result<()> {
        let mut io = IO::new(&self.input_file, &self.output_file)?;
        let hash = Hash(scrypt::Params::new(16, 8, 2, KEY_SIZE).expect("invalid param for scrypt"));

        if self.rand {
            Ok(with_rand(&mut io, &hash)?)
        } else if let Some(pw) = &self.password {
            Ok(with_password(&mut io, &hash, pw)?)
        } else {
            Ok(with_stdin(&mut io, &hash)?)
        }
    }
}

fn with_rand(io: &mut IO, hash: &Hash) -> error::Result<()> {
    let mut buf = [0u8; MAX_KEY_SIZE];
    let mut rng = rand::thread_rng();
    buf.iter_mut().for_each(|i| *i = rng.gen());

    let key = hash.hash(&buf);
    io.write_bytes(Engine::new().update(&key).bytes())?;

    Ok(())
}

fn with_password(io: &mut IO, hash: &Hash, pw: &String) -> error::Result<()> {
    let key = hash.hash(pw.as_bytes());
    io.write_bytes(Engine::new().update(&key).bytes())?;
    Ok(())
}

fn with_stdin(io: &mut IO, hash: &Hash) -> error::Result<()> {
    let keygen = Arc::new(Mutex::new(Engine::new()));
    let hash = Arc::new(hash);

    let scope: error::Result<()> = rayon::scope(|s| {
        loop {
            let mut buf = [0_u8; MAX_KEY_SIZE];
            let bytes_read = io.read_bytes(&mut buf)?;

            let keygen = Arc::clone(&keygen);
            let hash = Arc::clone(&hash);
            s.spawn(move |_| {
                let subkey = hash.hash(&buf);
                keygen
                    .lock()
                    .expect("unable to obtain thread lock for key generation engine")
                    .update(&subkey);
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
    let bytes = keygen.bytes();

    io.write_bytes(bytes)?;
    Ok(())
}
