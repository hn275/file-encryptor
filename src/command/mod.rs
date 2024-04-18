use std::{fs, io::{self, Write}};

use clap::{Parser, Subcommand};
pub mod keygen;
pub mod open;
pub mod seal;

/// A small Rust program to deal with file encryption.
#[derive(Parser, Debug)]
pub struct CLI {
    /// Action to perform on the input file
    #[command(subcommand)]
    pub action: Action,

    /// Key used to perform the ciphering action
    /// TODO: implement this
    #[arg(short, long)]
    pub key: Option<String>,

    /// Receiver of the file, this will be used as authenticated data.
    /// TODO: implement this
    #[arg(short, long)]
    pub auth_data: Option<String>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Action {
    /// Decrypt a file
    Open(open::Decryptor),

    /// Encrypt a file
    Seal(seal::Encryptor),

    /// Read in a key, process and hash. The input key will be read in _at most 64 bytes_.
    Keygen(keygen::KeyGen),
}

pub trait Command {
    fn handle(&self) -> Result<(), io::Error>;

    fn output(&self, buf: &[u8], outfile: &Option<String>) -> io::Result<()> {
        match outfile {
            None => io::stdout().lock().write_all(buf),
            Some(f) => {
                fs::OpenOptions::new().write(true).truncate(true).create(true).open(f)?.write_all(buf)
            }
        }
    }
}
