use crate::error;
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
}

#[derive(Subcommand, Clone, Debug)]
pub enum Action {
    /// generate a key, from pure random bytes, or from an input password.
    Keygen(keygen::KeyGen),

    /// open an encrypted file
    Open(open::Decryptor),

    /// seal a plaintext file
    Seal(seal::Encryptor),
}

pub trait Command {
    fn handle(&self) -> error::Result<()>;
}
