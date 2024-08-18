use crate::ioutils::FileArg;
use clap::{Parser, Subcommand};

pub mod keygen;
pub mod open;
pub mod seal;

/// A Rust CLI program that streams files for encryption and decryption.
#[derive(Parser, Debug)]
pub struct Cli {
    /// Action to perform on the input file
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// generate a key, from pure random bytes, or from an input password.
    Keygen(keygen::KeyGen),

    /// open an encrypted file
    Open(FileArg),

    /// seal a plaintext file
    Seal(FileArg),
}
