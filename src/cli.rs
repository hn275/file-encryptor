use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
pub struct CLI {
    #[arg(value_enum)]
    pub command: Command,

    /// File to encrypt/decrypt
    pub file_name: String,

    /// output file
    #[arg(short, long, default_value = "file-encryptor.out")]
    pub out: String,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum Command {
    /// Encrypt a file
    Open,
    /// Decrypt a file
    Seal,
}
