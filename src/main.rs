use clap::{Parser, ValueEnum};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::symmetriccipher::BlockDecryptor;
use crypto::symmetriccipher::BlockEncryptor;
use crypto::{self, digest::Digest, sha2};
use serpent::{
    cipher::{BlockEncrypt, KeyInit},
    Serpent,
};
use std::{io, process::exit};

#[derive(Parser, Debug)]
struct CLI {
    #[arg(value_enum)]
    command: Command,

    /// File to encrypt/decrypt
    file_name: String,

    /// output file
    #[arg(short, long, default_value = "file-encryptor.out")]
    out: String,
}

#[derive(ValueEnum, Clone, Debug)]
enum Command {
    /// Encrypt a file
    Enc,
    /// Decrypt a file
    Dec,
}

fn main() {
    let cli = CLI::parse();

    let mut key: [u8; 32] = [0; 32];
    if let Err(err) = make_key(&mut key) {
        eprintln!("Failed to create an encryption key: {}", err);
        exit(1);
    }

    let cipher = serpent::Serpent::new_from_slice(&key).unwrap();
    let mut read_buf = crypto::buffer::RefReadBuffer::new("Hello world".as_bytes());
    let mut buf: [u8; 64] = [0; 64];
    let mut write_buf = crypto::buffer::RefReadBuffer::new(&mut buf);
    cipher.encrypt_blocks(&mut read_buf);
    dbg!(&key);
}

fn make_key(buf: &mut [u8; 32]) -> io::Result<()> {
    let pass = rpassword::prompt_password("Enter key: ").unwrap();
    let pass_confirm = rpassword::prompt_password("Confirm key: ").unwrap();
    if pass != pass_confirm {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "password validation failed.",
        ));
    }
    let mut sha256 = sha2::Sha256::new();
    sha256.input(pass.as_bytes());
    sha256.result(buf);
    Ok(())
}
