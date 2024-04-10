use cbc::cipher::{block_padding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::{Parser, ValueEnum};
use crypto::{self, digest::Digest, sha2};
use std::{io, process::exit};

type SerpentCbcEnc = cbc::Encryptor<serpent::Serpent>;
type SerpentCbcDec = cbc::Decryptor<serpent::Serpent>;

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

    let nonce: [u8; 16] = [0; 16];
    let cipher = SerpentCbcEnc::new_from_slices(&key, &nonce).unwrap();
    let pt = "Hello world".as_bytes();
    let dat = cipher.encrypt_padded_vec_mut::<block_padding::Pkcs7>(&pt);
    dbg!(&dat, &dat.len(), pt.len());

    let cipher = SerpentCbcDec::new_from_slices(&key, &nonce).unwrap();
    let pt2 = cipher
        .decrypt_padded_vec_mut::<block_padding::Pkcs7>(&dat)
        .unwrap();

    dbg!(String::from_utf8(pt2).unwrap());
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
