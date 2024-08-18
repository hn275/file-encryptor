use crate::{
    crypto::{self, block::Block, cipher, Key, BLOCK_SIZE, IV_SIZE, KEY_SIZE},
    error,
    ioutils::{FileArg, IO},
};
use clap::Parser;
use std::{fs::OpenOptions, io::Read};

#[derive(Parser, Debug, Clone)]
pub struct Encryptor {
    /// (optional) input file, read from stdin by default
    #[arg(short, long)]
    input_file: Option<String>,

    /// (optional) output file, write to stdout by default
    #[arg(short, long)]
    output_file: Option<String>,

    /// (optional) additional authenticated data
    #[arg(short, long)]
    aad: Option<String>,

    /// (optional) key file, read (the first) 32 byte from stdin by default
    #[arg(short, long)]
    key: Option<String>,
}

pub fn seal(filearg: &FileArg) -> error::Result<()> {
    let mut io = IO::new(&filearg.input_file, &filearg.output_file)?;

    // reads in key, if `-k` flag is passed, reads from file
    // otherwise reads (the first) 32 bytes from stdin
    let key = match &filearg.key {
        None => {
            let mut buf = Key::default();
            std::io::stdin().read_exact(&mut buf).map_err(|err| {
                eprintln!("{}", err);
                error::Error::Key
            })?;

            buf
        }
        Some(key) => {
            let mut key_file = OpenOptions::new().read(true).open(key)?;
            if key_file.metadata()?.len() != KEY_SIZE as u64 {
                return Err(error::Error::Key);
            }
            let mut buf = Key::default();
            key_file.read_exact(&mut buf)?;

            buf
        }
    };

    // iv
    let iv = Block::new_iv();
    io.write_block(&iv, IV_SIZE)?;

    // let mut cipher = cipher::Cipher::new(key, iv, &filearg.aad);
    let mut cipher = cipher::Cipher::new(key, iv, &None);

    // stream file/stdin
    let mut eof = false;
    loop {
        let mut buf = Block::default();
        let bytes_read = io.read_block(&mut buf)?;
        if bytes_read != BLOCK_SIZE {
            crypto::pkcs7::pad(&mut buf, bytes_read);
            eof = true;
        }

        // cipher block
        cipher.encrypt_block_inplace(&mut buf, bytes_read);
        io.write_block(&buf, BLOCK_SIZE)?;

        if eof {
            break;
        }
    }

    io.write_block(cipher.tag(), BLOCK_SIZE)?;
    Ok(())
}
