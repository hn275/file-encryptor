use std::{fs::OpenOptions, io::Read};

use crate::{
    crypto::{block::Block, cipher::Cipher, pkcs7, Key, BLOCK_SIZE, IV_SIZE, KEY_SIZE},
    error,
    ioutils::{FileArg, IO},
};

pub fn open(arg: &FileArg) -> error::Result<()> {
    let mut io = IO::new(&arg.input_file, &arg.output_file)?;

    let key = match &arg.key {
        None => {
            let mut key = Key::default();
            std::io::stdin().read(&mut key)?;
            key
        }
        Some(filename) => {
            let mut file = OpenOptions::new().read(true).open(filename)?;
            if file.metadata()?.len() != (KEY_SIZE as u64) {
                return Err(error::Error::Key);
            }

            let mut key = Key::default();
            file.read_exact(&mut key)?;
            key
        }
    };

    let mut iv = Block::default();
    io.read_bytes(&mut iv.bytes_mut()[0..IV_SIZE])?;

    let mut cipher = Cipher::new(key, iv, &arg.aad);

    // read in the first block
    let mut buf_proc = Block::default();
    let mut bytes_read = io.read_block(&mut buf_proc)?;
    if bytes_read != BLOCK_SIZE {
        // invalid padding
        return Err(error::Error::Encryption(String::from(
            "invalid ciphertext file",
        )));
    }

    let mut buf_read = Block::default();
    bytes_read = io.read_block(&mut buf_read)?;
    if bytes_read != BLOCK_SIZE {
        // missing auth tag
        return Err(error::Error::Encryption(String::from(
            "invalid ciphertext file",
        )));
    }

    let mut loop_buf = Block::default();
    loop {
        bytes_read = io.read_block(&mut loop_buf)?;
        if bytes_read != BLOCK_SIZE {
            println!("last bytes_read: {}", bytes_read);
            break;
        }

        cipher.decrypt_block_inplace(&mut buf_proc);
        io.write_block(&buf_proc, BLOCK_SIZE)?;

        buf_proc.bytes_mut().copy_from_slice(buf_read.bytes());
        buf_read.bytes_mut().copy_from_slice(loop_buf.bytes());
    }

    // buf_proc contains the last ciphertext
    // buf_read contains the tag
    cipher.decrypt_block_inplace(&mut buf_proc);
    let buf_len = pkcs7::unpad(&mut buf_proc);
    io.write_block(&buf_proc, buf_len)?;

    let decrypted_tag = buf_read.bytes();
    dbg!(&decrypted_tag);
    dbg!(&cipher.tag().bytes());
    /*
    for (i, byte) in cipher.tag().bytes().iter().enumerate() {
        if *byte != decrypted_tag[i] {
            return Err(error::Error::Encryption("invalid tag".to_string()));
        }
    }
*/

    Ok(())
}
