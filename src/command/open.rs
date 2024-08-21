use aes::{cipher::BlockEncrypt, Aes256};
use aes_gcm::KeyInit;

use crate::{
    crypto::{block::Block, pkcs7, tag::Tag, Key, BLOCK_SIZE, IV_SIZE},
    error,
    ioutils::{FileArg, IO},
};

pub fn open(arg: &FileArg) -> error::Result<()> {
    let mut io = IO::new(&arg.input_file, &arg.output_file)?;

    let key = Key::try_from(arg)?;

    let aes = Aes256::new(&key.into());

    let mut iv = Block::default();
    io.read_bytes(&mut iv.bytes_mut()[0..IV_SIZE])?;

    let mut tag = Tag::new(&aes, &iv);
    if let Some(aad) = &arg.aad {
        tag.with_aad(aad.as_bytes());
    }

    // read in the first block
    let mut buf_proc = Block::default();
    if io.read_block(&mut buf_proc)? != BLOCK_SIZE {
        // invalid padding
        return Err(error::Error::Encryption(String::from(
            "invalid ciphertext file",
        )));
    }

    let mut buf_read = Block::default();
    if io.read_block(&mut buf_read)? != BLOCK_SIZE {
        // missing auth tag
        return Err(error::Error::Encryption(String::from(
            "invalid ciphertext file",
        )));
    }

    let mut loop_buf = Block::default();

    loop {
        let bytes_read = io.read_block(&mut loop_buf)?;

        if bytes_read != BLOCK_SIZE {
            //  invalid padding
            if bytes_read != 0 {
                return Err(error::Error::Encryption(String::from(
                    "invalid ciphertext file",
                )));
            }

            break;
        }

        tag.update_state(&buf_proc);

        let mut ctr = iv.next_counter();
        aes.encrypt_block(ctr.bytes_mut().into());

        buf_proc.xor(&ctr);

        io.write_block(&buf_proc)?;

        buf_proc.bytes_mut().copy_from_slice(buf_read.bytes());
        buf_read.bytes_mut().copy_from_slice(loop_buf.bytes());
    }

    // buf_proc contains the last ciphertext
    // buf_read contains the tag

    tag.update_state(&buf_proc);

    let mut ctr = iv.next_counter();
    aes.encrypt_block(ctr.bytes_mut().into());

    buf_proc.xor(&ctr);

    let buf_len = BLOCK_SIZE - pkcs7::unpad(&mut buf_proc);

    io.write_bytes(&buf_proc.bytes()[..buf_len])?;

    // calculate and verify auth tag

    let decrypted_tag = buf_read.bytes();
    let authenticated_tag = tag.authenticate().bytes();

    for (i, byte) in authenticated_tag.iter().enumerate() {
        if *byte != decrypted_tag[i] {
            return Err(error::Error::Encryption("invalid tag".to_string()));
        }
    }

    Ok(())
}
