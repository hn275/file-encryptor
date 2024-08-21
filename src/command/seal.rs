use aes::{cipher::BlockEncrypt, Aes256};
use aes_gcm::KeyInit;

use crate::{
    crypto::{self, block::Block, tag::Tag, Key, BLOCK_SIZE, IV_SIZE},
    error,
    ioutils::{FileArg, IO},
};

pub fn seal(filearg: &FileArg) -> error::Result<()> {
    let mut io = IO::new(&filearg.input_file, &filearg.output_file)?;

    let key = Key::try_from(filearg)?;

    let mut iv = Block::new_iv();

    let aes = Aes256::new(&key.into());

    let mut tag = Tag::new(&aes, &iv);
    if let Some(aad) = &filearg.aad {
        tag.with_aad(aad.as_bytes());
    }

    let mut eof = false;
    #[allow(unused)]
    let mut block_index: u64 = 0;

    io.write_bytes(&iv.bytes()[..IV_SIZE])?;

    loop {
        let mut buf = Block::default();

        let bytes_read = io.read_block(&mut buf)?;
        if bytes_read != BLOCK_SIZE {
            crypto::pkcs7::pad(&mut buf, bytes_read);
            eof = true;
        }

        let mut ctr = iv.next_counter();
        aes.encrypt_block(ctr.bytes_mut().into());

        buf.xor(&ctr);

        tag.update_state(&buf);

        io.write_block(&buf)?;

        if eof {
            break;
        }

        block_index += 1;
    }

    io.write_block(tag.authenticate())?;

    Ok(())
}
