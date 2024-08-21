use std::{
    fs::OpenOptions,
    io::{self, Read},
};

use crate::{error, ioutils::FileArg};

pub mod block;
pub mod pkcs7;
pub mod tag;

pub const IV_SIZE: usize = 12;
pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

pub type Key = [u8; KEY_SIZE];

impl TryFrom<&FileArg> for Key {
    type Error = error::Error;

    fn try_from(filearg: &FileArg) -> Result<Self, Self::Error> {
        // reads in key, if `-k` flag is passed, reads from file
        // otherwise reads (the first) 32 bytes from stdin
        Ok(match &filearg.key {
            None => {
                let mut buf = Key::default();
                io::stdin().read_exact(&mut buf).map_err(|err| {
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
        })
    }
}
