use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

use clap::Parser;

use crate::crypto::block::Block;

#[derive(Parser, Debug, Clone)]
pub struct FileArg {
    /// (optional) input file, read from stdin by default
    #[arg(short, long)]
    pub input_file: Option<String>,

    /// (optional) output file, write to stdout by default
    #[arg(short, long)]
    pub output_file: Option<String>,

    /// (optional) additional authenticated data
    #[arg(short, long)]
    pub aad: Option<String>,

    /// (optional) key file, read (the first) 32 byte from stdin by default
    #[arg(short, long)]
    pub key: Option<String>,
}

pub struct IO {
    filein: Option<File>,
    fileout: Option<File>,
}

impl IO {
    pub fn new(filein: &Option<String>, fileout: &Option<String>) -> std::io::Result<Self> {
        let filein = if let Some(filename) = filein {
            Some(OpenOptions::new().read(true).open(filename)?)
        } else {
            None
        };

        let fileout = if let Some(filename) = fileout {
            Some(
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(filename)?,
            )
        } else {
            None
        };

        Ok(Self { filein, fileout })
    }

    pub fn read_block(&mut self, block: &mut Block) -> std::io::Result<usize> {
        match &mut self.filein {
            None => std::io::stdin().read(block.bytes_mut()),
            Some(fd) => fd.read(block.bytes_mut()),
        }
    }

    pub fn write_block(&mut self, block: &Block, n: usize) -> std::io::Result<usize> {
        match &mut self.fileout {
            None => std::io::stdout().write(&block.bytes()[..n]),
            Some(fd) => fd.write(&block.bytes()[..n]),
        }
    }
}
