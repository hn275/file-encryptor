use clap::{Parser, ValueEnum};
use std::{
    fs,
    io::{self, Read, Write},
    path,
};

#[derive(Parser, Debug)]
pub struct CLI {
    #[arg(value_enum)]
    pub command: Command,

    /// File to encrypt/decrypt
    pub input_file: String,

    /// output file
    #[arg(short, long, default_value = "file-encryptor.out")]
    pub out: String,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum Command {
    /// Decrypt a file
    Open,

    /// Encrypt a file
    Seal,
}

impl CLI {
    pub fn validate_inout_file(&self) -> io::Result<()> {
        let file_path = path::Path::new(&self.input_file);
        if !file_path.exists() || !file_path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} not found.", &self.input_file),
            ));
        }

        let output_path = path::Path::new(&self.out);

        if !output_path.exists() {
            return Ok(());
        }

        print!("{} exists, overwrite? [y/n]: ", &self.out);
        io::stdout().flush()?;

        let mut user_choice = [0 as u8; 1];
        io::stdin().lock().read(&mut user_choice)?;
        if user_choice != "y".as_bytes() && user_choice != "Y".as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("output file {} found.", &self.out),
            ));
        }
        return Ok(());
    }

    /// when this function is called, the new file will either be truncated, or created.
    pub fn write_out(&self, output: &[u8]) -> io::Result<()> {
        let output_path = path::Path::new(&self.out);
        let n = fs::OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(&output_path)?
            .write(&output)?;

        println!(
            "
Success, wrote {} bytes to {}",
            n, &self.out
        );
        return Ok(());
    }
}
