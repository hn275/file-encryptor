use clap::{Parser, ValueEnum};
use std::{
    fs,
    io::{self, Read, Write},
    path,
};

/// A small Rust program to deal with file encryption.
#[derive(Parser, Debug)]
pub struct CLI {
    /// Action to perform on the input file
    #[arg(value_enum)]
    pub action: Action,

    /// Input file
    pub input_file: String,

    /// output file
    #[arg(short, long)]
    pub write: Option<String>,

    /// Key used to perform the ciphering action
    /// TODO: implement this
    #[arg(short, long)]
    pub key: Option<String>,

    /// Receiver of the file, this will be used as authenticated data.
    /// TODO: implement this
    #[arg(short, long)]
    pub receiver: Option<String>,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum Action {
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

        let output_path = if let Some(output_file) = &self.write {
            path::Path::new(output_file)
        } else {
            return Ok(());
        };

        if !output_path.exists() {
            return Ok(());
        }

        let output_file_name = output_path.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid output file name")
        })?;

        print!("{} exists, overwrite? [y/n]: ", output_file_name);
        io::stdout().flush()?;

        let mut user_choice = [0 as u8; 1];
        io::stdin().lock().read(&mut user_choice)?;
        if user_choice != "y".as_bytes() && user_choice != "Y".as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("output file {} found.", output_file_name),
            ));
        }
        return Ok(());
    }

    /// when this function is called, the new file will either be truncated, or created.
    pub fn write_out(&self, output: &[u8]) -> io::Result<()> {
        let output_path = if let Some(output_path) = &self.write {
            path::Path::new(output_path)
        } else {
            io::stdout().lock().write_all(output)?;
            return Ok(());
        };

        let output_file_name = output_path.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid output file path")
        })?;

        let n = fs::OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(&output_path)?
            .write(&output)?;

        println!(
            "
Success, wrote {} bytes to {}",
            n, output_file_name
        );
        return Ok(());
    }
}
