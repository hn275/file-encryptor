use clap::Parser;
use crate::{error, Exec};

#[derive(Parser, Debug, Clone)]
pub struct Decryptor {
    /// input file
    input_file: String,

    /// (optional) additional authenticated data
    #[arg(short, long)]
    aad: Option<String>,
}

impl Exec for Decryptor {
    fn handle(&self) -> error::Result<()> {
        Ok(())
    }
}
