use std::process;

use clap::Parser;
use file_encryptor::{
    command::{self, Exec},
    error,
};

fn main() -> error::Result<()> {
    let cmd = command::Cli::parse();

    let result = match cmd.cmd {
        command::Command::Open(dec) => dec.handle(),
        command::Command::Seal(enc) => enc.handle(),
        command::Command::Keygen(k) => k.handle(),
    };

    if let Err(err) = &result {
        eprintln!("{}", err);
        process::exit(err.status_code().into());
    }

    Ok(())
}
