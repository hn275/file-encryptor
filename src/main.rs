use std::process;

use clap::Parser;
use command::Command;

mod command;
mod crypto;
mod error;

fn main() -> error::Result<()> {
    let cmd = command::Cli::parse();

    let result = match cmd.action {
        command::Action::Open(dec) => dec.handle(),
        command::Action::Seal(enc) => enc.handle(),
        command::Action::Keygen(k) => k.handle(),
    };

    if let Err(err) = &result {
        eprintln!("{}", err.to_string());
        process::exit(err.status_code().into());
    }

    Ok(())
}
