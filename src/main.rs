use clap::Parser;
use command::Command;

mod command;
mod crypto;
mod error;

fn main() -> error::Result<()> {
    let cmd = command::CLI::parse();

    match cmd.action {
        command::Action::Open(dec) => dec.handle(),
        command::Action::Seal(enc) => enc.handle(),
        command::Action::Keygen(k) => k.handle(),
    }?;

    Ok(())
}
