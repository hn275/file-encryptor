use clap::Parser;
use command::Command;
use std::{io, process};

mod command;
mod crypto;

fn main() {
    let cmd = command::CLI::parse();

    match cmd.action {
        command::Action::Open(dec) => dec.handle(),
        command::Action::Seal(enc) => enc.handle(),
        command::Action::Keygen(k) => k.handle(),
    }
    .unwrap_or_else(|err| match err.kind() {
        io::ErrorKind::AlreadyExists => process::exit(0), // user confirmed, no need for error
        _ => {
            eprintln!("{}", err);
            process::exit(1);
        }
    });
}
