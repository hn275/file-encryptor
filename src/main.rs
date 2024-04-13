use clap::Parser;
use crypto::aesgcm::OVERHEAD;
use std::{
    fs,
    io::{self, Read, Write},
    path, process,
};

mod cli;
mod crypto;

const MINIMUM_KEY_LEN: usize = 8;

fn main() {
    let cli = cli::CLI::parse();

    match cli.command {
        cli::Command::Open => open(cli),
        cli::Command::Seal => seal(cli),
    }
    .unwrap_or_else(|err| match err.kind() {
        io::ErrorKind::AlreadyExists => process::exit(0), // user confirmed, no need for error
        _ => {
            eprintln!("{}", err);
            process::exit(1);
        }
    });
}

fn open(cli: cli::CLI) -> io::Result<()> {
    // check for input and output file existence
    // if output file exist and user does not want to overwrite it, exit
    cli.validate_inout_file()?;

    // open input file, read content into buffer
    let file_len: usize = path::Path::new(&cli.input_file)
        .metadata()?
        .len()
        .try_into()
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to convert file length:\n{}", err),
            )
        })?;

    let mut buf = crypto::make_buffer(file_len);
    fs::OpenOptions::new()
        .read(true)
        .open(&cli.input_file)?
        .read_exact(&mut buf)?;

    // make encryption key
    let password = rpassword::prompt_password(format!(
        "Enter encryption key (minimum {} characters): ",
        MINIMUM_KEY_LEN
    ))?;
    if password.len() < MINIMUM_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Encryption key must be at least must be {} character long.",
                MINIMUM_KEY_LEN
            ),
        ));
    }

    let mut key: [u8; 32] = [0; 32];
    crypto::sha256::encode(&mut key, password.as_bytes());

    // make aad
    let aad: Option<[u8; 32]> = if buf[0] == 0 {
        None
    } else {
        // read `aad`
        let aad_str = rpassword::prompt_password("Enter additional authenticate data (AAD): ")?;
        if aad_str == "" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AAD required, but not provided.",
            ));
        }

        let mut buf = [0 as u8; 32];
        crypto::sha256::encode(&mut buf, aad_str.as_bytes()); // remove the trailing new line
        Some(buf)
    };

    // decrypt
    crypto::aesgcm::Encryptor::new(&key).decrypt(&mut buf, &aad)?;
    return cli.write_out(&buf[OVERHEAD..]);
}

fn seal(cli: cli::CLI) -> io::Result<()> {
    // check for output file existence
    // if exist and user does not want to overwrite it, exit
    cli.validate_inout_file()?;

    // open input file, read content into buffer
    let file_len: usize = path::Path::new(&cli.input_file)
        .metadata()?
        .len()
        .try_into()
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to convert file length:\n{}", err),
            )
        })?;

    let mut buf = crypto::make_buffer(file_len + crypto::aesgcm::OVERHEAD);
    fs::OpenOptions::new()
        .read(true)
        .open(&cli.input_file)?
        .read_exact(&mut buf[crypto::aesgcm::OVERHEAD..])?;

    // make encryption key
    let password = rpassword::prompt_password(format!(
        "Enter encryption key (minimum {} characters): ",
        MINIMUM_KEY_LEN
    ))?;
    if password.len() < MINIMUM_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Encryption key must be at least must be {} character long.",
                MINIMUM_KEY_LEN
            ),
        ));
    }
    let conf_password = rpassword::prompt_password("Confirm encryption key: ")?;
    if password != conf_password {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Failed to confirm encryption key.",
        ));
    }

    let mut key: [u8; 32] = [0; 32];
    crypto::sha256::encode(&mut key, password.as_bytes());

    // read `aad`
    let aad_input = rpassword::prompt_password(
        "Enter additional authenticate data (AAD), leave blank to skip: ",
    )?;
    let aad: Option<[u8; 32]> = if aad_input.len() == 0 {
        None
    } else {
        let mut buf = [0 as u8; 32];
        crypto::sha256::encode(&mut buf, aad_input.as_bytes()); // remove the trailing new line
        Some(buf)
    };

    // encrypt
    crypto::aesgcm::Encryptor::new(&key).encrypt(&mut buf, &aad)?;

    return cli.write_out(&buf);
}
