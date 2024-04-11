use clap::Parser;
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    process::exit,
};

mod cli;
mod crypto;

fn main() {
    let cli = cli::CLI::parse();
    match cli.command {
        cli::Command::Open => open(cli),
        cli::Command::Seal => seal(cli),
    };
}

fn open(cli: cli::CLI) {
    // input file handler
    let input_file = Path::new(&cli.file_name);
    let ciphertext = fs::read(&input_file).unwrap_or_else(|err| {
        eprintln!("Failed to read input file:\n{err}");
        exit(1);
    });

    let ciphertext = crypto::encoding::Base64::decode(&ciphertext).unwrap_or_else(|err| {
        eprintln!("Failed to decode input file:\n{}", err);
        exit(1);
    });

    // output file handler
    let mut output_file = make_file_out(&cli.out).unwrap_or_else(|err| {
        eprintln!("Failed to open output file {}:\n{}", &cli.out, err);
        exit(1);
    });

    // read encryption key
    let password = rpassword::prompt_password("Enter encryption key: ").unwrap_or_else(|err| {
        eprintln!("Failed to read encryption key:\n{}", err);
        exit(1);
    });

    // make cipher block
    let mut key: [u8; 32] = [0; 32];
    crypto::Encoding::sha256(&mut key, password.as_bytes());
    let block = crypto::Encryptor::new(&key);
    let plaintext = block.decrypt(&ciphertext).unwrap_or_else(|err| {
        eprintln!("Failed to decrypt data:\n{}", err);
        exit(1);
    });

    println!("{}", std::str::from_utf8(&plaintext).unwrap());
}

fn seal(cli: cli::CLI) {
    // input file handler
    let input_file = Path::new(&cli.file_name);
    let plaintext = fs::read(&input_file).unwrap_or_else(|err| {
        eprintln!("Failed to read input file:\n{err}");
        exit(1);
    });

    // let plaintext = crypto::Encoding::b

    // output file handler
    let mut output_file = make_file_out(&cli.out).unwrap_or_else(|err| {
        eprintln!("Failed to open output file {}:\n{}", &cli.out, err);
        exit(1);
    });

    // read encryption key
    let password = rpassword::prompt_password("Enter encryption key: ").unwrap_or_else(|err| {
        eprintln!("Failed to read encryption key:\n{}", err);
        exit(1);
    });

    let confirm_password =
        rpassword::prompt_password("Confirm encryption key: ").unwrap_or_else(|err| {
            eprintln!("Failed to read encryption key:\n{}", err);
            exit(1);
        });

    if password != confirm_password {
        println!("Failed to confirm encryption key.");
        exit(0);
    }

    // make cipher block
    let mut key: [u8; 32] = [0; 32];
    crypto::Encoding::sha256(&mut key, password.as_bytes());
    let block = crypto::Encryptor::new(&key);

    // encrypt data
    let s: usize = plaintext.len() + crypto::NONCE_LEN + crypto::AUTH_TAG_LEN;
    let mut ciphertext: Vec<u8> = crypto::make_buffer(s);
    block
        .encrypt(plaintext.as_slice(), &mut ciphertext)
        .unwrap_or_else(|err| {
            eprintln!("Failed to encrypt file:\n{}", err);
            exit(1);
        });

    // write out the bytes
    let c = crypto::encoding::Base64::encode(ciphertext.as_slice());
    match output_file.write(c.as_bytes()) {
        Err(err) => {
            eprintln!("Failed to write to output file:\n{}", err)
        }
        Ok(n) => {
            println!(
                "{} encrypted. Wrote {} bytes to output file {}",
                &cli.file_name, n, &cli.out
            )
        }
    };
}

fn make_file_out(file_name: &str) -> io::Result<fs::File> {
    // open output file
    let path = std::path::Path::new(file_name);
    let mut output_file_opt = fs::OpenOptions::new();

    if path.exists() {
        let mut overwrite: [u8; 1] = [0];
        print!("{} found. Overwrite? [y/n]: ", file_name);
        io::stdout().flush()?;

        let stdin = io::stdin();
        stdin.lock().read(&mut overwrite)?;
        match overwrite[0] == b'y' {
            true => output_file_opt.truncate(true),
            false => {
                eprintln!("Ouput file exists.");
                exit(1);
            }
        };
    } else {
        output_file_opt.create_new(true);
    }

    return output_file_opt.write(true).open(&path);
}
