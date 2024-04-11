use clap::Parser;
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    path::Path,
    process::exit,
};

mod cli;
mod crypto;

trait HandleFile {
    fn handle(self, cli: &cli::CLI);
}

fn main() {
    let cli = cli::CLI::parse();
    match cli.command {
        cli::Command::Open => open_file(cli),
        cli::Command::Seal => seal_file(cli),
    };
}

fn open_file(cli: cli::CLI) {}

fn seal_file(cli: cli::CLI) {
    // read input file
    let input_file = Path::new(&cli.file_name);
    let plaintext = fs::read(&input_file).unwrap_or_else(|err| {
        eprintln!("Failed to read input file:\n{err}");
        exit(1);
    });

    // open output file
    let path = std::path::Path::new(&cli.out);
    let mut output_file_opt = fs::OpenOptions::new();

    if path.exists() {
        let mut overwrite: [u8; 1] = [0];
        print!("{} found. Overwrite? [y/n]: ", &cli.out);
        io::stdout().flush().unwrap();
        let stdin = io::stdin();
        stdin.lock().read(&mut overwrite).unwrap();

        match overwrite == *b"y" {
            true => output_file_opt.truncate(true),
            false => {
                eprintln!("Ouput file exists.");
                exit(1);
            }
        };
    } else {
        output_file_opt.create_new(true);
    }

    let mut output_file = output_file_opt.write(true).open(&path).unwrap();

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
    let mut key: crypto::Key = [0; 32];
    crypto::Encoding::sha256(&mut key, password.as_bytes());
    let block = crypto::Encryptor::new(key);

    // encrypt data
    let pt_len = plaintext.len();
    let size = pt_len + block.overhead(pt_len) + crypto::IV_SIZE;
    let mut ciphertext: Vec<u8> = crypto::make_buffer(size);
    block
        .encrypt(plaintext.as_slice(), &mut ciphertext)
        .unwrap_or_else(|err| {
            eprintln!("Failed to encrypt file:\n{}", err);
            exit(1);
        });

    // write to output file
    let c = crypto::Encoding::base64(ciphertext.as_slice());
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
