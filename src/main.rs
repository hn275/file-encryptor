use crypto::{digest::Digest, sha2};
use std::{io, process::exit};

fn main() {
    let mut buf: [u8; 32] = [0; 32];
    if let Err(err) = read_password(&mut buf) {
        eprintln!("Failed to create a key: {}", err);
        exit(1);
    }
    dbg!(&buf);
}

fn read_password(buf: &mut [u8; 32]) -> io::Result<()> {
    let pass = rpassword::prompt_password("Enter key: ").unwrap();
    let pass_confirm = rpassword::prompt_password("Confirm key: ").unwrap();
    if pass != pass_confirm {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "password validation failed.",
        ));
    }
    let mut sha256 = sha2::Sha256::new();
    sha256.input(pass.as_bytes());
    sha256.result(buf);
    Ok(())
}
