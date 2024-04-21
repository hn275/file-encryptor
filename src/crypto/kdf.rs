use std::{error::Error, io};

/// the following settings yield a 3 second key derivation time on my machine
/// configure these to whatever, but:
/// https://tobtu.com/minimum-password-settings/
const LOG_N: u8 = 16;
const R: u32 = 3;
const P: u32 = 2;
const KEYLEN: usize = 32;

/// generating key with the given password with kdf "scrypt".
pub fn generate(password: &str, key_buf: &mut [u8; KEYLEN]) -> Result<(), Box<dyn Error>> {
    if password.len() < 8 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password too short. Must be at least 8 characters.",
        )));
    }
    let param = scrypt::Params::new(LOG_N, R, P, KEYLEN)?;
    scrypt::scrypt(password.as_bytes(), &[], &param, key_buf)?;
    Ok(())
}
