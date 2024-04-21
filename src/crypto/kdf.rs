use crate::crypto::cipher;
use std::io;

const LOG_N: u8 = 16;
const R: u32 = 8;
const P: u32 = 2;

/// https://tobtu.com/minimum-password-settings/
struct Setting {
    log_n: u8,
    r: u32,
    p: u32,
}

impl Setting {
    fn new() -> io::Result<Setting> {
        Ok(Setting::default())
    }
}

impl Default for Setting {
    fn default() -> Self {
        Setting {
            log_n: LOG_N,
            r: R,
            p: P,
        }
    }
}

/// generating key with the given password with kdf "scrypt".
pub fn generate(password: &[u8], key_buf: &mut [u8; cipher::KEY_LEN]) -> io::Result<()> {
    if password.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password too short. Must be at least 8 characters.",
        ));
    }

    let setting = Setting::new()?;
    let param = scrypt::Params::new(setting.log_n, setting.r, setting.p, cipher::KEY_LEN)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

    scrypt::scrypt(password, &[], &param, key_buf)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}
