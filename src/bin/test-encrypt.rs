use std::{
    fs::OpenOptions,
    io::{Read, Write},
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

use anyhow;

fn main() -> anyhow::Result<()> {
    let mut key = file_encryptor::crypto::cipher::Key::default();
    let mut key_file = std::fs::OpenOptions::new()
        .read(true)
        .open("test-output-key.key")?;

    key_file.read_exact(&mut key)?;
    let key: Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(&key);

    let nonce = file_encryptor::crypto::cipher::Block::default();
    let nonce = Nonce::from_slice(&nonce[..12]);

    let mut plaintext_file = std::fs::OpenOptions::new().read(true).open("LICENSE")?;
    let mut plaintext: Vec<_> = Vec::new();
    plaintext_file.read_to_end(&mut plaintext)?;

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
    OpenOptions::new()
        .create(true)
        .write(true)
        .open("test-output-cipher-libaes_gcm.ciphertext")
        .unwrap()
        .write_all(&ciphertext)
        .unwrap();

    Ok(())
}
