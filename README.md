# file-encryptor

A small Rust program designed to encrypt and decrypt files securely using **Advanced Encryption
Standard-Galois/Counter Mode**, or [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode),
with a 256-bit key produced by
[scrypt](https://en.wikipedia.org/wiki/Scrypt) key derivation function (KDF).

## Use Cases

You can use this tool for various purposes, though here are some examples:

- **Secure File Transfer**: Encrypt sensitive files before transferring them over insecure
  channels, such as email or USB drives. (Similar to how data transfer over the internet)

- **Data Backup**: Enhance the security of backup files by encrypting them before storing them in
  cloud storage or external hard drives.

- **Software Configuration/Environment Variables**: Need to share those secrets?
  Encrypt them then commit to version control. Contributors can decrypt the files locally on their
  machine.

## Installation

```sh
cargo install
```

## Usage

By default, all output will simply be written to standard output. I wanted a solution that offers
flexibility for scripting.

### Cookbook

#### 1. Key generation

To encrypt a file, first a key must be generated. For example, we are using the entire text of
Frankenstein in a text file as the cryptographic key, though this may be done with different file
types, since it's all 1's and 0's for computers anyway.

```sh
file-encryptor keygen < frankenstein.txt > secret.key
```

You can also pass in the option `-p` (or `--password`) to generate key from a certain passphrase.

```sh
file-encryptor keygen -p "this is my password" > secret.key
```

- NOTE: The AES256 key, which consists of 32 bytes, is produced with the
  [following configuration](https://tobtu.com/minimum-password-settings/) as parameters for KDF scrypt:
  - $log_2N = 16$
  - $R = 8$
  - $P = 2$

#### 2. Encrypting the file `foo.txt`

To seal (encrypt) a file, say `foo.txt`:

```sh
file-encryptor seal foo.txt < secret.key > foo_ciphered
```

With additional authenticated data:

```sh
file-encryptor seal foo.txt -a "haln_01@proton.me" < secret.key > foo_ciphered
```

#### 3. Decrypting the ciphertext file `foo_ciphered`

To open the `foo_ciphered` file:

```sh
file-encryptor open foo.txt < secret.key > foo-plaintext.txt
```

And if additional authenticated data was used:

```sh
file-encryptor open foo.txt -a "haln_01@proton.me" < secret.key > foo-plaintext.txt
```

### General Usage

```sh
file-encryptor --help
A small Rust program to deal with file encryption

Usage: file-encryptor [OPTIONS] <COMMAND>

Commands:
  keygen  generate a key, from pure random bytes, or from an input password
  open    open an encrypted file
  seal    seal a plaintext file
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```
