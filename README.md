# file-encryptor

A small Rust program to stream and encrypt/decrypt files securely using **Advanced Encryption
Standard-Galois/Counter Mode**, or [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode),
with a 256-bit key produced by
[scrypt](https://en.wikipedia.org/wiki/Scrypt) key derivation function (KDF).

## Usage

I wanted a small cli program that would _stream_ the file, and is flexible enough for
scripting!

Note that the use of additional authenticated data is not supported as of the current version.

### General Usage

```sh
file-encryptor --help
A Rust CLI program that streams files for encryption and decryption

Usage: file-encryptor <COMMAND>

Commands:
  keygen  generate a key, from pure random bytes, or from an input password
  open    open an encrypted file
  seal    seal a plaintext file
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### Cookbook

#### 1. Key generation

To encrypt a file, first a key must be generated. For example, we are using the entire text of
Frankenstein in a text file as the cryptographic key, though this may be done with different file
types, since it's all 1's and 0's for computers anyway.

```sh
file-encryptor keygen < frankenstein.txt > secret.key

# or -i and -o
file-encryptor keygen -i frankenstein.txt -o secret.key

# You can also pass in the option `-p` (or `--password`)
# to generate key from a certain passphrase.
file-encryptor keygen -p "this is my password" > secret.key

# and for all pseudoramdom bytes
file-encryptor keygen -r > secret.key
```

#### 2. Encrypting the file `foo.plaintext`

To seal (encrypt) a file, say `foo.plaintext`:

```sh
# By default, it will read the first 32 bytes from stdin for as the key,
# then the rest as plaintext.
file-encryptor seal < secret.key < foo.plaintext > foo.ciphertext

# Or passing in the file names from cli
file-encryptor seal -k secret.key -i foo.plaintext -o foo.ciphertext
```

#### 3. Decrypting the ciphertext file `foo_ciphered`

To open the `foo.ciphertext` file:

```sh
# By default, it will read the first 32 bytes from stdin for as the key,
# then the rest as ciphertext.
file-encryptor open < secret.key < foo.ciphertext > foo.plaintext.decrypted

# Or passing in the file names from cli
file-encryptor open -k secret.key -i foo.ciphertext -o foo.plaintext.decrypted
```

## Breaking Changes

The key generation schema is different, since `file-encryptor` now also streams the
input key file.
