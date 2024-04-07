# file-encryptor

A small Go script designed to encrypt and decrypt files securely.

## Features

- Utilizes the [Serpent](<https://en.wikipedia.org/wiki/Serpent_(cipher)>)
  symmetric key block cipher with [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
  operation mode for encryption.
- Offers protection against brute-force attacks by using a slower encryption algorithm compared to
  AES.
- Supports password-based encryption and decryption, ensuring that only the same password used for 
  encryption can decrypt the file.

## Why?

Because I sometimes want to share stuff with my friends, but the internet is a scary place.

## Build

```sh
go build .
```

## Usage

```plaintext
Usage: file-encryptor <command> <input> [output]
        command: enc|dec
            enc - encrypt a file
            dec - decrypt a file
        input: input file name
        (optional) output: output file name, default: file.out
```
