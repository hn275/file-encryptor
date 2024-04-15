# file-encryptor

A small Rust program designed to encrypt and decrypt files securely using **Advanced Encryption
Standard-Galois/Counter Mode**, or [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode),
encryption with a 256-bit key. It supports password based encryption with (optionally) additional
authenticated data (AAD).

## Use Cases:

You can use this tool for various purposes, leveraging its file encryption and decryption capabilities. Here are some examples:

- **Secure File Transfer**:
  Encrypt sensitive files before transferring them over insecure channels, such as email or USB
  drives. This ensures that even if the transfer is intercepted, the files remain protected.

- **Data Backup**:
  Enhance the security of backup files by encrypting them before storing them in cloud storage or
  external hard drives. This provides an additional layer of protection for sensitive information like financial records or personal documents.

- **Secure File Sharing**:
  Protect your confidential documents or sensitive information when sharing them with trusted
  individuals or colleagues. Encrypting files before sharing ensures that only authorized parties
  can access the data.

- **Software Configuration/Environment Variables**:
  Safely share environment variables or configuration files by encrypting them before committing to
  version control, such as GitHub. Contributors can decrypt the files locally on their machines,
  ensuring secure sharing of sensitive information.

## Build

```sh
$ cargo build --release
```

## Usage

```sh
$ file-encryptor --help
Usage: file-encryptor [OPTIONS] <COMMAND> <INPUT_FILE>

Arguments:
  <COMMAND>
          Possible values:
          - seal: Encrypt a file
          - open: Decrypt a file

  <INPUT_FILE>
          File to encrypt/decrypt

Options:
  -o, --out <OUT>
          Output file

          [default: file-encryptor.out]

  -h, --help
          Print help (see a summary with '-h')
```
