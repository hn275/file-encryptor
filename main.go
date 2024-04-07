package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/aead/serpent"
	"golang.org/x/term"
)

var (
	base64         = b64.StdEncoding
	binName        = os.Args[0]
	usage   string = fmt.Sprintf(`Usage: %s <command> <input> [output]
        command: enc|dec
            enc - to encrypt a file
            dec - to decrypt a file
        input: input file name
        (optional) output: output file name, default: file.out`, binName)
)

type Command interface {
	handle(f *File) ([]byte, error)
}

type Encryptor struct {
	cipher.AEAD
}
type Decryptor struct {
	cipher.AEAD
}

type File struct {
	fileName    string
	fileNameOut string
	buf         []byte
}

func main() {
	// PARSE COMMAND LINE
	if len(os.Args) != 3 && len(os.Args) != 4 {
		fmt.Printf("Invalid argument(s).\n%s\n", usage)
		os.Exit(1)
	}

	action := os.Args[1]
	if action != "enc" && action != "dec" {
		fmt.Printf("Invalid action.\n%s\n", usage)
		os.Exit(1)
	}

	var file File
	file.fileName = os.Args[2]
	if file.fileName[:2] == "./" {
		file.fileName = file.fileName[2:]
	}

	if len(os.Args) == 4 {
		file.fileNameOut = os.Args[3]
	} else {
		file.fileNameOut = "file.out"
	}

	// READ INPUT FILE
	var err error
	file.buf, err = os.ReadFile(file.fileName)
	if err != nil {
		log.Fatal(err)
	}

	// READ KEY
	fmt.Println("Enter key: ")
	pass, err := term.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}

	if len(pass) < 8 {
		log.Fatal("Password at least 8 characters long.")
	}

	s := sha256.New()
	if _, err := s.Write(pass); err != nil {
		log.Fatal(err)
	}

	block, err := serpent.NewCipher(s.Sum(nil))
	if err != nil {
		log.Fatal(err)
	}

	c, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	// ENCRYPT/DECRYPT
	var cmd Command
	if action == "dec" {
		cmd = &Decryptor{c}
	} else {
		cmd = &Encryptor{c}
	}

	buf, err := cmd.handle(&file)
	if err != nil {
		log.Fatal(err)
	}

	// WRITE OUTPUT FILE
	fileOut, err := os.OpenFile(file.fileNameOut, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer fileOut.Close()

	n, err := fileOut.Write(buf)
	if err != nil {
		log.Fatal(err)
	}

	// OUTPUT STDIN
	opts := "Encryption"
	if action == "dec" {
		opts = "Decryption"
	}
	fmt.Printf("%s ok.\nWrote %d bytes to %s.\n", opts, n, file.fileNameOut)
}

// Encrypts and base64 encodes the content of the file.
func (aead *Encryptor) handle(f *File) ([]byte, error) {
	// nonce
	nonceSize := aead.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// encrypt
	size := nonceSize + len(f.buf) + aead.Overhead()
	ciphertext := make([]byte, nonceSize, size)

	copy(ciphertext[:nonceSize], nonce)
	ciphertext = aead.Seal(ciphertext, nonce, f.buf, nil)

	// base64 encodes
	encoded := make([]byte, base64.EncodedLen(len(ciphertext)))
	base64.Encode(encoded, ciphertext)
	return encoded, nil
}

// Decode base 64 and decrypt content of the file.
func (c *Decryptor) handle(f *File) ([]byte, error) {
	var err error
	// decode base64
	buf := make([]byte, base64.DecodedLen(len(f.buf)))
	if _, err = base64.Decode(buf, f.buf); err != nil {
		return nil, err
	}

	// decrypt
	nonceSize := c.NonceSize()
	nonce := buf[:nonceSize]
	ciphertext := buf[nonceSize:]
	return c.Open(nil, nonce, ciphertext, nil)
}
