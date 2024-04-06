package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/aead/serpent"
	"golang.org/x/term"
)

var (
	ErrHelpCommand = errors.New("")

	base64 = b64.StdEncoding
)

type Command interface {
	handle(cli *Cli) error
}

type Encryptor struct{}
type Decryptor struct{}

type Cli struct {
	command     Command
	fileName    string
	fileNameOut string
}

func main() {
	cli, err := parseCli()
	if err != nil {
		if errors.Is(err, ErrHelpCommand) {
			fmt.Printf("%s\n%s\n", asciiArt, usage)
			os.Exit(0)
		}
		fmt.Printf("%s\nError - %s\n%s\n", asciiArt, err.Error(), usage)
		os.Exit(0)
	}
	fmt.Println(asciiArt)
	if err := cli.command.handle(cli); err != nil {
		log.Fatal(err)
	}
}

func (enc *Encryptor) handle(cli *Cli) error {
	// OPEN FILEBYTES
	fmt.Println("Reading file", cli.fileName)
	fileBytes, err := os.ReadFile(cli.fileName)
	if err != nil {
		return err
	}

	// READ KEY
	fmt.Println("Enter password: ")
	pass, err := term.ReadPassword(0)
	if err != nil {
		return err
	}

	if len(pass) < 8 {
		return errors.New("Password at least 8 characters long.")
	}

	fmt.Print("\nGenerating key from input... ")
	s := sha256.New()
	if _, err := s.Write(pass); err != nil {
		return nil
	}
	key := s.Sum(nil)

	fmt.Print("OK\n")
	// ENCRYPT DATA
	fmt.Print("Encrypting data... ")
	// create new cipher block
	block, err := serpent.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// nonce
	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	// encrypt
	size := nonceSize + len(fileBytes) + gcm.Overhead()
	ciphertext := make([]byte, nonceSize, size)

	copy(ciphertext[:nonceSize], nonce)
	ciphertext = gcm.Seal(ciphertext, nonce, fileBytes, nil)

	fmt.Print("OK\n")

	// WRITE TO FILE
	fmt.Printf("Writing to file [%s]... ", cli.fileNameOut)
	// base64 ciphertext
	buf := make([]byte, base64.EncodedLen(size))
	base64.Encode(buf, ciphertext)

	// create/truncate fileNameOut
	fileOut, err := os.OpenFile(cli.fileNameOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer fileOut.Close()

	// write to file
	n, err := fileOut.Write(buf)
	if err != nil {
		return err
	}
	fmt.Printf("OK, wrote %d bytes.\n", n)
	return nil
}

const asciiArt string = `
  __ _ _                                             _             
 / _(_) | ___        ___ _ __   ___ _ __ _   _ _ __ | |_ ___  _ __ 
| |_| | |/ _ \_____ / _ \ '_ \ / __| '__| | | | '_ \| __/ _ \| '__|
|  _| | |  __/_____|  __/ | | | (__| |  | |_| | |_) | || (_) | |   
|_| |_|_|\___|      \___|_| |_|\___|_|   \__, | .__/ \__\___/|_|   
                                         |___/|_|`

const usage string = `
Usage: file-encryptor <command> <input-file-name> [output-file-name]
       <command> 
           enc                        encrypt a file
           dec                        decrypt a file
           --help | -h                print this help and exit
       <input-file-name>              input file
       [output-file-name] (optional)  output file, default to "out"`

func (dec *Decryptor) handle(cli *Cli) error {
	panic("not implemented")
}

func parseCli() (*Cli, error) {
	if len(os.Args) < 2 {
		return nil, errors.New("Missing command")
	}

	cmd := strings.ToLower(os.Args[1])
	if cmd == "--help" || cmd == "-h" {
		return nil, ErrHelpCommand
	}

	if len(os.Args) < 3 {
		return nil, errors.New("Missing file name")
	}

	fileNameOut := "out"
	if len(os.Args) >= 4 {
		fileNameOut = os.Args[3]
	}

	switch cmd {
	case "enc":
		return &Cli{
			command:     &Encryptor{},
			fileName:    os.Args[2],
			fileNameOut: fileNameOut,
		}, nil

	case "dec":
		return &Cli{
			command:     &Decryptor{},
			fileName:    os.Args[2],
			fileNameOut: fileNameOut,
		}, nil

	default:
		return nil, fmt.Errorf("Unrecognized command: %s", os.Args[1])

	}
}
