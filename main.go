package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var ErrHelpCommand = errors.New("")

type Command interface {
	handle() error
}

type Encryptor struct{}
type Decryptor struct{}

type Cli struct {
	command     Command
	fileName    string
	fileNameOut string
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
	fmt.Println(cli)
}

func (enc *Encryptor) handle() error {
	return nil
}

func (dec *Decryptor) handle() error {
	return nil
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
