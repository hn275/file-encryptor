#!/usr/bin/env bash

action="$1"
file_re="$2"
file_wr="$3"

usage() {
    printf "\nUsage: $0 [seal|open] <input-file> <output-file>\n"
}

# validate files
if [[ ! -f "$file_re" ]]; then
    echo "input file not found: $file_re" 
    usage
    exit 1
fi

if [[ -z "$file_wr" ]]; then
    echo "output file not specified."
    usage
    exit 1
fi

if [[ -f "$file_wr" ]]; then
    read -p "the output file $file_wr exists. Overwrite? [Y/n] " c
    [[ "$c" != "y" && "$c" != "Y" ]] && exit
fi

case $action in
    seal)
        read -s -p "Enter password: " password
        echo ""
        read -s -p "Confirm password: " confirm_password
        [[ $password != $confirm_password ]] && echo "Passwords do not match." && exit
        printf "\n\nPassword OK, encrypting file $file_re\n"
        file-encryptor keygen -p $password | file-encryptor seal $file_re > $file_wr && \
            echo "Done, wrote to $file_wr"
        ;;
    open)
        read -s -p "Enter password: " password
        printf "\n\nDecrypting $file_re\n"
        file-encryptor keygen -p $password | file-encryptor open $file_re > $file_wr && \
            echo "Done, wrote to $file_wr"
        ;;
    *)
        printf "Invalid command: $action\n"
        usage
        ;;
esac
