test:
	cargo build --release
	./target/release/file-encryptor seal -k test-output-key -i test-input.txt -a "haln_01@proton.me" -o test-output.ciphertext
	./target/release/file-encryptor open -k test-output-key -i test-output.ciphertext -a "haln_01@proton.me"  -o test-output.plaintext
	diff test-output.plaintext test-input.txt
