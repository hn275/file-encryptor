test: seal open
	diff test-input.txt test-output.plaintext

seal:
	cargo run -- seal -k test-output-key -i test-input.txt -a "haln_01@proton.me" -o test-output.ciphertext

open:
	cargo run -- open -k test-output-key -i test-output.ciphertext -a "haln_01@proton.me"  -o test-output.plaintext

.PHONY: test seal open
