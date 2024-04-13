install:
	cargo build --release
	sudo ln -Pf ./target/release/file-encryptor /usr/local/bin/
