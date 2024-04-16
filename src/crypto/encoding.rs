pub mod sha256 {
    use crypto::{self, digest::Digest as _, sha2};

    pub fn encode(buf: &mut [u8; 32], data: &[u8]) {
        let mut sha256 = sha2::Sha256::new();
        sha256.input(data);
        sha256.result(buf);
    }

    pub type Digest = [u8; 32];
}
