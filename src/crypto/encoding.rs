pub mod base64 {

    use base64::{self, engine::general_purpose::STANDARD_NO_PAD as b64, Engine};

    /// base64 encoded length from 32 bytes buffer
    pub const ENCODED_LEN_32: usize = 43;

    pub fn encode(
        buf: &mut [u8; ENCODED_LEN_32],
        msg: &[u8],
    ) -> Result<(), base64::EncodeSliceError> {
        b64.encode_slice(msg, buf)?;
        Ok(())
    }
}

pub mod sha256 {
    use crypto::{self, digest::Digest as _, sha2};

    pub fn encode(buf: &mut [u8; 32], data: &[u8]) {
        let mut sha256 = sha2::Sha256::new();
        sha256.input(data);
        sha256.result(buf);
    }

    pub type Digest = [u8; 32];
}
