use crate::crypto::{block::Block, BLOCK_SIZE};

pub fn pad(block: &mut Block, block_size: usize) {
    let block_len = BLOCK_SIZE;
    let pad_value = block_len - block_size;
    let bytes = block.bytes_mut();
    for i in 0..pad_value {
        bytes[block_len - 1 - i] = pad_value as u8;
    }
}

/// returns the number of padding bytes removed
pub fn unpad(block: &mut Block) -> usize {
    let block_len = BLOCK_SIZE;

    let bytes = block.bytes_mut();
    let last_byte = bytes[block_len - 1];

    // check if padding exists
    let mut bytes_padded = 0;
    for i in 0..(last_byte as usize) {
        if bytes[block_len - 1 - i] != last_byte {
            return 0;
        }
        bytes_padded += 1;
    }

    // remove padding
    for i in 0..(last_byte as usize) {
        bytes[block_len - 1 - i] = 0;
    }

    bytes_padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_pad() {
        let mut block = Block::default();
        pad(&mut block, 3);
        for i in 3..16 {
            assert_eq!(block.bytes()[i], 13);
        }

        let mut block = Block::default();
        pad(&mut block, 0);
        for i in 0..16 {
            assert_eq!(block.bytes()[i], 16);
        }
    }

    #[test]
    fn pkcs7_unpad() {
        let mut block = Block::default();
        pad(&mut block, 3);
        let padded_bytes = unpad(&mut block);
        assert_eq!(padded_bytes, BLOCK_SIZE - 3);
        for i in 3..16 {
            assert_eq!(block.bytes()[i], 0);
        }

        let mut block = Block::default();
        pad(&mut block, 0);
        unpad(&mut block);
        for i in 0..16 {
            assert_eq!(block.bytes()[i], 0);
        }
    }
}
