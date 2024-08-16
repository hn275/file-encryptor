use crate::crypto::cipher;

pub fn pad(block: &mut cipher::Block, block_size: usize) {
    let block_len = block.len();
    let pad_value = block_len - block_size;
    for i in 0..pad_value {
        block[block_len - 1 - i] = pad_value as u8;
    }
}

pub fn unpad(block: &mut cipher::Block) {
    let block_len = block.len();
    let last_byte = block[block_len - 1];

    // check if padding exists
    for i in 0..(last_byte as usize) {
        if block[block_len - 1 - i] != last_byte {
            return;
        }
    }

    // remove padding
    for i in 0..(last_byte as usize) {
        block[block_len - 1 - i] = 0;
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::cipher;

    #[test]
    fn pad() {
        let mut block = cipher::Block::default();
        super::pad(&mut block, 3);
        for i in 3..16 {
            assert_eq!(block[i], 13);
        }

        let mut block = cipher::Block::default();
        super::pad(&mut block, 0);
        for i in 0..16 {
            assert_eq!(block[i], 16);
        }
    }

    #[test]
    fn unpad() {
        let mut block = cipher::Block::default();
        super::pad(&mut block, 3);
        super::unpad(&mut block);
        for i in 3..16 {
            assert_eq!(block[i], 0);
        }

        let mut block = cipher::Block::default();
        super::pad(&mut block, 0);
        super::unpad(&mut block);
        for i in 0..16 {
            assert_eq!(block[i], 0);
        }
    }
}
