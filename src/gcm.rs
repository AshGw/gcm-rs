use crate::constants::{NONCE_SIZE, TAG_SIZE};
use crate::ctr::Aes256Ctr32;
use crate::error::Error;
use crate::types::{Bytes, Key, Nonce, Result};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use ghash::universal_hash::UniversalHash;
use ghash::GHash;

#[derive(Clone)]
pub struct GcmGhash {
    ghash: GHash,
    ghash_padding: [u8; TAG_SIZE],
    msg_buffer: [u8; TAG_SIZE],
    msg_buffer_offset: usize,
    ad_len: usize,
    msg_len: usize,
}

impl GcmGhash {
    fn new(
        h: &[u8; TAG_SIZE],
        ghash_padding: [u8; TAG_SIZE],
        associated_data: &Bytes,
    ) -> Result<Self> {
        let mut ghash = GHash::new(h.into());

        ghash.update_padded(associated_data);

        Ok(Self {
            ghash,
            ghash_padding,
            msg_buffer: [0u8; TAG_SIZE],
            msg_buffer_offset: 0,
            ad_len: associated_data.len(),
            msg_len: 0,
        })
    }

    pub fn update(&mut self, msg: &[u8]) {
        if self.msg_buffer_offset > 0 {
            let taking = std::cmp::min(
                msg.len(),
                TAG_SIZE - self.msg_buffer_offset,
            );
            self.msg_buffer[self.msg_buffer_offset
                ..self.msg_buffer_offset + taking]
                .copy_from_slice(&msg[..taking]);
            self.msg_buffer_offset += taking;
            assert!(self.msg_buffer_offset <= TAG_SIZE);

            self.msg_len += taking;

            if self.msg_buffer_offset == TAG_SIZE {
                self.ghash.update(std::slice::from_ref(
                    ghash::Block::from_slice(&self.msg_buffer),
                ));
                self.msg_buffer_offset = 0;
                return self.update(&msg[taking..]);
            } else {
                return;
            }
        }

        self.msg_len += msg.len();

        assert_eq!(self.msg_buffer_offset, 0);
        let full_blocks = msg.len() / 16;
        let leftover = msg.len() - 16 * full_blocks;
        assert!(leftover < TAG_SIZE);
        if full_blocks > 0 {
            let blocks = unsafe {
                std::slice::from_raw_parts(
                    msg[..16 * full_blocks].as_ptr().cast(),
                    full_blocks,
                )
            };
            assert_eq!(
                std::mem::size_of_val(blocks) + leftover,
                std::mem::size_of_val(msg)
            );
            self.ghash.update(blocks);
        }

        self.msg_buffer[0..leftover]
            .copy_from_slice(&msg[full_blocks * 16..]);
        self.msg_buffer_offset = leftover;
        assert!(self.msg_buffer_offset < TAG_SIZE);
    }

    pub fn finalize(mut self) -> [u8; TAG_SIZE] {
        if self.msg_buffer_offset > 0 {
            self.ghash.update_padded(
                &self.msg_buffer[..self.msg_buffer_offset],
            );
        }

        let mut final_block = [0u8; 16];
        final_block[..8]
            .copy_from_slice(&(8 * self.ad_len as u64).to_be_bytes());
        final_block[8..].copy_from_slice(
            &(8 * self.msg_len as u64).to_be_bytes(),
        );

        self.ghash.update(&[final_block.into()]);
        let mut hash = self.ghash.finalize();

        for (i, b) in hash.iter_mut().enumerate() {
            *b ^= self.ghash_padding[i];
        }

        hash.into()
    }
}

pub fn setup(
    key: &Key,
    nonce: &Nonce,
    associated_data: &Bytes,
) -> Result<(Aes256Ctr32, GcmGhash)> {
    if nonce.len() != NONCE_SIZE {
        return Err(Error::InvalidNonceSize {
            expected_size: NONCE_SIZE,
        });
    }

    let aes256: Aes256 = Aes256::new_from_slice(key)
        .map_err(|_| Error::InvalidKeySize)?;
    let mut h = [0u8; TAG_SIZE];
    aes256.encrypt_block(GenericArray::from_mut_slice(&mut h));

    let mut ctr = Aes256Ctr32::new(aes256, nonce, 1)?;

    let mut ghash_padding = [0u8; 16];
    ctr.xor(&mut ghash_padding);

    let ghash = GcmGhash::new(&h, ghash_padding, associated_data)?;
    Ok((ctr, ghash))
}
