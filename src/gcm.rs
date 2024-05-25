use crate::constants::{C_SIZE, NONCE_SIZE, ZEROED_BLOCK};
use crate::ctr::Aes256Ctr32;
use crate::error::Error;
use crate::types::{BlockBytes, Bytes, Key, Nonce, Result};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use ghash::universal_hash::UniversalHash;
use ghash::GHash;

#[derive(Clone)]
pub struct GcmGhash {
    ghash: GHash,
    ghash_padding: BlockBytes,
    msg_buffer: BlockBytes,
    msg_buffer_offset: usize,
    ad_len: usize,
    msg_len: usize,
}

impl GcmGhash {
    fn new(
        h: &BlockBytes,
        ghash_padding: BlockBytes,
        associated_data: &Bytes,
    ) -> Result<Self> {
        let mut ghash = GHash::new(h.into());

        ghash.update_padded(associated_data);

        Ok(Self {
            ghash,
            ghash_padding,
            msg_buffer: ZEROED_BLOCK,
            msg_buffer_offset: 0,
            ad_len: associated_data.len(),
            msg_len: 0,
        })
    }

    pub fn update(&mut self, msg: &Bytes) {
        if self.msg_buffer_offset > 0 {
            let taking = std::cmp::min(
                msg.len(),
                C_SIZE - self.msg_buffer_offset,
            );
            self.msg_buffer[self.msg_buffer_offset
                ..self.msg_buffer_offset + taking]
                .copy_from_slice(&msg[..taking]);
            self.msg_buffer_offset += taking;
            assert!(self.msg_buffer_offset <= C_SIZE);

            self.msg_len += taking;

            if self.msg_buffer_offset == C_SIZE {
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
        let full_blocks = msg.len() / C_SIZE;
        let leftover = msg.len() - C_SIZE * full_blocks;
        assert!(leftover < C_SIZE);
        if full_blocks > 0 {
            let blocks = unsafe {
                std::slice::from_raw_parts(
                    msg[..C_SIZE * full_blocks].as_ptr().cast(),
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
            .copy_from_slice(&msg[full_blocks * C_SIZE..]);
        self.msg_buffer_offset = leftover;
        assert!(self.msg_buffer_offset < C_SIZE);
    }

    pub fn finalize(mut self) -> BlockBytes {
        if self.msg_buffer_offset > 0 {
            self.ghash.update_padded(
                &self.msg_buffer[..self.msg_buffer_offset],
            );
        }

        let mut final_block = ZEROED_BLOCK;
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
    let mut h = ZEROED_BLOCK;
    aes256.encrypt_block(GenericArray::from_mut_slice(&mut h));

    let mut ctr = Aes256Ctr32::new(aes256, nonce, 1)?;

    let mut ghash_padding = ZEROED_BLOCK;
    ctr.xor(&mut ghash_padding);

    let ghash = GcmGhash::new(&h, ghash_padding, associated_data)?;
    Ok((ctr, ghash))
}
