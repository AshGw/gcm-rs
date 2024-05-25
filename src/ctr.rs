use crate::error::Error;
use crate::types::{Bytes, Key, Nonce, Result};
use aes::cipher::typenum::Unsigned;
use aes::cipher::KeyInit;
use aes::cipher::{InnerIvInit, StreamCipher, StreamCipherSeek};
use aes::Aes256;

use crate::types::CTRInitializer;
pub struct Aes256Ctr32(ctr::Ctr32BE<Aes256>);

const _BLOCK_SIZE: usize =
    <Aes256 as aes::cipher::BlockSizeUser>::BlockSize::USIZE;
const _NONCE_SIZE: usize = _BLOCK_SIZE - 4;

impl Aes256Ctr32 {
    pub fn new(
        algo: Aes256,
        nonce: &Nonce,
        initializer: CTRInitializer,
    ) -> Result<Self> {
        if !is_valid_nonce_size(nonce, _NONCE_SIZE) {
            return Err(Error::InvalidNonceSize {
                expected_size: _NONCE_SIZE,
            });
        }
        let mut _nonce_block = [0u8; _BLOCK_SIZE];
        _nonce_block[0.._NONCE_SIZE].copy_from_slice(nonce);

        let mut ctr = ctr::Ctr32BE::from_core(
            ctr::CtrCore::inner_iv_init(algo, &_nonce_block.into()),
        );
        ctr.seek(_BLOCK_SIZE * (initializer as usize));
        Ok(Self(ctr))
    }

    pub fn from_key(
        key: &Key,
        nonce: &Nonce,
        initializer: CTRInitializer,
    ) -> Result<Self> {
        Self::new(
            Aes256::new_from_slice(key)
                .map_err(|_| Error::InvalidKeySize)?,
            nonce,
            initializer,
        )
    }
    pub fn xor(&mut self, buf: &mut Bytes) {
        self.0.apply_keystream(buf);
    }
}

fn is_valid_nonce_size(nonce: &Nonce, expected_size: usize) -> bool {
    nonce.len() == expected_size
}
