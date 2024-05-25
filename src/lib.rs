pub mod constants;
pub mod ctr;
pub mod error;
pub mod gcm;
pub mod types;

use crate::constants::TAG_SIZE;
use ctr::Aes256Ctr32;
use error::Error;
use gcm::{setup as setup_gcm, GcmGhash};
use subtle::ConstantTimeEq;
use types::{Bytes, Key, Nonce, Result};

pub struct Aes256GcmEncryption {
    ctr: Aes256Ctr32,
    ghash: GcmGhash,
}

impl Aes256GcmEncryption {
    pub fn new(
        key: &Key,
        nonce: &Nonce,
        associated_data: &Bytes,
    ) -> Result<Self> {
        let (ctr, ghash) = setup_gcm(key, nonce, associated_data)?;
        Ok(Self { ctr, ghash })
    }

    pub fn encrypt(&mut self, buf: &mut Bytes) {
        self.ctr.xor(buf);
        self.ghash.update(buf);
    }

    pub fn compute_tag(self) -> [u8; TAG_SIZE] {
        self.ghash.finalize()
    }
}

pub struct Aes256GcmDecryption {
    ctr: Aes256Ctr32,
    ghash: GcmGhash,
}

impl Aes256GcmDecryption {
    pub fn new(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Self> {
        let (ctr, ghash) = setup_gcm(key, nonce, associated_data)?;
        Ok(Self { ctr, ghash })
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        self.ghash.update(buf);
        self.ctr.xor(buf);
    }

    pub fn verify_tag(self, tag: &[u8]) -> Result<()> {
        if tag.len() != TAG_SIZE {
            return Err(Error::InvalidTag);
        }

        let computed_tag: [u8; 16] = self.ghash.finalize();

        let tag_ok: subtle::Choice = tag.ct_eq(&computed_tag);

        if !bool::from(tag_ok) {
            return Err(Error::InvalidTag);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_encryption_decryption() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let associated_data = b"associated_data";
        let plaintext = b"plaintext";

        let mut encryption =
            Aes256GcmEncryption::new(&key, &nonce, associated_data)
                .unwrap();
        let mut ciphertext = plaintext.to_vec();
        encryption.encrypt(&mut ciphertext);
        let mut decryption =
            Aes256GcmDecryption::new(&key, &nonce, associated_data)
                .unwrap();
        decryption.decrypt(&mut ciphertext);
        assert_eq!(&ciphertext, plaintext);
        let tag = encryption.compute_tag();
        assert!(decryption.verify_tag(&tag).is_ok());
    }

    #[test]
    fn test_aes256_ctr32_encryption_decryption() {
        // Test data
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let init_ctr = 0;
        let plaintext = b"plaintext";

        let mut encryption =
            Aes256Ctr32::from_key(&key, &nonce, init_ctr).unwrap();

        let mut ciphertext = plaintext.to_vec();
        encryption.xor(&mut ciphertext);

        let mut decryption =
            Aes256Ctr32::from_key(&key, &nonce, init_ctr).unwrap();

        decryption.xor(&mut ciphertext);

        assert_eq!(&ciphertext, plaintext);
    }
}
