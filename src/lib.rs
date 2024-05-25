pub mod ctr;
pub mod error;
pub mod types;

#[allow(unused_imports)]
use ctr::Aes256Ctr32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_ctr32_encryption_decryption() {
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
