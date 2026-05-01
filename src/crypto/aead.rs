use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use thiserror::Error;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("AEAD seal failed")]
    Seal,
    #[error("AEAD open failed (wrong key, tampered ciphertext, or wrong AD)")]
    Open,
}

pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| AeadError::Seal)
}

pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| AeadError::Open)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [7u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let ad = b"associated";
        let pt = b"hello world";
        let ct = seal(&key, &nonce, ad, pt).unwrap();
        let recovered = open(&key, &nonce, ad, &ct).unwrap();
        assert_eq!(&recovered[..], pt);
    }

    #[test]
    fn tampered_ad_fails() {
        let key = [7u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"ad1", b"hello").unwrap();
        assert!(open(&key, &nonce, b"ad2", &ct).is_err());
    }

    #[test]
    fn tampered_ct_fails() {
        let key = [7u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let mut ct = seal(&key, &nonce, b"ad", b"hello").unwrap();
        ct[0] ^= 0x01;
        assert!(open(&key, &nonce, b"ad", &ct).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let nonce = [1u8; NONCE_LEN];
        let ct = seal(&[1u8; KEY_LEN], &nonce, b"", b"hello").unwrap();
        assert!(open(&[2u8; KEY_LEN], &nonce, b"", &ct).is_err());
    }
}
