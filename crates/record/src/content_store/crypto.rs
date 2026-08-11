//! Per-blob authenticated encryption. Destroying the separate key is cryptographic erasure.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const MAGIC: &[u8; 8] = b"CORECB01";

pub(super) fn seal(plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut key_bytes = Zeroizing::new([0u8; KEY_BYTES]);
    getrandom::fill(&mut *key_bytes).map_err(|_| CryptoError::Entropy)?;
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::Entropy)?;
    let key =
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &*key_bytes).map_err(|_| CryptoError::Key)?);
    let mut encrypted = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(aad),
        &mut encrypted,
    )
    .map_err(|_| CryptoError::Seal)?;
    let mut envelope = Vec::with_capacity(MAGIC.len() + NONCE_BYTES + encrypted.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&encrypted);
    let retained_key = key_bytes.to_vec();
    Ok((retained_key, envelope))
}

pub(super) fn open(key_bytes: &[u8], envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key_bytes.len() != KEY_BYTES
        || envelope.len() < MAGIC.len() + NONCE_BYTES + AES_256_GCM.tag_len()
        || &envelope[..MAGIC.len()] != MAGIC
    {
        return Err(CryptoError::Envelope);
    }
    let owned_key = Zeroizing::new(key_bytes.to_vec());
    let key =
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &owned_key).map_err(|_| CryptoError::Key)?);
    let nonce_start = MAGIC.len();
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&envelope[nonce_start..nonce_start + NONCE_BYTES]);
    let mut encrypted = envelope[nonce_start + NONCE_BYTES..].to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut encrypted,
        )
        .map_err(|_| CryptoError::Open)?
        .to_vec();
    Ok(plaintext)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CryptoError {
    Entropy,
    Key,
    Envelope,
    Seal,
    Open,
}
