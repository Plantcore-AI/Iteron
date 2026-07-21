//! Fixed-bounded canonical hashing and HMAC-SHA-256 for evolution attestations.

use crate::verifier::VerifierError;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;

const HMAC_BLOCK_BYTES: usize = 64;

pub(crate) fn digest_serialized<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<String, VerifierError> {
    let mut writer = DigestWriter::new(limit);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        return if writer.exceeded {
            Err(VerifierError::CanonicalTooLarge { max: limit })
        } else {
            Err(VerifierError::CanonicalEncoding(error.to_string()))
        };
    }
    Ok(writer.finish())
}

pub(crate) fn hmac_serialized<T: Serialize>(
    key: &[u8],
    value: &T,
    limit: usize,
) -> Result<String, VerifierError> {
    let mut writer = HmacWriter::new(key, limit);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        return if writer.exceeded {
            Err(VerifierError::CanonicalTooLarge { max: limit })
        } else {
            Err(VerifierError::CanonicalEncoding(error.to_string()))
        };
    }
    Ok(writer.finish())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(Sha256::digest(bytes))
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

struct DigestWriter {
    hasher: Sha256,
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl DigestWriter {
    fn new(limit: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            written: 0,
            limit,
            exceeded: false,
        }
    }

    fn finish(self) -> String {
        hex_lower(self.hasher.finalize())
    }
}

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(std::io::Error::other("canonical byte limit exceeded"));
        }
        self.hasher.update(bytes);
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct HmacWriter {
    inner: Sha256,
    outer_pad: [u8; HMAC_BLOCK_BYTES],
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl HmacWriter {
    fn new(key: &[u8], limit: usize) -> Self {
        let mut inner_pad = [0x36; HMAC_BLOCK_BYTES];
        let mut outer_pad = [0x5c; HMAC_BLOCK_BYTES];
        for (index, byte) in key.iter().enumerate() {
            inner_pad[index] ^= byte;
            outer_pad[index] ^= byte;
        }
        let mut inner = Sha256::new();
        inner.update(inner_pad);
        Self {
            inner,
            outer_pad,
            written: 0,
            limit,
            exceeded: false,
        }
    }

    fn finish(self) -> String {
        let inner_digest = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.outer_pad);
        outer.update(inner_digest);
        hex_lower(outer.finalize())
    }
}

impl Write for HmacWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(std::io::Error::other("canonical byte limit exceeded"));
        }
        self.inner.update(bytes);
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn hex_lower(digest: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
