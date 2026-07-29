use anyhow::{Context, Result};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use zeroize::Zeroizing;

const BEARER_TOKEN_BYTES: usize = 32;
const BEARER_TOKEN_HEX_BYTES: usize = BEARER_TOKEN_BYTES * 2;
const MAX_BEARER_TOKEN_INPUT_BYTES: usize = BEARER_TOKEN_HEX_BYTES + 1;

/// A server-scoped capability received from the managing parent, never from process metadata.
///
/// The loopback restriction keeps remote hosts out; this token keeps unrelated local processes
/// from submitting operations to a more privileged Core process. It is intentionally absent from
/// `argv`, environment, ready metadata, errors, and ordinary `Debug` output.
pub(super) struct BearerToken(Zeroizing<[u8; BEARER_TOKEN_BYTES]>);

impl BearerToken {
    fn from_lower_hex(input: &[u8]) -> std::result::Result<Self, &'static str> {
        if input.len() != BEARER_TOKEN_HEX_BYTES {
            return Err("bearer token must contain exactly 64 lowercase hexadecimal bytes");
        }
        let mut decoded = Zeroizing::new([0_u8; BEARER_TOKEN_BYTES]);
        for (index, pair) in input.chunks_exact(2).enumerate() {
            let high = lower_hex_nibble(pair[0])
                .ok_or("bearer token must contain exactly 64 lowercase hexadecimal bytes")?;
            let low = lower_hex_nibble(pair[1])
                .ok_or("bearer token must contain exactly 64 lowercase hexadecimal bytes")?;
            decoded[index] = (high << 4) | low;
        }
        Ok(Self(decoded))
    }

    /// Compare all decoded bytes. Both operands have a fixed length, so no mismatch position
    /// changes the amount of work performed.
    pub(super) fn authorizes(&self, candidate: &Self) -> bool {
        self.0
            .iter()
            .zip(candidate.0.iter())
            .fold(0_u8, |difference, (expected, actual)| {
                difference | (expected ^ actual)
            })
            == 0
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted bearer token>")
    }
}

impl<'de> Deserialize<'de> for BearerToken {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BearerTokenVisitor;

        impl Visitor<'_> for BearerTokenVisitor {
            type Value = BearerToken;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 64-byte lowercase hexadecimal bearer token")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                BearerToken::from_lower_hex(value.as_bytes()).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(BearerTokenVisitor)
    }
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Read exactly one parent-provided token to EOF. The one-byte excess allowance detects an
/// overlong parent without ever allocating in proportion to its input.
pub(super) async fn read_from_stdin() -> Result<BearerToken> {
    tokio::task::spawn_blocking(|| {
        use std::io::Read as _;

        let mut input = Zeroizing::new(Vec::with_capacity(MAX_BEARER_TOKEN_INPUT_BYTES));
        let read_result = std::io::stdin()
            .lock()
            .take(MAX_BEARER_TOKEN_INPUT_BYTES as u64)
            .read_to_end(&mut input);
        if let Err(error) = read_result {
            return Err(error).context("read headless bearer token from stdin");
        }
        BearerToken::from_lower_hex(&input)
            .map_err(anyhow::Error::msg)
            .context("invalid headless bearer token on stdin")
    })
    .await
    .context("headless bearer-token reader task join")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape_debug_and_comparison_do_not_disclose_the_capability() {
        let expected = BearerToken::from_lower_hex(
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        let same = BearerToken::from_lower_hex(
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        let different = BearerToken::from_lower_hex(
            b"100102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        assert!(expected.authorizes(&same));
        assert!(!expected.authorizes(&different));
        let debug = format!("{expected:?}");
        assert_eq!(debug, "<redacted bearer token>");
        assert!(!debug.contains("00010203"));
        assert!(BearerToken::from_lower_hex(b"ABCDEF").is_err());
    }
}
