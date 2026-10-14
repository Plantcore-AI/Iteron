//! Public transport negotiation. Kernel SQ admission remains an exact version gate.
//!
//! An authenticated N-1 observer may read the bounded Product V1 projection. It has no
//! submission or mutation authority, even if a later frame carries the current wire stamp.

use serde::{Deserialize, Serialize};

use crate::PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAccessV1 {
    Control,
    Observe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedClientV1 {
    pub client_version: u32,
    pub access: ClientAccessV1,
}

pub fn negotiate_client_v1(
    client_version: u32,
    observation_only: bool,
) -> Result<NegotiatedClientV1, &'static str> {
    let access = if observation_only {
        ClientAccessV1::Observe
    } else {
        ClientAccessV1::Control
    };
    if client_version == PROTOCOL_VERSION
        || (observation_only && client_version.checked_add(1) == Some(PROTOCOL_VERSION))
    {
        Ok(NegotiatedClientV1 {
            client_version,
            access,
        })
    } else {
        Err("unsupported protocol version for requested client authority")
    }
}

impl NegotiatedClientV1 {
    pub fn accepts_submission(self, frame_version: u32) -> bool {
        self.access == ClientAccessV1::Control && frame_version == PROTOCOL_VERSION
    }

    pub fn accepts_control(self, frame_version: u32, read_only: bool) -> bool {
        frame_version == self.client_version
            && (self.access == ClientAccessV1::Control || read_only)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n_minus_one_observer_cannot_upgrade_authority_with_a_current_frame() {
        let peer = negotiate_client_v1(PROTOCOL_VERSION - 1, true).unwrap();
        assert!(peer.accepts_control(PROTOCOL_VERSION - 1, true));
        assert!(!peer.accepts_control(PROTOCOL_VERSION - 1, false));
        assert!(!peer.accepts_control(PROTOCOL_VERSION, false));
        assert!(!peer.accepts_submission(PROTOCOL_VERSION));
        assert!(negotiate_client_v1(PROTOCOL_VERSION - 1, false).is_err());
    }

    #[test]
    fn unknown_and_older_protocols_fail_closed_even_for_observers() {
        for version in [0, PROTOCOL_VERSION - 2, PROTOCOL_VERSION + 1, u32::MAX] {
            assert!(negotiate_client_v1(version, true).is_err());
        }
        let peer = negotiate_client_v1(PROTOCOL_VERSION, false).unwrap();
        assert!(peer.accepts_submission(PROTOCOL_VERSION));
        assert!(peer.accepts_control(PROTOCOL_VERSION, false));
    }
}
