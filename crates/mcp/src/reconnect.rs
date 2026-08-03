//! Deferred connection, and what a server is allowed to become when it comes back.
//!
//! Two properties, and the second is the one with teeth.
//!
//! **Deferred.** A configured server that is never used should cost nothing. Connecting eagerly at
//! start-up pays a process spawn and a handshake for every server in the config, on every run, to
//! discover tools the turn may never call.
//!
//! **A reconnect must not be a privilege escalation.** The identity a server presented when the
//! operator approved it is the identity it is approved *as*. A process that dies and respawns can
//! come back announcing a different protocol version or a larger tool set -- through an upgrade, a
//! changed `$PATH`, a rewritten config, or a hostile replacement of the binary. Re-approving it
//! silently, because "it is the same server name", grants whatever it now asks for. So identity is
//! recorded at first admission and re-checked on every reconnect, and the check is asymmetric:
//! losing capability is fine, gaining it is not.

use std::collections::BTreeSet;

/// What a server presented at a handshake. Tools are a `BTreeSet` so comparison is order- and
/// duplicate-insensitive: a server that merely reorders its catalogue has not changed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentity {
    pub name: String,
    pub protocol_version: String,
    pub tools: BTreeSet<String>,
}

impl ServerIdentity {
    pub fn new<I, S>(name: &str, protocol_version: &str, tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.to_owned(),
            protocol_version: protocol_version.to_owned(),
            tools: tools.into_iter().map(Into::into).collect(),
        }
    }
}

/// Why a returning server is not the one that was approved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Drift {
    #[error("server name changed from {approved:?} to {presented:?}")]
    NameChanged { approved: String, presented: String },
    #[error(
        "protocol version changed from {approved:?} to {presented:?}; renegotiation must be explicit"
    )]
    ProtocolChanged { approved: String, presented: String },
    #[error("server gained tools that were never approved: {}", .gained.join(", "))]
    ToolsGained { gained: Vec<String> },
}

/// The outcome of re-admitting a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Identical to what was approved.
    Unchanged,
    /// The server came back with strictly fewer tools. Allowed: it can only do less than the
    /// operator approved, so nothing new is being granted. The lost names are reported because a
    /// caller that had a tool and now does not should say so rather than fail mysteriously later.
    Narrowed { lost: Vec<String> },
    /// Refused. The server is not the one that was approved.
    Refused(Drift),
}

impl Admission {
    pub fn is_allowed(&self) -> bool {
        !matches!(self, Admission::Refused(_))
    }
}

/// Compare a returning server against the identity approved at first admission.
///
/// Checked in order of severity: a different name is a different server, a different protocol is a
/// different contract, and only then is the tool set compared. Reporting "gained tools" for a
/// server that is also announcing a different protocol version would describe the least important
/// difference.
pub fn readmit(approved: &ServerIdentity, presented: &ServerIdentity) -> Admission {
    if approved.name != presented.name {
        return Admission::Refused(Drift::NameChanged {
            approved: approved.name.clone(),
            presented: presented.name.clone(),
        });
    }
    if approved.protocol_version != presented.protocol_version {
        return Admission::Refused(Drift::ProtocolChanged {
            approved: approved.protocol_version.clone(),
            presented: presented.protocol_version.clone(),
        });
    }

    let gained: Vec<String> = presented
        .tools
        .difference(&approved.tools)
        .cloned()
        .collect();
    if !gained.is_empty() {
        return Admission::Refused(Drift::ToolsGained { gained });
    }

    let lost: Vec<String> = approved
        .tools
        .difference(&presented.tools)
        .cloned()
        .collect();
    if lost.is_empty() {
        Admission::Unchanged
    } else {
        Admission::Narrowed { lost }
    }
}

/// Where a configured server is in its lifecycle. `Idle` is the resting state: configured, costing
/// nothing, never spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Connecting,
    Ready,
    /// Connection lost; may be retried while budget remains.
    Lost,
    /// Refused re-admission, or out of budget. Terminal — a caller must not keep retrying a server
    /// that was refused on identity grounds, because retrying cannot change the answer.
    Closed,
}

#[derive(Debug, Clone)]
pub struct DeferredServer {
    phase: Phase,
    approved: Option<ServerIdentity>,
    attempts: u32,
    max_attempts: u32,
}

impl DeferredServer {
    /// Configured but not connected. No process, no handshake, no discovery.
    pub fn configured(max_attempts: u32) -> Self {
        Self {
            phase: Phase::Idle,
            approved: None,
            attempts: 0,
            max_attempts,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn approved(&self) -> Option<&ServerIdentity> {
        self.approved.as_ref()
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// A tool call needs this server. Returns whether a connection must be established.
    pub fn needed(&mut self) -> bool {
        match self.phase {
            Phase::Idle | Phase::Lost => {
                self.phase = Phase::Connecting;
                true
            }
            _ => false,
        }
    }

    /// First successful handshake: record the identity this server is approved as.
    pub fn admit(&mut self, presented: ServerIdentity) -> Admission {
        match &self.approved {
            None => {
                self.approved = Some(presented);
                self.phase = Phase::Ready;
                self.attempts = 0;
                Admission::Unchanged
            }
            Some(approved) => {
                let outcome = readmit(approved, &presented);
                match &outcome {
                    Admission::Refused(_) => self.phase = Phase::Closed,
                    _ => {
                        // A narrowed server is still the approved one; record what it can now do so
                        // a later reconnect is compared against reality rather than against a
                        // capability it already lost.
                        self.approved = Some(presented);
                        self.phase = Phase::Ready;
                        self.attempts = 0;
                    }
                }
                outcome
            }
        }
    }

    /// The connection dropped. Reports whether another attempt is permitted.
    pub fn lost(&mut self) -> bool {
        if self.phase == Phase::Closed {
            return false;
        }
        self.attempts += 1;
        if self.attempts >= self.max_attempts {
            self.phase = Phase::Closed;
            false
        } else {
            self.phase = Phase::Lost;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(tools: &[&str]) -> ServerIdentity {
        ServerIdentity::new("files", "2024-11-05", tools.iter().copied())
    }

    #[test]
    fn a_configured_server_costs_nothing_until_a_tool_needs_it() {
        let mut s = DeferredServer::configured(3);
        assert_eq!(s.phase(), Phase::Idle);
        assert!(s.approved().is_none());

        assert!(s.needed(), "first use must ask for a connection");
        assert_eq!(s.phase(), Phase::Connecting);
        assert!(
            !s.needed(),
            "an in-flight connection must not be started twice"
        );
    }

    #[test]
    fn a_server_that_comes_back_with_extra_tools_is_refused() {
        // The escalation this prevents: approved for read, returns offering write.
        let mut s = DeferredServer::configured(3);
        s.needed();
        s.admit(ident(&["read"]));

        s.lost();
        s.needed();
        let outcome = s.admit(ident(&["read", "write"]));
        assert_eq!(
            outcome,
            Admission::Refused(Drift::ToolsGained {
                gained: vec!["write".to_owned()]
            })
        );
        assert_eq!(s.phase(), Phase::Closed, "refusal on identity is terminal");
        assert!(!s.lost(), "a refused server must not be retried");
    }

    #[test]
    fn a_server_that_comes_back_with_fewer_tools_is_allowed_and_says_what_it_lost() {
        // Narrowing grants nothing new, so it is permitted -- but a caller that had `write` and
        // now does not should learn it here, not from a confusing failure later.
        let mut s = DeferredServer::configured(3);
        s.needed();
        s.admit(ident(&["read", "write"]));
        s.lost();
        s.needed();

        assert_eq!(
            s.admit(ident(&["read"])),
            Admission::Narrowed {
                lost: vec!["write".to_owned()]
            }
        );
        assert_eq!(s.phase(), Phase::Ready);
    }

    #[test]
    fn a_narrowed_server_is_compared_against_reality_on_the_next_reconnect() {
        // After losing `write`, regaining it is a gain relative to what it actually offers now.
        let mut s = DeferredServer::configured(5);
        s.needed();
        s.admit(ident(&["read", "write"]));
        s.lost();
        s.needed();
        s.admit(ident(&["read"]));
        s.lost();
        s.needed();

        assert!(matches!(
            s.admit(ident(&["read", "write"])),
            Admission::Refused(Drift::ToolsGained { .. })
        ));
    }

    #[test]
    fn a_reordered_or_duplicated_catalogue_is_not_a_change() {
        let mut s = DeferredServer::configured(3);
        s.needed();
        s.admit(ServerIdentity::new("files", "2024-11-05", ["a", "b"]));
        s.lost();
        s.needed();
        assert_eq!(
            s.admit(ServerIdentity::new("files", "2024-11-05", ["b", "a", "a"])),
            Admission::Unchanged
        );
    }

    #[test]
    fn a_changed_protocol_version_is_refused_before_tools_are_compared() {
        // Reporting "gained tools" for a server also announcing a different contract would name
        // the least important difference.
        let approved = ServerIdentity::new("files", "2024-11-05", ["read"]);
        let presented = ServerIdentity::new("files", "2099-01-01", ["read", "write"]);
        assert_eq!(
            readmit(&approved, &presented),
            Admission::Refused(Drift::ProtocolChanged {
                approved: "2024-11-05".into(),
                presented: "2099-01-01".into(),
            })
        );
    }

    #[test]
    fn a_changed_name_is_refused_first_of_all() {
        let approved = ServerIdentity::new("files", "2024-11-05", ["read"]);
        let presented = ServerIdentity::new("other", "2099-01-01", ["read", "write"]);
        assert!(matches!(
            readmit(&approved, &presented),
            Admission::Refused(Drift::NameChanged { .. })
        ));
    }

    #[test]
    fn reconnect_attempts_are_bounded_and_exhaustion_is_terminal() {
        let mut s = DeferredServer::configured(3);
        s.needed();
        s.admit(ident(&["read"]));

        assert!(s.lost(), "1st loss may retry");
        assert!(s.lost(), "2nd loss may retry");
        assert!(!s.lost(), "3rd loss exhausts the budget");
        assert_eq!(s.phase(), Phase::Closed);
    }

    #[test]
    fn a_successful_readmission_restores_the_retry_budget() {
        // Otherwise a server that drops once a week eventually refuses to reconnect for a reason
        // a week old -- the same rule the LSP session uses.
        let mut s = DeferredServer::configured(3);
        s.needed();
        s.admit(ident(&["read"]));
        s.lost();
        assert_eq!(s.attempts(), 1);

        s.needed();
        s.admit(ident(&["read"]));
        assert_eq!(s.attempts(), 0);
    }

    #[test]
    fn first_admission_records_the_identity_rather_than_comparing_to_nothing() {
        let mut s = DeferredServer::configured(3);
        s.needed();
        assert_eq!(s.admit(ident(&["read"])), Admission::Unchanged);
        assert_eq!(s.approved().unwrap().tools.len(), 1);
        assert_eq!(s.phase(), Phase::Ready);
    }
}
