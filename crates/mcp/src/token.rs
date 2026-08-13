//! Bearer-token lifecycle: when a credential is usable, when it must be refreshed, and what a
//! caller is allowed to learn about it.
//!
//! Three properties, and each one fails silently in the direction that looks like it worked.
//!
//! **A token is refreshed before it expires, not after it fails.** Waiting for a 401 means every
//! expiry costs a wasted request, and the retry it triggers is indistinguishable from a real auth
//! failure -- so a genuinely revoked credential and a merely stale one produce the same symptom at
//! the same moment, which is exactly when an operator needs them separated.
//!
//! **Expiry is judged against a skew margin.** A token that expires in 200 ms is not usable: the
//! request has to be built, sent, and received, and the server's clock is not this clock. Treating
//! "not yet expired" as "usable" turns a clock difference into an intermittent auth failure that
//! reproduces on nobody's machine.
//!
//! **The secret is not in `Debug`, `Display`, or any error.** A credential that reaches a log has
//! left the process, and the usual way it happens is a struct derived `Debug` and printed in a
//! diagnostic nobody thought about. This type therefore cannot be printed at all; only its
//! *state* can.

/// How long before nominal expiry a token stops being offered for use.
///
/// Covers request build/flight time plus clock disagreement with the authorization server. Thirty
/// seconds is deliberately generous: the cost of refreshing early is one extra refresh, and the
/// cost of refreshing late is a failed request that looks like a revocation.
pub const EXPIRY_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("token has expired or is inside the {skew}s refresh margin")]
    Expired { skew: u64 },
    #[error("token was revoked and must not be reused")]
    Revoked,
    #[error("no credential has been obtained yet")]
    Absent,
}

/// What a caller may know about a credential without holding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Absent,
    /// Usable now.
    Fresh,
    /// Still nominally valid but inside the skew margin: refresh before the next request.
    Stale,
    Expired,
    Revoked,
}

/// A bearer credential.
///
/// Deliberately implements neither `Debug` nor `Display`. The compiler then refuses the most common
/// way a secret escapes -- interpolating a struct into a log line -- rather than relying on every
/// future caller to remember. [`Token::state`] exists so diagnostics stay possible without the
/// secret being printable.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    secret: String,
    /// Absolute expiry in the caller's monotonic-seconds domain.
    expires_at_secs: u64,
    revoked: bool,
}

impl Token {
    pub fn new(secret: impl Into<String>, expires_at_secs: u64) -> Self {
        Self {
            secret: secret.into(),
            expires_at_secs,
            revoked: false,
        }
    }

    /// From an OAuth `expires_in`, which is a duration rather than an instant.
    ///
    /// Saturating: a server claiming a century-long lifetime must not wrap the deadline into the
    /// past, which would present a fresh token as permanently expired.
    pub fn from_expires_in(secret: impl Into<String>, now_secs: u64, expires_in_secs: u64) -> Self {
        Self::new(secret, now_secs.saturating_add(expires_in_secs))
    }

    pub fn state(&self, now_secs: u64) -> State {
        if self.revoked {
            return State::Revoked;
        }
        if now_secs >= self.expires_at_secs {
            return State::Expired;
        }
        if self.expires_at_secs - now_secs
            <= iteron_tunables::param_integer("mcp.token.expiry_skew_secs", EXPIRY_SKEW_SECS)
        {
            return State::Stale;
        }
        State::Fresh
    }

    /// Whether a refresh should be started, without asserting the token is unusable.
    ///
    /// `Stale` is the interesting case: still valid, but a request started now may arrive after
    /// expiry. Refreshing here is what keeps a 401 from ever being the signal.
    pub fn needs_refresh(&self, now_secs: u64) -> bool {
        !matches!(self.state(now_secs), State::Fresh)
    }

    /// Borrow the secret for an outbound request, or refuse with the reason.
    ///
    /// The only way to reach the secret, and it cannot be reached at all once the token is inside
    /// the skew margin -- so a caller cannot accidentally send a credential that will be rejected
    /// in flight and then be unable to tell that outcome from a revocation.
    pub fn authorize(&self, now_secs: u64) -> Result<&str, TokenError> {
        match self.state(now_secs) {
            State::Fresh => Ok(&self.secret),
            State::Revoked => Err(TokenError::Revoked),
            State::Absent => Err(TokenError::Absent),
            State::Stale | State::Expired => Err(TokenError::Expired {
                skew: iteron_tunables::param_integer(
                    "mcp.token.expiry_skew_secs",
                    EXPIRY_SKEW_SECS,
                ),
            }),
        }
    }

    /// Mark revoked. Terminal: a revoked credential is never usable again, even if a later refresh
    /// response would nominally extend it, because the authorization server has already said no.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(expires_at: u64) -> Token {
        Token::new("sk-secret-value", expires_at)
    }

    #[test]
    fn a_token_inside_the_skew_margin_is_refused_before_it_nominally_expires() {
        // The failure this prevents: a request built at T with a token expiring at T+5 arrives
        // after expiry, and the 401 is indistinguishable from a revocation.
        let t = tok(1_000);
        assert_eq!(t.state(1_000 - EXPIRY_SKEW_SECS - 1), State::Fresh);
        assert_eq!(t.state(1_000 - EXPIRY_SKEW_SECS), State::Stale);
        assert_eq!(t.state(999), State::Stale);

        assert!(t.authorize(900).is_ok());
        assert_eq!(
            t.authorize(999),
            Err(TokenError::Expired {
                skew: EXPIRY_SKEW_SECS
            })
        );
    }

    #[test]
    fn refresh_is_signalled_while_the_token_is_still_valid() {
        let t = tok(1_000);
        assert!(!t.needs_refresh(900), "fresh needs no refresh");
        assert!(t.needs_refresh(980), "stale must refresh before it fails");
        assert!(t.needs_refresh(1_100), "expired certainly does");
    }

    #[test]
    fn revocation_is_terminal_and_outranks_a_valid_expiry() {
        let mut t = tok(u64::MAX);
        t.revoke();
        assert_eq!(t.state(0), State::Revoked);
        assert_eq!(t.authorize(0), Err(TokenError::Revoked));
        assert!(t.is_revoked());
    }

    #[test]
    fn a_revoked_token_is_not_rescued_by_a_far_future_expiry() {
        // The authorization server said no; a longer lifetime does not undo that.
        let mut t = Token::from_expires_in("s", 0, u64::MAX);
        t.revoke();
        assert!(matches!(t.authorize(0), Err(TokenError::Revoked)));
    }

    #[test]
    fn an_absurd_expires_in_saturates_instead_of_wrapping_into_the_past() {
        // Wrapping would present a brand-new credential as permanently expired. Saturation is the
        // property under test, not freshness: at `u64::MAX - 5` the saturated deadline is only
        // five seconds away, which is legitimately inside the skew margin, so `Stale` is correct
        // and `Expired` would be the bug.
        let t = Token::from_expires_in("s", u64::MAX - 5, u64::MAX);
        assert_ne!(
            t.state(u64::MAX - 5),
            State::Expired,
            "must not wrap into the past"
        );
        assert_eq!(t.state(u64::MAX - 5), State::Stale);

        // At an ordinary `now`, the same saturated deadline is simply fresh.
        let ordinary = Token::from_expires_in("s", 1_000, u64::MAX);
        assert_eq!(ordinary.state(1_000), State::Fresh);
    }

    #[test]
    fn expiry_exactly_at_now_is_expired_not_fresh() {
        let t = tok(1_000);
        assert_eq!(t.state(1_000), State::Expired);
    }

    #[test]
    fn the_secret_is_reachable_only_through_authorize() {
        let t = tok(10_000);
        assert_eq!(t.authorize(0).unwrap(), "sk-secret-value");
        // And `Token` implements neither Debug nor Display, so it cannot be interpolated into a
        // log line at all -- the compiler enforces what a redaction pass would only mop up after.
        // (If someone derives Debug on it later, this comment is the reason not to.)
    }

    #[test]
    fn errors_never_carry_the_secret() {
        let mut t = tok(0);
        assert!(!format!("{}", t.authorize(1).unwrap_err()).contains("sk-"));
        t.revoke();
        assert!(!format!("{}", t.authorize(1).unwrap_err()).contains("sk-"));
    }
}
