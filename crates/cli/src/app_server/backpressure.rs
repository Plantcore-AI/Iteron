//! Immutable SQ/EQ owner policy.
//!
//! Capacities are decoded from the run checkpoint before the resident actor is wired.  The
//! frontend cannot silently construct a second queue with current-binary defaults on resume.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) enum CosmeticOverflow {
    Drop,
    Coalesce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) enum AuthoritativeOverflow {
    Wait,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) struct AppServerQueuePolicy {
    submission_entries: usize,
    submission_bytes: usize,
    event_entries: usize,
    cosmetic_overflow: CosmeticOverflow,
    authoritative_overflow: AuthoritativeOverflow,
}

impl AppServerQueuePolicy {
    pub(crate) fn new(
        submission_entries: usize,
        submission_bytes: usize,
        event_entries: usize,
        cosmetic_overflow: CosmeticOverflow,
        authoritative_overflow: AuthoritativeOverflow,
    ) -> Result<Self, &'static str> {
        if submission_entries
            <= iteron_tunables::param_integer(
                "cli.app_server.sq_priority_capacity",
                super::SQ_PRIORITY_CAPACITY,
            )
            || submission_entries > 65_536
            || submission_bytes == 0
            || submission_bytes > 268_435_456
            || submission_bytes > u32::MAX as usize
            || event_entries == 0
            || event_entries > 65_536
        {
            return Err("app-server queue policy is outside its bounded owner envelope");
        }
        Ok(Self {
            submission_entries,
            submission_bytes,
            event_entries,
            cosmetic_overflow,
            authoritative_overflow,
        })
    }

    pub(crate) fn owner() -> Self {
        Self::new(
            iteron_tunables::param_integer("cli.app_server.sq_capacity", super::SQ_CAPACITY),
            super::sq_byte_capacity(),
            iteron_tunables::param_integer("cli.app_server.eq_capacity", super::EQ_CAPACITY),
            CosmeticOverflow::Coalesce,
            AuthoritativeOverflow::Wait,
        )
        .expect("fixed app-server queue policy")
    }

    pub(crate) const fn submission_entries(self) -> usize {
        self.submission_entries
    }

    pub(crate) const fn submission_bytes(self) -> usize {
        self.submission_bytes
    }

    pub(crate) const fn event_entries(self) -> usize {
        self.event_entries
    }

    pub(crate) fn data_entries(self) -> usize {
        self.submission_entries
            - iteron_tunables::param_integer(
                "cli.app_server.sq_priority_capacity",
                super::SQ_PRIORITY_CAPACITY,
            )
    }

    pub(crate) fn priority_entries(self) -> usize {
        iteron_tunables::param_integer(
            "cli.app_server.sq_priority_capacity",
            super::SQ_PRIORITY_CAPACITY,
        )
    }

    pub(crate) const fn cosmetic_overflow(self) -> CosmeticOverflow {
        self.cosmetic_overflow
    }

    pub(crate) const fn authoritative_overflow(self) -> AuthoritativeOverflow {
        self.authoritative_overflow
    }
}

impl Default for AppServerQueuePolicy {
    fn default() -> Self {
        Self::owner()
    }
}
