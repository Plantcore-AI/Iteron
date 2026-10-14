//! Immutable frontend queue contract shared by runtime composition and server adapters.
//! This module has no dependency on the resident server, TCP, CLI or TUI.
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
pub(crate) struct FrontendQueuePolicy {
    submission_entries: usize,
    submission_bytes: usize,
    event_entries: usize,
    cosmetic_overflow: CosmeticOverflow,
    authoritative_overflow: AuthoritativeOverflow,
}

impl FrontendQueuePolicy {
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
                SQ_PRIORITY_CAPACITY,
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
            iteron_tunables::param_integer("cli.app_server.sq_capacity", SQ_CAPACITY),
            sq_byte_capacity(),
            iteron_tunables::param_integer("cli.app_server.eq_capacity", EQ_CAPACITY),
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
                SQ_PRIORITY_CAPACITY,
            )
    }

    pub(crate) fn priority_entries(self) -> usize {
        iteron_tunables::param_integer("cli.app_server.sq_priority_capacity", SQ_PRIORITY_CAPACITY)
    }

    pub(crate) const fn cosmetic_overflow(self) -> CosmeticOverflow {
        self.cosmetic_overflow
    }

    pub(crate) const fn authoritative_overflow(self) -> AuthoritativeOverflow {
        self.authoritative_overflow
    }
}

impl Default for FrontendQueuePolicy {
    fn default() -> Self {
        Self::owner()
    }
}

/// Submission-queue depth.
///
/// Sized for the burst a human can produce with a held key or a paste, not for a backlog: past this
/// the honest answer is "busy", not a longer queue.
pub(crate) const SQ_CAPACITY: usize = 256;

/// Entries reserved for in-turn control. A paste or a burst of future turns may consume every
/// data slot, but can never prevent an interrupt, force-cancel, drain, steer, or approval receipt
/// from reaching the resident actor.
pub(crate) const SQ_PRIORITY_CAPACITY: usize = 16;

/// Conservative heap charge for the envelope, enum/segment storage, channel node and allocator
/// bookkeeping of one submission, before counting its variable-length strings.
///
/// Small control operations use only this charge. Keeping a full queue's worth in reserve means
/// the byte budget never reduces the existing 256-item control burst bound.
pub(crate) const SQ_ENTRY_OVERHEAD_BYTES: usize = 1024;

/// Bytes reserved for a full [`SQ_CAPACITY`] burst of small control operations.
pub(crate) const SQ_CONTROL_RESERVE_BYTES: usize = SQ_CAPACITY * SQ_ENTRY_OVERHEAD_BYTES;

pub(crate) fn sq_control_reserve_bytes() -> usize {
    iteron_tunables::param_integer(
        "cli.app_server.sq_control_reserve_bytes",
        SQ_CONTROL_RESERVE_BYTES,
    )
}

/// Total heap budget for submissions waiting on the in-process SQ.
///
/// This admits one maximum legal multimodal submission (1 MiB text plus 32 MiB of encoded image
/// data), with a full control-queue reserve beside it. The item bound still applies, so a maximum
/// payload plus controls can occupy at most 256 queue slots. Charging the actual text and encoded
/// image lengths prevents 256 maximum payloads from multiplying into a multi-GiB queue.
pub(crate) const SQ_BYTE_CAPACITY: usize = SQ_ENTRY_OVERHEAD_BYTES
    + iteron_protocol::task::MAX_TASK_TEXT_BYTES
    + iteron_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES
    + SQ_CONTROL_RESERVE_BYTES;

pub(crate) fn sq_byte_capacity() -> usize {
    let derived = iteron_tunables::param_integer(
        "cli.app_server.sq_entry_overhead_bytes",
        SQ_ENTRY_OVERHEAD_BYTES,
    )
    .saturating_add(iteron_protocol::task::MAX_TASK_TEXT_BYTES)
    .saturating_add(iteron_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES)
    .saturating_add(sq_control_reserve_bytes());
    iteron_tunables::param_integer("cli.app_server.sq_byte_capacity", derived)
}

/// Event-queue depth.
///
/// Streamed text arrives far faster than a terminal repaints, so this is the elastic that absorbs a
/// burst between frames. It is a bound, not a buffer to be filled: see the drop policy above.
pub(crate) const EQ_CAPACITY: usize = 1024;
