//! Explicit unset-clock values used by local launch and audit projections.

/// Unix second stamp used when the clock reads before the epoch. Zero resolves no rate card, so
/// a priced run fails closed rather than billing against an invented instant.
pub(crate) const UNIX_SECS_ON_UNUSABLE_CLOCK: u64 = 0;
/// Unix nanosecond component of a generated run id when the clock reads before the epoch. The
/// pid in the same id still separates concurrent runs.
pub(crate) const UNIX_NANOS_ON_UNUSABLE_CLOCK: u128 = 0;
/// Nanosecond component of a fresh run id when no fresh clock was sampled — only reachable on a
/// resume, which does not mint an id at all. The pid still separates concurrent runs.
pub(crate) const RUN_ID_NANOS_WITHOUT_FRESH_CLOCK: u128 = 0;
