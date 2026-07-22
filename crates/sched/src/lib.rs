//! core-sched — the resilience and overlap layer.
//!
//! Against a rate-limited, heavy-tailed model API, the only honest knob is bounded inflight
//! concurrency (Little's Law), and retries need dual budgets + full-jitter backoff — a single
//! 429/529 must never kill a run (`docs/intake/tail-latency-and-reliability.md`). This crate
//! owns those scheduling concerns. Pure-tool memoization lives with the executing tool registry,
//! where effect completion can invalidate cached reads through one authoritative path.
//!
//! What is here: the full-jitter backoff math (unit-tested), a `RetryProvider` that wraps any
//! `Provider` and retries retryable API errors before any stream content is emitted, a
//! bounded-concurrency `Governor`. Speculative overlap is scoped to local tool work only
//! (ADR-004 amendment: no speculative provider calls).

pub mod backoff;
pub mod clock;
pub mod governor;
pub mod retry;

pub use backoff::{BackoffPolicy, full_jitter};
pub use clock::{Clock, TokioClock};
pub use governor::Governor;
pub use retry::RetryProvider;
