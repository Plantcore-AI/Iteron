//! core-sched — the resilience and overlap layer.
//!
//! Against a rate-limited, heavy-tailed model API, the only honest knob is bounded inflight
//! concurrency (Little's Law), and retries need dual budgets + full-jitter backoff — a single
//! 429/529 must never kill a run (`docs/intake/tail-latency-and-reliability.md`). This crate
//! owns that, plus content-addressed memoization of pure tools (ADR-004: SOUND for pure tools
//! keyed on all determining inputs).
//!
//! What is here: the full-jitter backoff math (unit-tested), a `RetryProvider` that wraps any
//! `Provider` and retries retryable API errors before any stream content is emitted, a
//! bounded-concurrency `Governor`, and a `Memo` for pure-tool results. Speculative prefetch is
//! scoped to local FS/memo only (ADR-004 amendment: no speculative provider calls).

pub mod backoff;
pub mod governor;
pub mod memo;
pub mod retry;

pub use backoff::{BackoffPolicy, full_jitter, is_retryable};
pub use governor::Governor;
pub use memo::Memo;
pub use retry::RetryProvider;
