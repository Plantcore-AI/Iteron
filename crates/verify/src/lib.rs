//! core-verify — the verification layer (the crown, as a HYPOTHESIS pending our own
//! V/C/S ablation — ADR-005 amendment).
//!
//! Two things, both from the recon:
//!   1. **Oracle-strength typing (ADR-005 R6):** oracles are ranked, and a WEAK oracle may
//!      never veto. Strong (the repo's real tests, the compiler) may veto; medium (LSP,
//!      regression deltas) may rank; weak (generated tests) contribute evidence only; weakest
//!      (an LLM judge) is advisory. Agentless's own generated verifier is right <1/3 of the
//!      time, so trusting a weak oracle as a gate silently selects wrong patches — designed out.
//!   2. **A verification GATE that does not trust "done":** when the agent claims success, the
//!      harness independently runs the strong oracle. Ground-truth-in-the-loop (Willison,
//!      Anthropic) beats a self-report. This is the single most valuable production behavior in
//!      this crate.
//!
//! The resolve-vs-ceiling gap (did we produce a correct solution and fail to select it) is
//! tracked as the field's most actionable metric — nobody reports it (ADR-005).

pub mod oracle;
pub mod select;

pub use oracle::{Oracle, OracleStrength, TestOracle, Verdict};
pub use select::{Candidate, Selection};
