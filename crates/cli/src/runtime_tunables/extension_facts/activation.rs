//! Historical runtime-activation adapter removed in registry revision 10.
//!
//! Extension values are now either canonical `Always` policies or are activated by an admitted
//! source (`Configured`). Exact owner values are sampled in `values` and `constraints`; the
//! post-checkpoint `EffectiveExecution`/`EffectiveMcp` consumers provide the executable gate.
