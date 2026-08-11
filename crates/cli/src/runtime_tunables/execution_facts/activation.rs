//! Historical runtime-activation adapter removed in registry revision 10.
//!
//! These policies now have canonical `Always` or source-driven `Configured` activation. Their
//! production owners are observed by the value/default/constraint adapters, and their physical
//! consumers are gated by the post-checkpoint effective decoders. Keeping a second boolean
//! “tool present” signal here would neither own the value nor prove that the getter consumed it.
