//! The configuration model: what a `bx` config repo says, and where it said it.
//!
//! A config repo is a set of **layers**. `bx.toml` is the first, `modules/*.toml`
//! follow in lexicographic filename order, and the account's `local.toml` in the
//! state directory is last. This module discovers and parses them. It does not
//! merge them, resolve a value, or substitute anything: that is entry A3's, and
//! keeping the two apart is what lets a merge be a pure function of the layer
//! files.
//!
//! Documents are read through `toml_edit`'s DOM and never through `serde`.
//! `serde` deserialisation discards the spans [`Origin`] is built from, and the
//! DOM is also what will let a future `bx add` edit a hand-written file without
//! reflowing a byte the user wrote.

pub mod origin;

pub use origin::Origin;
