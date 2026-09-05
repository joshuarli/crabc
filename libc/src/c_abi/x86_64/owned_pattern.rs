//! Owned Linux/x86-64 C filename-pattern boundary.
//!
//! This source owner translates pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT; recorded in
//! `compat/upstreams.toml`): `src/regex/fnmatch.c` maps to
//! `owned_fnmatch.rs`, and `src/regex/glob.c` maps to `owned_glob.rs`.
//! It keeps the public `fnmatch`, `glob`, and `globfree` C records distinct
//! from the Rust-only byte matcher/traversal.  The matcher consumes the
//! selected C/POSIX/C.UTF-8 multibyte and wide-classification owners; glob
//! composes the selected C allocator, directory stream, stat, environment,
//! process-identity, and conventional-passwd owners.  It is neither a second
//! allocator, an NSS/provider framework, nor a general locale database.

#[path = "owned_fnmatch.rs"]
mod owned_fnmatch;
#[path = "owned_glob.rs"]
mod owned_glob;
