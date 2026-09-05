//! Pinned-musl TRE records for the owned static Linux/x86-64 regex provider.
//!
//! This is a source-shaped port scaffold, not a second regex implementation.
//! It starts with the exact compiled-TNFA records from musl 1.2.6's
//! `src/regex/tre.h:91-229` (`e734e68decc33b5ee983db12cabcbdd2589c2d16088677228087b0e5dc365cf3`)
//! and the active dynamic compiler/matcher arena from
//! `src/regex/tre-mem.c:53-151` (`4721979ce365a395fd7644335c847a8a97913e87f14348641f7f199b57b93e28`).
//! The parser and both source matching algorithms are deliberately absent
//! until they can consume these records directly.
//!
//! `tre.h` and `tre-mem.c` originated in TRE and carry Ville Laurikari's
//! two-clause BSD license; musl records that they were substantially modified
//! by Rich Felker.  The later `regcomp.c` and `regexec.c` ports must retain
//! this same source and license provenance.  This module exports no `regex.h`
//! entry point by itself and is not selected from `static_c_abi.rs` yet.

mod memory;
mod types;
