#![no_std]
#![no_main]
#![allow(unexpected_cfgs)]

//! Standalone source root retained for the original fixed-graph artifact.
//!
//! The companion private Cargo target imports the same implementation through
//! `ldso/src/lib.rs`. Keeping this tiny root lets the original direct-rustc
//! proof retain its no_std/no_main contract without making those crate-level
//! attributes leak into the feature-gated `crabc-ldso` target root.

#[path = "x86_64_initial_graph.rs"]
mod x86_64_initial_graph;
