#![no_std]
#![cfg_attr(not(test), no_main)]
#![allow(unexpected_cfgs)]

//! Standalone root for the private general initial-graph evidence artifact.
//!
//! The direct-rustc proof supplies `--cfg crabc_general_initial_graph`; Cargo
//! selects the same implementation with its
//! `x86_64-general-initial-interpreter` feature.  The fixed source root stays
//! separate so its historical bounded runner remains a regression fixture.

#[path = "x86_64_initial_graph.rs"]
mod x86_64_initial_graph;
