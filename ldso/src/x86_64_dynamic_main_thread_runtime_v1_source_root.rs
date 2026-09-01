#![no_std]
#![cfg_attr(not(test), no_main)]
#![allow(unexpected_cfgs)]

//! Standalone root for the private x86 dynamic-main-thread RuntimeV1 bridge.
//!
//! The root combines the existing arbitrary initial graph, one retained
//! initial TLS generation, and the exact 72-byte RuntimeV1 descriptor with a
//! deliberately small Scrt1 admission. It neither publishes the older owned
//! CRT handoff record nor takes ownership of DSO finalization: the sole new
//! loader rule is the ordinary null weak-owned-record form emitted by the
//! Rust-produced Scrt1.o before that CRT attaches the main-resident consumer.

// Keep this direct source root as explicit as its Cargo feature binding: a
// caller must select the general graph, retained initial-TLS state, exact
// RuntimeV1 record, and the bridge admission together. The shared module
// carries the finer disjointness checks against fixed and owned-CRT siblings.
#[cfg(not(all(
    crabc_general_initial_graph,
    crabc_general_initial_tls_materialization_v1,
    crabc_general_loader_libc_tls_runtime_v1,
    crabc_dynamic_main_thread_runtime_v1,
)))]
compile_error!("dynamic main-thread RuntimeV1 root needs the complete general RuntimeV1 cfg set");

#[path = "x86_64_initial_graph.rs"]
mod x86_64_initial_graph;
