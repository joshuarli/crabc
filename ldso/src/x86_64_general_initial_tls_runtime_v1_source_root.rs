#![no_std]
#![cfg_attr(not(test), no_main)]
#![allow(unexpected_cfgs)]

//! Standalone root for the private x86 general-initial TLS RuntimeV1 wire.
//!
//! Direct evidence supplies `crabc_general_initial_graph`,
//! `crabc_general_initial_tls_materialization_v1`, and
//! `crabc_general_loader_libc_tls_runtime_v1` together. Cargo selects the
//! same isolated path with `x86_64-general-initial-tls-runtime-v1-interpreter`.
//! This is not the fixed-graph RuntimeV1 fixture and does not select CRT
//! lifecycle, dlfcn, runtime mapping/unload, worker materialization, or DTV
//! growth.

#[path = "x86_64_initial_graph.rs"]
mod x86_64_initial_graph;
