#![no_std]
#![cfg_attr(not(test), no_main)]
#![allow(unexpected_cfgs)]

//! Standalone root for private x86 general-initial TLS materialization.
//!
//! The direct-rustc evidence supplies both `crabc_general_initial_graph` and
//! `crabc_general_initial_tls_materialization_v1`. Cargo selects the same
//! isolated source path with `x86_64-general-initial-tls-interpreter`. This
//! root is not the fixed RuntimeV1 producer and does not select a dynamic CRT,
//! pthread, `dlopen`, or installed dynamic product.

#[path = "x86_64_initial_graph.rs"]
mod x86_64_initial_graph;
