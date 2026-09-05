#![no_std]
//! Installed main-resident CRT attachment. All ordinary C helpers remain in
//! shared libc; unlike the isolated evidence root this defines no substitutes.
#[path = "loader_tls_runtime_v1.rs"]
mod loader_tls_runtime_v1;
