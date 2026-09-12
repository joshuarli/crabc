//! Focused native test root for the private wordexp engine.
//!
//! This imports no selected C ABI root, so Rust's standard test runtime cannot
//! collide with exported libc entry points. The engine's own test module
//! exercises only its deterministic syntax, context, evaluator, and adapters.

#[path = "../../libc/src/c_abi/x86_64/owned_wordexp_engine.rs"]
mod owned_wordexp_engine;
