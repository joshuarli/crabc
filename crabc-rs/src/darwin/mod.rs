//! The macOS/AArch64 backend: facade operations over Apple's libSystem.
//!
//! libSystem is the only stable kernel boundary on macOS, so every Darwin
//! operation calls a libSystem function declared in [`sys`]. Failures arrive
//! through the thread-local `errno`; each wrapper reads it immediately after
//! the failing call and returns it as a typed [`errno::Errno`] from the same
//! function, so `errno` never crosses a facade boundary.
//!
//! Each submodule implements the target-specific part of one facade module.
//! The facade module re-exports it next to the vocabulary both targets share.

pub(crate) mod errno;
pub(crate) mod fs;
pub(crate) mod io;
pub(crate) mod mm;
pub(crate) mod net;
pub(crate) mod pipe;
pub(crate) mod process;
pub(crate) mod pty;
pub(crate) mod rand;
pub(crate) mod shm;
pub(crate) mod signal;
pub(crate) mod sys;
pub(crate) mod termios;
pub(crate) mod time;
