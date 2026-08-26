//! The deliberately narrow Linux/x86-64 event facade.
//!
//! This target presently admits only the scalar `eventfd2` counter seam.
//! Poll, ppoll, pselect, epoll, signalfd, and their kernel record layouts
//! remain absent until each has independent x86-64 ABI evidence.

pub use crate::eventfd::{EventfdFlags, eventfd, eventfd_read, eventfd_write};
