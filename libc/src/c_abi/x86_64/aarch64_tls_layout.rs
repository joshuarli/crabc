//! AArch64 TLS variant I: musl 1.2.6 arch/aarch64/pthread_arch.h and
//! src/env/__init_tls.c place the thread record below TP and the image above
//! the 16-byte gap. The image offset preserves the PT_TLS image alignment phase.
//! The dynamic TLS owner must reserve the same cancellation word below TP.

pub(super) const THREAD_RECORD_SIZE: usize = 16;
pub(super) const CANCELLATION_OFFSET_BELOW_TP: usize = 8;
pub(super) const GAP_ABOVE_TP: usize = 16;
