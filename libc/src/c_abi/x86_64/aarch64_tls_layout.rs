//! AArch64 TLS variant I: musl 1.2.6 arch/aarch64/pthread_arch.h and
//! src/env/__init_tls.c place the thread record below TP and the image above
//! the 16-byte gap. The image offset preserves the PT_TLS image alignment phase.
//! musl src/internal/pthread_impl.h places the canary and DTV at the end
//! of the thread record; crabc reserves its cancellation cache before them.

pub(super) const THREAD_RECORD_SIZE: usize = 32;
pub(super) const CANCELLATION_OFFSET_BELOW_TP: usize = 24;
pub(super) const CANARY_OFFSET_BELOW_TP: usize = 16;
pub(super) const DTV_OFFSET_BELOW_TP: usize = 8;
pub(super) const GAP_ABOVE_TP: usize = 16;
