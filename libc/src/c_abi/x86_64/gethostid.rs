//! Selected static Linux/x86-64 `gethostid` C ABI.
//!
//! This leaf owns exactly the historical `long gethostid(void)` spelling. It
//! returns musl's deterministic zero host identifier and has no input, mutable
//! state, syscall, errno, TLS, allocation, configuration-file, namespace, or
//! authority boundary. It is not hostname/domain-name observation or mutation,
//! a host-identity policy, a system-information framework, secure-execution
//! policy, libc.so, a CRT, a loader, a sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl `src/misc/gethostid.c::gethostid` maps
//! directly to [`gethostid`] below. Its complete Linux implementation returns
//! zero rather than reading a host-specific file or kernel state.
//!
//! Linux/x86-64 is LP64, so the public C `long` result is a signed eight-byte
//! scalar returned in `rax` under the System V AMD64 ABI. The literal `0`
//! therefore needs no C ABI translation, runtime seam, or unsafe memory access.

use core::ffi::c_long;

/// Return musl's deterministic historical host identifier.
#[no_mangle]
pub extern "C" fn gethostid() -> c_long {
    0
}
