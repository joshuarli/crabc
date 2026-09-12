//! Shared-libc views of the interpreter's debugger rendezvous.
//!
//! musl 1.2.6 ldso/dynlink.c (MIT), revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, exposes an eight-byte pointer
//! and an inert weak breakpoint hook from its combined libc/loader. Here the
//! native loader alone owns r_debug and the existing live link-map chain.
//! Its validated initial relocation transaction fills this slot before main
//! COPY relocations and before any constructor. No static loader is selected.

#[no_mangle]
pub static mut _dl_debug_addr: *mut core::ffi::c_void = core::ptr::null_mut();

// The actual notification address is the loader-local function in r_brk.
// This weak public spelling remains a safe inert call, as musl's default is.
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn _dl_debug_state() {}
