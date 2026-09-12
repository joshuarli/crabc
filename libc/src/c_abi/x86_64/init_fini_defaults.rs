//! Inert weak libc defaults, distinct from the executable's strong CRT hooks.
//!
//! musl 1.2.6 (MIT), revision 9fa28ece75d8a2191de7c5bb53bed224c5947417:
//! src/env/__libc_start_main.c::dummy/_init and src/exit/exit.c::dummy/_fini.
//! Constructors and finalizers belong to CRT/loader lifecycle owners. Calling
//! either libc default directly must not dispatch or repeat that work.

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn _init() {}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn _fini() {}
