//! Bounded x86 static GNU secure-environment observation ABI.
//!
//! This leaf exports only GNU secure_getenv. Private static startup caches
//! musl's secure-execution decision from the validated initial auxiliary
//! vector before callbacks; secure mode returns null without inspecting the
//! selected environment, while ordinary mode returns the same borrowed value
//! as super::environment::getenv.
//!
//! Translation provenance is musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license:
//! src/env/secure_getenv.c supplies the cached-security gate over getenv, and
//! src/env/__libc_start_main.c supplies the cache rule in
//! super::startup_security. The sibling super::auxv_observation artifact
//! exclusively owns public raw __getauxval/weak-getauxval; this leaf neither
//! changes nor extends it.
//!
//! This observation does not sanitize descriptors, manage credentials, alter
//! environment entries, create or execute processes, install signals, own a
//! loader, allocate, or provide a general x86 runtime.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 secure environment requires little-endian Linux/x86-64");

use core::{ffi::c_char, ptr};

use super::{environment, startup_security};

/// Return an environment value only when static startup was not secure.
///
/// The returned pointer is borrowed from environment::getenv under that
/// leaf's caller-coordinated mutation/lifetime contract. Secure mode does not
/// inspect name or change errno, matching musl's one-line gate.
#[no_mangle]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    if startup_security::is_secure() {
        ptr::null_mut()
    } else {
        unsafe { environment::getenv(name) }
    }
}
