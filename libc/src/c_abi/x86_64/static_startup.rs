//! Private static Linux/x86-64 process-startup composition.
//!
//! This leaf is the static-PIE `rcrt1.o` companion for the selected x86
//! archive. It implements the musl-shaped `__libc_start_main` ABI only after
//! [`super::static_tls`] has materialized the final executable's Static Initial TLS v1 image.
//! Its ordinary-exit hooks are deliberately a fixed,
//! process-local block: this is enough to own the CRT-to-libc handoff and the
//! executable's `fini` callback without selecting allocation, stdio,
//! C++-runtime teardown, dynamic-loader finalizers, environment mutation, or
//! a general threaded exit protocol. The sibling `process_globals` leaf owns
//! only publication of the validated program name and option-parser state.
//! Its other selected environment responsibility is to hand the already-
//! validated initial `envp` pointer to [`super::environment`] before
//! application callbacks. The adjacent `auxv_observation` leaf receives the
//! same validated initial auxiliary vector before constructors, but owns only
//! raw tag lookup rather than secure-execution or loader policy. The private
//! adjacent startup_security cache derives the bounded secure_getenv and
//! issetugid decisions from that same validated vector; it does not alter the
//! raw lookup contract.
//!
//! Translation provenance is musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `crt/crt1.c` defines the six-argument startup ABI,
//! `src/env/__libc_start_main.c` owns the startup-to-`main` transition, and
//! `src/exit/atexit.c` plus `src/exit/exit.c` establish LIFO ordinary-exit
//! dispatch. Musl's native startup owns its array walk internally. The
//! selected Rust x86 CRT instead passes already-bounded executable `init` and
//! `fini` callbacks, matching its explicit linker-array ownership in
//! `crt/src/x86_64_startup.rs`; `fini` is registered before application code
//! so application handlers run first in the normal LIFO order.
//!
//! It is not a general x86 libc startup implementation. In particular,
//! `rtld_fini` is rejected because this static-only leaf has no loaded-object
//! graph, `__cxa_finalize` is intentionally a no-op like musl's compatibility
//! entry point, and the fixed registry neither promises concurrent
//! registration nor reentrant-exit semantics.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 static startup requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};

use super::{
    auxv_observation, environment, immediate_termination, posix_exit, process_globals,
    startup_security, static_tls,
};

const MAX_STARTUP_POINTERS: usize = 1 << 20;
const MAX_AUXV_ENTRIES: usize = 4096;
const AT_NULL: usize = 0;

type MainFunction = unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) -> c_int;
type LifecycleFunction = unsafe extern "C" fn();

#[derive(Clone, Copy)]
struct StartupVectors {
    envp: *const *const c_char,
    auxv: *const usize,
}

/// Validate the static CRT's process-vector delimiters and derive envp/auxv.
///
/// The kernel/CRT ABI, not this helper, owns pointer validity through the
/// terminators. The explicit bounds prevent malformed synthetic inputs from
/// turning the delimiter checks into unbounded reads before `main` executes.
unsafe fn startup_vectors(argc: c_int, argv: *const *const c_char) -> Option<StartupVectors> {
    let argc = usize::try_from(argc).ok()?;
    if argc > MAX_STARTUP_POINTERS || argv.is_null() {
        return None;
    }
    // SAFETY: the static CRT ABI promises storage through argv[argc].
    if unsafe { core::ptr::read(argv.add(argc)) }.is_null() {
        let envp = unsafe { argv.add(argc.checked_add(1)?) };
        for index in 0..MAX_STARTUP_POINTERS {
            // SAFETY: a valid kernel startup vector has a terminating envp
            // null; the bound closes malformed input before it can run away.
            if unsafe { core::ptr::read(envp.add(index)) }.is_null() {
                // SAFETY: the validated envp terminator is immediately
                // followed by the kernel auxiliary-vector word pairs.
                let auxv = unsafe { envp.add(index + 1).cast::<usize>() };
                for auxv_index in 0..MAX_AUXV_ENTRIES {
                    // SAFETY: a valid kernel startup vector terminates its
                    // `(tag, value)` pairs with AT_NULL; the explicit bound
                    // closes malformed synthetic input before publication.
                    if unsafe { core::ptr::read(auxv.add(auxv_index * 2)) } == AT_NULL {
                        return Some(StartupVectors { envp, auxv });
                    }
                }
                return None;
            }
        }
    }
    None
}

// Both process compositions retain this one registration implementation;
// static startup continues to own its no-loader exit sequence below.
#[path = "process_exit.rs"]
mod process_exit;
pub use process_exit::{atexit, __cxa_atexit, __cxa_finalize, __funcs_on_exit};

/// Run the fixed ordinary-exit dispatch and terminate the whole process.
#[no_mangle]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    unsafe { __funcs_on_exit() };
    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe { __stdio_exit() };
    posix_exit::_exit(status)
}

#[cold]
#[inline(never)]
fn startup_reject() -> ! {
    immediate_termination::_Exit(127)
}

/// Static-archive fallback for musl's private stack-protector initializer.
///
/// Musl 1.2.6 `src/env/__libc_start_main.c` retains an inert
/// `dummy1(void *)` through `weak_alias(dummy1, __init_ssp)`.  Its separate
/// `src/env/__stack_chk_fail.c` object provides the real strong initializer
/// when static link inputs select stack-protector support.  Preserve only the
/// former archive-binding spelling here, next to the selected static startup
/// owner, so a stronger application or runtime definition can replace it.
///
/// The static TLS bootstrap already initializes the concrete x86 guard from
/// `AT_RANDOM` before any protected code can run, including constructors.
/// `__libc_start_main` does not call this compatibility fallback or reseed the
/// guard after protected frames may have saved it.
/// The ignored pointer therefore has no validity requirement for this inert
/// private static-link boundary.
#[inline(never)]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __init_ssp(_entropy: *mut c_void) {}

/// Owned-static finalization hook, or the private fixture's weak fallback.
///
/// Musl 1.2.6 `src/exit/exit.c` exposes its inert `dummy()` through
/// `weak_alias(dummy, __stdio_exit)`. Its separate `src/stdio/__stdio_exit.c`
/// object supplies the strong stream-finalization body only when that stdio
/// support is linked. Preserve the weak static binding next to this selected
/// startup/ordinary-exit owner so a stronger application or runtime spelling
/// can replace it.
///
/// The private fixture does not call its inert fallback. The owned-static
/// aggregate supplies a strong hook and invokes it after ordinary-exit
/// callbacks, flushing permanent and registry-owned dynamic streams.
///
/// # Safety
/// The caller must be the ordinary-exit owner after callbacks have returned,
/// with no concurrent process finalization or stream destruction. All live
/// streams and caller-supplied setvbuf storage must remain valid until return.
#[inline(never)]
#[no_mangle]
#[cfg_attr(not(feature = "x86-owned-static-runtime"), linkage = "weak")]
pub unsafe extern "C" fn __stdio_exit() {
    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe { super::stdio_standard::flush_all_on_exit() };
}

/// Enter a selected static C application after the real x86 CRT installed TLS.
///
/// This has musl's six-argument binary ABI. Nullable callbacks use Rust's
/// ABI-compatible `Option<extern "C" fn>` representation so a synthetic null
/// main can be rejected before it is called. `rtld_fini` must be null:
/// non-null would imply a dynamic-linker lifetime this static archive
/// intentionally does not own.
#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: Option<MainFunction>,
    argc: c_int,
    argv: *const *const c_char,
    init: Option<LifecycleFunction>,
    fini: Option<LifecycleFunction>,
    rtld_fini: Option<LifecycleFunction>,
) -> ! {
    let Some(vectors) = (unsafe { startup_vectors(argc, argv) }) else {
        startup_reject();
    };
    let Some(main) = main else {
        startup_reject();
    };
    if rtld_fini.is_some() || !static_tls::is_ready() {
        startup_reject();
    }

    // SAFETY: `startup_vectors` validated the kernel/CRT envp and auxiliary
    // vector delimiters before this sole process-wide raw-pointer publication.
    // The adjacent lookup leaf owns no loader or secure-execution policy.
    unsafe { auxv_observation::install_initial(vectors.auxv) };

    // SAFETY: the same validated immutable vector supplies the private musl
    // secure_getenv/issetugid cache. It does not publish or alter raw
    // getauxval state.
    unsafe { startup_security::install_initial(vectors.auxv) };

    // SAFETY: `startup_vectors` validated the kernel/CRT argv/envp
    // delimiters before any libc-visible startup state changes.  The selected
    // x86 environment leaf owns only this initial pointer installation and
    // its bounded later mutation state; it does not widen static startup into
    // a general dynamic loader or process-environment lifecycle.
    unsafe { environment::install_initial(vectors.envp) };

    // All delimiter validation completed above. Publish the process-global
    // aliases before constructors, matching musl's startup ordering without
    // selecting an environment owner or dynamic-loader bridge.
    unsafe { process_globals::install(argc, argv) };

    if fini.is_some() && unsafe { atexit(fini) } != 0 {
        startup_reject();
    }
    if let Some(init) = init {
        unsafe { init() };
    }

    let status = unsafe { main(argc, argv, vectors.envp) };
    unsafe { exit(status) }
}
