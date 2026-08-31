//! Private static Linux/x86-64 process-startup composition.
//!
//! This leaf is the static-PIE `rcrt1.o` companion for the selected x86
//! archive. It implements the musl-shaped `__libc_start_main` ABI only after
//! [`super::static_tls`] has materialized the final executable's Static Initial TLS v1 image.
//! Its ordinary-exit hooks are deliberately a fixed,
//! process-local block: this is enough to own the CRT-to-libc handoff and the
//! executable's `fini` callback without selecting allocation, stdio,
//! C++-runtime teardown, dynamic-loader finalizers, a general environment or
//! program-name owner, or a general threaded exit protocol. Its one selected
//! environment responsibility is to hand the already-validated initial
//! `envp` pointer to [`super::environment`] before application callbacks.
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

use super::{environment, immediate_termination, static_tls};

const MAX_STARTUP_POINTERS: usize = 1 << 20;
const ATEXIT_CAPACITY: usize = 32;

type MainFunction = unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) -> c_int;
type ExitFunction = unsafe extern "C" fn(*mut c_void);
type PlainExitFunction = unsafe extern "C" fn();
type LifecycleFunction = unsafe extern "C" fn();

#[derive(Clone, Copy)]
struct StartupVectors {
    envp: *const *const c_char,
}

/// Validate the static CRT's process-vector delimiters and derive `envp`.
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
                return Some(StartupVectors { envp });
            }
        }
    }
    None
}

/// One no-allocation ordinary-exit registration.
///
/// The data is private to the selected static startup path. Registrations
/// occur during single-threaded startup/application setup; broader concurrent
/// and reentrant exit semantics remain outside this artifact's contract.
#[derive(Clone, Copy)]
struct ExitRegistration {
    callback: Option<ExitFunction>,
    argument: *mut c_void,
}

impl ExitRegistration {
    const EMPTY: Self = Self {
        callback: None,
        argument: core::ptr::null_mut(),
    };
}

static mut ATEXIT_REGISTRATIONS: [ExitRegistration; ATEXIT_CAPACITY] =
    [ExitRegistration::EMPTY; ATEXIT_CAPACITY];
static mut ATEXIT_COUNT: usize = 0;
static mut ATEXIT_FINISHED: bool = false;

/// Register a C++-ABI-shaped ordinary-exit callback in the fixed static block.
///
/// The selected static runtime does not own DSO finalization. Its `_dso`
/// parameter is therefore retained only for ABI compatibility with the musl
/// entry point and does not select any DSO-specific semantics.
#[no_mangle]
pub unsafe extern "C" fn __cxa_atexit(
    callback: Option<ExitFunction>,
    argument: *mut c_void,
    _dso: *mut c_void,
) -> c_int {
    if callback.is_none() || unsafe { ATEXIT_FINISHED || ATEXIT_COUNT == ATEXIT_CAPACITY } {
        return -1;
    }
    let count = unsafe { ATEXIT_COUNT };
    // SAFETY: `count` is bounded by the condition above. Function and data
    // pointers share the AMD64 machine-word calling representation used by
    // this musl-compatible ABI boundary.
    unsafe {
        ATEXIT_REGISTRATIONS[count] = ExitRegistration {
            callback,
            argument,
        };
        ATEXIT_COUNT = count + 1;
    }
    0
}

unsafe extern "C" fn invoke_plain_exit(argument: *mut c_void) {
    // SAFETY: `atexit` records only a non-null C ABI no-argument function
    // pointer in this machine-word slot.
    let callback: PlainExitFunction = unsafe { core::mem::transmute(argument) };
    unsafe { callback() };
}

/// Register a C `atexit` callback in the fixed static block.
#[no_mangle]
pub unsafe extern "C" fn atexit(callback: Option<PlainExitFunction>) -> c_int {
    let Some(callback) = callback else {
        return -1;
    };
    unsafe {
        __cxa_atexit(
            Some(invoke_plain_exit),
            core::mem::transmute(callback),
            core::ptr::null_mut(),
        )
    }
}

/// Dispatch registered ordinary-exit callbacks in LIFO order.
///
/// Each entry is cleared before invocation. A normal handler that registers
/// another callback therefore adds it above the current consumed slot and it
/// is selected by the same reverse walk; no callback can be observed twice.
#[no_mangle]
pub unsafe extern "C" fn __funcs_on_exit() {
    loop {
        let registration = unsafe {
            if ATEXIT_COUNT == 0 {
                ATEXIT_FINISHED = true;
                return;
            }
            ATEXIT_COUNT -= 1;
            let index = ATEXIT_COUNT;
            let registration = ATEXIT_REGISTRATIONS[index];
            ATEXIT_REGISTRATIONS[index] = ExitRegistration::EMPTY;
            registration
        };
        if let Some(callback) = registration.callback {
            unsafe { callback(registration.argument) };
        }
    }
}

/// Static compatibility no-op for the C++ ABI finalization entry point.
///
/// Like musl's corresponding entry point, this deliberately leaves ordinary
/// registrations for `exit`'s LIFO dispatch instead of adding DSO filtering.
#[no_mangle]
pub unsafe extern "C" fn __cxa_finalize(_dso: *mut c_void) {}

/// Terminate this process immediately without ordinary-exit callbacks.
#[no_mangle]
pub unsafe extern "C" fn _exit(status: c_int) -> ! {
    immediate_termination::_Exit(status)
}

/// Run the fixed ordinary-exit dispatch and terminate the whole process.
#[no_mangle]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    unsafe { __funcs_on_exit() };
    unsafe { _exit(status) }
}

#[cold]
#[inline(never)]
fn startup_reject() -> ! {
    immediate_termination::_Exit(127)
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

    // SAFETY: `startup_vectors` validated the kernel/CRT argv/envp
    // delimiters before any libc-visible startup state changes.  The selected
    // x86 environment leaf owns only this initial pointer installation and
    // its bounded later mutation state; it does not widen static startup into
    // a general dynamic loader or process-environment lifecycle.
    unsafe { environment::install_initial(vectors.envp) };

    if fini.is_some() && unsafe { atexit(fini) } != 0 {
        startup_reject();
    }
    if let Some(init) = init {
        unsafe { init() };
    }

    let status = unsafe { main(argc, argv, vectors.envp) };
    unsafe { exit(status) }
}
