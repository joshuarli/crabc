//! Owned native x86 dynamic startup and ordinary-exit composition.
//!
//! Scrt1 validates the unchanged 72-byte loader TLS descriptor and the owned
//! lifecycle handoff before calling this six-argument libc ABI. The loader
//! owns FS/TCB/DTV allocation; libc seeds the reserved FS+40 compiler guard
//! and publishes its environment/auxv/security before the CRT invokes preinit,
//! dependency initialization, and main initialization in that order.
//!
//! Ordinary return and exit drain the shared bounded registration owner,
//! then invoke executable finalization and rtld_fini. No fixture callback or
//! success marker participates in this runtime. Worker creation, concurrent
//! registration, recursive exit, and buffered stdio remain unqualified here.

use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicU8, Ordering};
use super::{auxv_observation, environment, errno, immediate_termination, process_exit, startup_security};

const MAX_STARTUP_POINTERS: usize = 1 << 20;
const MAX_AUXV_ENTRIES: usize = 4096;
const AT_NULL: usize = 0;
const AT_RANDOM: usize = 25;
const VACANT: u8 = 0;
const STARTING: u8 = 1;
const READY: u8 = 2;
const EXITING: u8 = 3;

type MainFunction = unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) -> c_int;
type LifecycleFunction = unsafe extern "C" fn();

struct StartupVectors {
    envp: *const *const c_char,
    auxv: *const usize,
    random: *const usize,
}

static PROCESS_STATE: AtomicU8 = AtomicU8::new(VACANT);
static mut EXECUTABLE_FINI: Option<LifecycleFunction> = None;
static mut LOADER_FINI: Option<LifecycleFunction> = None;

/// Compiler guard storage, initialized once from the kernel AT_RANDOM bytes.
/// The x86 compiler reads the matching FS+40 TCB word; libc never reinstalls FS.
#[no_mangle]
pub static mut __stack_chk_guard: usize = 0;

/// Validate delimiter bounds before publishing pointers into the kernel stack.
unsafe fn startup_vectors(argc: c_int, argv: *const *const c_char) -> Option<StartupVectors> {
    let argc = usize::try_from(argc).ok()?;
    if argc > MAX_STARTUP_POINTERS || argv.is_null()
        || !unsafe { core::ptr::read(argv.add(argc)) }.is_null()
    {
        return None;
    }
    let envp = unsafe { argv.add(argc.checked_add(1)?) };
    for index in 0..MAX_STARTUP_POINTERS {
        if unsafe { core::ptr::read(envp.add(index)) }.is_null() {
            let auxv = unsafe { envp.add(index + 1).cast::<usize>() };
            let mut random: *const usize = core::ptr::null();
            for index in 0..MAX_AUXV_ENTRIES {
                let kind = unsafe { core::ptr::read(auxv.add(index * 2)) };
                if kind == AT_NULL {
                    return (!random.is_null()).then_some(StartupVectors { envp, auxv, random });
                }
                let value = unsafe { core::ptr::read(auxv.add(index * 2 + 1)) };
                if kind == AT_RANDOM { random = value as *const usize; }
            }
            return None;
        }
    }
    None
}

/// Enter owned dynamic startup after the CRT's TLS and handoff validation.
///
/// # Safety
/// `argv` must retain the Linux initial stack through its bounded envp/auxv
/// terminators and AT_RANDOM bytes. All callbacks must obey their C ABI and
/// remain mapped through process exit. The caller must be the once-only owned
/// Scrt1 entry with the loader's 64-byte TCB installed, including writable
/// FS+40 guard storage; it must not enter through a foreign/static CRT.
#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: Option<MainFunction>, argc: c_int, argv: *const *const c_char,
    init: Option<LifecycleFunction>, fini: Option<LifecycleFunction>,
    rtld_fini: Option<LifecycleFunction>,
) -> ! {
    let (Some(main), Some(init), Some(fini), Some(rtld_fini)) = (main, init, fini, rtld_fini) else {
        immediate_termination::_Exit(127);
    };
    let Some(vectors) = (unsafe { startup_vectors(argc, argv) }) else {
        immediate_termination::_Exit(127);
    };
    if PROCESS_STATE.compare_exchange(VACANT, STARTING, Ordering::AcqRel, Ordering::Acquire).is_err()
        || unsafe { errno::get_errno() } != 0
    {
        immediate_termination::_Exit(127);
    }
    // Same kernel-entropy copy and second-byte masking as static TLS and
    // musl 1.2.6 src/env/__stack_chk_fail.c; no PRNG or fallback seed.
    let guard = unsafe { core::ptr::read_unaligned(vectors.random) } & !0xff00;
    if guard == 0 { immediate_termination::_Exit(127); }
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(__stack_chk_guard), guard);
        core::arch::asm!("mov qword ptr fs:[40], {guard}", guard = in(reg) guard, options(nostack));
        environment::install_initial(vectors.envp);
        auxv_observation::install_initial(vectors.auxv);
        startup_security::install_initial(vectors.auxv);
        core::ptr::write(core::ptr::addr_of_mut!(EXECUTABLE_FINI), Some(fini));
        core::ptr::write(core::ptr::addr_of_mut!(LOADER_FINI), Some(rtld_fini));
    }
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    if !unsafe { super::prepare(argc, argv) } { immediate_termination::_Exit(127); }
    PROCESS_STATE.store(READY, Ordering::Release);
    unsafe { init() };
    let status = unsafe { main(argc, argv, vectors.envp) };
    unsafe { exit(status) }
}

/// Drain ordinary handlers, executable fini, and loader fini before termination.
///
/// # Safety
/// The selected dynamic startup must have reached READY, and registrations
/// and callbacks must remain valid. Callers must serialize registration/exit;
/// concurrent and recursive exit are not admitted lifecycle operations here.
#[no_mangle]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    if PROCESS_STATE.compare_exchange(READY, EXITING, Ordering::AcqRel, Ordering::Acquire).is_err() {
        immediate_termination::_Exit(status);
    }
    unsafe { process_exit::__funcs_on_exit() };
    let executable = unsafe { core::ptr::replace(core::ptr::addr_of_mut!(EXECUTABLE_FINI), None) };
    if let Some(callback) = executable { unsafe { callback() }; }
    let loader = unsafe { core::ptr::replace(core::ptr::addr_of_mut!(LOADER_FINI), None) };
    if let Some(callback) = loader { unsafe { callback() }; }
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    unsafe { super::flush_on_exit() };
    immediate_termination::_Exit(status)
}
