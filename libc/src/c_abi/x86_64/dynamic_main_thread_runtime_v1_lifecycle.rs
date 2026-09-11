//! Owned native x86 dynamic startup and ordinary-exit composition.
//!
//! Rust-owned Scrt1 validates its unchanged 72-byte main-only descriptor and
//! lifecycle handoff before this six-argument ABI. A conventional musl CRT
//! instead reaches the distinct canonical-libc 88-byte startup snapshot; libc
//! validates that snapshot before errno or any `%fs`-relative access. The
//! loader owns FS/TCB/DTV allocation; libc seeds the reserved FS+40 compiler
//! guard and publishes its environment/auxv/security before the selected
//! lifecycle owner invokes constructors.
//!
//! Ordinary return and exit drain the shared bounded registration owner,
//! then invoke executable finalization and rtld_fini. No fixture callback or
//! success marker participates in this runtime. The shared pthread owner also
//! enters this exit path after the unique final-task transition, preserving
//! cleanup/TSD ordering and loader TLS lifetime when main exits first.
//! Concurrent registration and recursive ordinary exit remain outside this
//! startup owner's caller contract.

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

enum LifecycleOwner {
    Owned {
        executable_init: LifecycleFunction,
        executable_fini: LifecycleFunction,
        loader_fini: LifecycleFunction,
    },
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    Conventional {
        run_initial: LifecycleFunction,
        loader_fini: LifecycleFunction,
    },
}

struct StartupVectors {
    envp: *const *const c_char,
    auxv: *const usize,
    random: *const usize,
}

#[cfg(feature = "x86-owned-dynamic-runtime")]
fn select_lifecycle(
    selection: super::conventional_startup::Selection,
    init: Option<LifecycleFunction>,
    fini: Option<LifecycleFunction>,
    rtld_fini: Option<LifecycleFunction>,
) -> Option<LifecycleOwner> {
    match selection {
        super::conventional_startup::Selection::Conventional(conventional) => {
            // The non-null loader slot, not musl's three dummy callback
            // arguments, selects ordinary CRT ownership.
            Some(LifecycleOwner::Conventional {
                run_initial: conventional.run_initial,
                loader_fini: conventional.process_fini,
            })
        }
        super::conventional_startup::Selection::Owned => {
            // Owned Scrt1 is an explicit lifecycle owner. Its null ordinary
            // slot cannot fall back when any handoff callback is absent.
            let (Some(executable_init), Some(executable_fini), Some(loader_fini)) =
                (init, fini, rtld_fini)
            else {
                return None;
            };
            Some(LifecycleOwner::Owned {
                executable_init,
                executable_fini,
                loader_fini,
            })
        }
    }
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

/// Enter selected dynamic startup after its explicit CRT/loader handoff.
///
/// # Safety
/// `argv` must retain the Linux initial stack through its bounded envp/auxv
/// terminators and AT_RANDOM bytes. All callbacks must obey their C ABI and
/// remain mapped through process exit. The caller is either the once-only
/// owned Scrt1 entry or a conventional musl CRT whose canonical-libc receiver
/// has accepted the loader record before this function reads TLS state.
#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: Option<MainFunction>, argc: c_int, argv: *const *const c_char,
    init: Option<LifecycleFunction>, fini: Option<LifecycleFunction>,
    rtld_fini: Option<LifecycleFunction>,
) -> ! {
    let Some(main) = main else {
        immediate_termination::_Exit(127);
    };
    let Some(vectors) = (unsafe { startup_vectors(argc, argv) }) else {
        immediate_termination::_Exit(127);
    };
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    let lifecycle = match unsafe { super::conventional_startup::select() }
        .and_then(|selection| select_lifecycle(selection, init, fini, rtld_fini))
    {
        Some(lifecycle) => lifecycle,
        None => immediate_termination::_Exit(127),
    };
    #[cfg(not(feature = "x86-owned-dynamic-runtime"))]
    let lifecycle = match rtld_fini {
        Some(loader_fini) => {
            // This source root has no conventional record consumer. Retain
            // the historical owned route's complete callback requirement.
            let (Some(executable_init), Some(executable_fini)) = (init, fini) else {
                immediate_termination::_Exit(127);
            };
            LifecycleOwner::Owned {
                executable_init,
                executable_fini,
                loader_fini,
            }
        }
        None => immediate_termination::_Exit(127),
    };
    if PROCESS_STATE.compare_exchange(VACANT, STARTING, Ordering::AcqRel, Ordering::Acquire).is_err() {
        immediate_termination::_Exit(127);
    }
    // Conventional mode reached this only after its receiver validated the
    // loader-installed TCB/DTV. The owned Scrt1 route retains its established
    // main-only attachment proof before entering this function.
    if unsafe { errno::get_errno() } != 0 {
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
        match lifecycle {
            LifecycleOwner::Owned { executable_fini, loader_fini, .. } => {
                core::ptr::write(core::ptr::addr_of_mut!(EXECUTABLE_FINI), Some(executable_fini));
                core::ptr::write(core::ptr::addr_of_mut!(LOADER_FINI), Some(loader_fini));
            }
            #[cfg(feature = "x86-owned-dynamic-runtime")]
            LifecycleOwner::Conventional { loader_fini, .. } => {
                core::ptr::write(core::ptr::addr_of_mut!(EXECUTABLE_FINI), None);
                core::ptr::write(core::ptr::addr_of_mut!(LOADER_FINI), Some(loader_fini));
            }
        }
    }
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    if !unsafe { super::prepare(argc, argv) } { immediate_termination::_Exit(127); }
    PROCESS_STATE.store(READY, Ordering::Release);
    match lifecycle {
        LifecycleOwner::Owned { executable_init, .. } => unsafe { executable_init() },
        #[cfg(feature = "x86-owned-dynamic-runtime")]
        LifecycleOwner::Conventional { run_initial, .. } => unsafe { run_initial() },
    }
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

#[cfg(all(test, feature = "x86-owned-dynamic-runtime"))]
mod tests {
    use super::*;

    unsafe extern "C" fn first() {}
    unsafe extern "C" fn second() {}
    unsafe extern "C" fn third() {}

    #[test]
    fn nonnull_conventional_slot_ignores_dummy_crt_callbacks() {
        let lifecycle = select_lifecycle(
            super::super::conventional_startup::Selection::Conventional(
                super::super::conventional_startup::Lifecycle {
                    run_initial: first,
                    process_fini: second,
                },
            ),
            None,
            Some(third),
            Some(first),
        )
        .expect("non-null loader slot selects conventional mode");
        assert!(matches!(lifecycle, LifecycleOwner::Conventional { .. }));
    }

    #[test]
    fn null_slot_requires_every_owned_handoff_callback() {
        let rejected = select_lifecycle(
            super::super::conventional_startup::Selection::Owned,
            Some(first),
            None,
            Some(second),
        );
        assert!(rejected.is_none());
    }
}
