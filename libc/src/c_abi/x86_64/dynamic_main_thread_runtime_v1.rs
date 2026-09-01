//! Private x86 dynamic-main-thread RuntimeV1 libc startup.
//!
//! This is the deliberately small libc-side half of one real
//! loader -> Scrt1 -> libc startup path. The loader owns the initial TLS
//! image; the cfg-selected Rust Scrt1.o has already checked the main-resident
//! RuntimeV1 observer before it can call this `__libc_start_main`. This module
//! therefore owns only the six-argument transition, one dynamic TLS `errno`
//! observation, executable callbacks, and process termination. It is not a
//! shared libc product, an ordinary-exit implementation, a loader lifecycle,
//! or a thread/runtime expansion.

use core::arch::asm;
use core::ffi::{c_char, c_int};

use super::errno;

const MAX_STARTUP_POINTERS: usize = 1 << 20;
const SYS_WRITE: usize = 1;
const SYS_EXIT_GROUP: usize = 231;

type MainFunction = unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) -> c_int;
type LifecycleFunction = unsafe extern "C" fn();

struct StartupVectors {
    envp: *const *const c_char,
}

unsafe extern "C" {
    /// Fixture-local main-image proof that Scrt1's fini callback ran before
    /// this minimal dynamic runtime returns to the kernel.
    fn __crabc_dynamic_main_thread_runtime_v1_fini_state() -> c_int;
}

/// Derive the bounded `envp` vector from the six-argument C startup ABI.
///
/// The actual kernel stack remains owned by the executable/CRT. This module
/// validates only the two required delimiters before forwarding the original
/// pointers to the application `main` callback.
unsafe fn startup_vectors(argc: c_int, argv: *const *const c_char) -> Option<StartupVectors> {
    let argc = usize::try_from(argc).ok()?;
    if argc > MAX_STARTUP_POINTERS || argv.is_null() {
        return None;
    }
    if !unsafe { core::ptr::read(argv.add(argc)) }.is_null() {
        return None;
    }
    let envp = unsafe { argv.add(argc.checked_add(1)?) };
    for index in 0..MAX_STARTUP_POINTERS {
        if unsafe { core::ptr::read(envp.add(index)) }.is_null() {
            return Some(StartupVectors { envp });
        }
    }
    None
}

/// Enter the minimum private dynamic libc startup after Scrt1 attached V1.
///
/// This deliberately requires the Rust Scrt1 callback shape rather than
/// guessing a foreign dynamic-libc convention. In particular, the owned-CRT
/// record remains absent and `rtld_fini` must be null; this source does not
/// assume or consume a loader finalizer.
#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: Option<MainFunction>,
    argc: c_int,
    argv: *const *const c_char,
    init: Option<LifecycleFunction>,
    fini: Option<LifecycleFunction>,
    rtld_fini: Option<LifecycleFunction>,
) -> ! {
    let Some(main) = main else {
        startup_reject();
    };
    let Some(init) = init else {
        startup_reject();
    };
    let Some(fini) = fini else {
        startup_reject();
    };
    if rtld_fini.is_some() {
        startup_reject();
    }
    let Some(vectors) = (unsafe { startup_vectors(argc, argv) }) else {
        startup_reject();
    };

    // The Rust Scrt1 variant performs the exact descriptor/TLS observation
    // before this function becomes callable. A nonzero slot here would prove
    // an incorrect initial dynamic-TLS image rather than an errno result.
    if unsafe { errno::get_errno() } != 0 {
        startup_reject();
    }

    unsafe { init() };
    let status = unsafe { main(argc, argv, vectors.envp) };
    unsafe { fini() };
    if unsafe { __crabc_dynamic_main_thread_runtime_v1_fini_state() } != 1 {
        startup_reject();
    }
    if status != 0 || raw_write(b"L") != 1 {
        exit_group(126);
    }
    exit_group(0)
}

#[inline(never)]
fn raw_write(bytes: &[u8]) -> isize {
    let result: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") SYS_WRITE => result,
            in("rdi") 1usize,
            in("rsi") bytes.as_ptr(),
            in("rdx") bytes.len(),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(never)]
fn exit_group(status: c_int) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_EXIT_GROUP,
            in("rdi") status as usize,
            options(noreturn, nostack),
        );
    }
}

#[cold]
#[inline(never)]
fn startup_reject() -> ! {
    exit_group(127)
}
