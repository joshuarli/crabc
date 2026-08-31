//! Private no-std x86 Rust consumer for the current closed static boundary.
//!
//! This is an executable compiler/link/LTO witness, not a stock-`std`, libc,
//! loader, or sysroot fixture.  The bounded lifecycle owners below exist only
//! because the current private `rcrt1.o` artifact deliberately exposes its
//! libc handoff without selecting a general application runtime.
#![no_main]
#![no_std]

use core::ffi::c_void;

use crabc_core::process::exit_immediately;
use crabc_rs::fd::BorrowedFd;
use crabc_rs::{io, process};

type ApplicationMain = unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type LifecycleHook = unsafe extern "C" fn();

const OK: &[u8] = b"x86-static-pie-lto:ok\n";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_immediately(101)
}

// The pinned toolchain's prebuilt `core` archive names this Rust ABI entry by
// its v0 symbol. The linker-plugin bitcode compile sees that archive only at
// the later closed LLD step, so retain and globalize this exact pinned symbol
// instead of admitting a panic-runtime archive. The language item itself must
// keep the compiler-assigned name; rustc rejects `no_mangle` on it.
#[used]
static KEEP_PANIC_HANDLER: fn(&core::panic::PanicInfo<'_>) -> ! = panic;
core::arch::global_asm!(".global _RNvCshC78LsHd0gk_7___rustc17rust_begin_unwind");

// The pinned target `core` archive retains this unwind-table anchor even for
// the selected panic-abort executable.  The fixture cannot unwind and no
// executed route calls this symbol; defining it keeps that closed Rust ABI
// boundary explicit instead of admitting a toolchain panic-runtime archive.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// Crosses the typed direct facade and the companion bitcode crate.
#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_x86_consumer_lto_route(seed: u64) -> i32 {
    let pid = process::getpid().as_raw_pid();
    let first = crabc_x86_consumer_lto_helper::fingerprint(seed);
    let second = crabc_x86_consumer_lto_helper::fingerprint(seed);
    if pid > 0 && first != 0 && first == second {
        0
    } else {
        1
    }
}

#[no_mangle]
pub unsafe extern "C" fn main(
    argc: i32,
    argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    if argc <= 0 || argv.is_null() || unsafe { argv.read() }.is_null() {
        return 91;
    }
    if crabc_x86_consumer_lto_route(argc as u64) != 0 {
        return 92;
    }
    // SAFETY: descriptor 1 is borrowed from the process and is not closed by
    // this fixture.  `io::write` reaches the direct Rust facade.
    let stdout = unsafe { BorrowedFd::borrow_raw(1) };
    match io::write(stdout, OK) {
        Ok(length) if length == OK.len() => 0,
        _ => 93,
    }
}

#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_static_tls_bootstrap(
    _initial_stack: *const usize,
) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    application: ApplicationMain,
    argc: i32,
    argv: *const *const u8,
    init: *const c_void,
    fini: *const c_void,
    _rtld_fini: *const c_void,
) -> ! {
    if argc < 0 || argv.is_null() {
        exit_immediately(94);
    }
    if !init.is_null() {
        // SAFETY: the Rust CRT supplies `_init` using this exact C ABI.
        let callback: LifecycleHook = unsafe { core::mem::transmute(init) };
        unsafe { callback() };
    }
    let environment = argv.wrapping_add(argc as usize + 1);
    let status = unsafe { application(argc, argv, environment) };
    if !fini.is_null() {
        // SAFETY: the Rust CRT supplies `_fini` using this exact C ABI.
        let callback: LifecycleHook = unsafe { core::mem::transmute(fini) };
        unsafe { callback() };
    }
    exit_immediately(status)
}
