#![no_std]

//! Controlled x86-64 static-PIE CRT and builtins consumer.
//!
//! This is deliberately a private bundle fixture: it consumes the Rust
//! `rcrt1.o`/`crti.o`/`crtn.o` objects and the evidence-only
//! `libcrabc-builtins.a` helper archive without selecting a sysroot, libc, or
//! an ambient compiler runtime.

use core::ffi::c_void;

type ApplicationMain = unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type LifecycleHook = unsafe extern "C" fn();

extern "C" {
    fn __udivti3(numerator: u128, denominator: u128) -> u128;
}

#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_static_tls_bootstrap(_initial_stack: *const usize) -> i32 {
    0
}

#[inline(never)]
fn write_stdout(bytes: &[u8]) {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 1usize,
            in("rdi") 1usize,
            in("rsi") bytes.as_ptr(),
            in("rdx") bytes.len(),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

unsafe extern "C" fn constructor() {
    write_stdout(b"I");
}

unsafe extern "C" fn destructor() {
    write_stdout(b"F");
}

#[used]
#[link_section = ".init_array"]
static INIT: unsafe extern "C" fn() = constructor;

#[used]
#[link_section = ".fini_array"]
static FINI: unsafe extern "C" fn() = destructor;

#[no_mangle]
pub unsafe extern "C" fn main(
    argc: i32,
    argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    if argc <= 0 || argv.is_null() || unsafe { core::ptr::read(argv) }.is_null() {
        return 91;
    }
    let quotient = unsafe { __udivti3((1_u128 << 100) + 17, 17) };
    if quotient != (1_u128 << 100) / 17 + 1 {
        return 92;
    }
    write_stdout(b"B");
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
    let expected_envp = argv.wrapping_add(argc as usize + 1);
    if argv.is_null() || argc < 0 || expected_envp.is_null() {
        exit(93);
    }
    if !init.is_null() {
        let callback: LifecycleHook = unsafe { core::mem::transmute(init) };
        unsafe { callback() };
    }
    let status = unsafe { application(argc, argv, expected_envp) };
    if !fini.is_null() {
        let callback: LifecycleHook = unsafe { core::mem::transmute(fini) };
        unsafe { callback() };
    }
    exit(status)
}

#[no_mangle]
pub extern "C" fn exit(status: i32) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 60usize,
            in("rdi") status as usize,
            options(noreturn, nostack),
        );
    }
}
