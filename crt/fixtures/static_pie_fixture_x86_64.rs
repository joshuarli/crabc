#![no_std]

//! Native x86-64 observable fixture for the bounded `rcrt1.o` bootstrap.

use core::ffi::c_void;

type ApplicationMain = unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type LifecycleHook = unsafe extern "C" fn();

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
        return 81;
    }

    let mut output = [0u8; 16];
    let mut address = main as usize;
    for index in (0..output.len()).rev() {
        let digit = (address & 0xF) as u8;
        output[index] = if digit < 10 { b'0' + digit } else { b'a' + (digit - 10) };
        address >>= 4;
    }
    write_stdout(&output);
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
        exit(82);
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
