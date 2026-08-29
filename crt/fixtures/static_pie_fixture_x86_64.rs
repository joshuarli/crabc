#![no_std]
#![allow(unexpected_cfgs)]

//! Native x86-64 observable fixture for the bounded `rcrt1.o` bootstrap.
//!
//! The evidence runner builds this once without TLS and once with
//! `--cfg crabc_static_pie_tls` plus its local-exec assembly companion.  The
//! first form preserves the no-`PT_TLS` startup policy; the second proves the
//! owned first-thread TLS bootstrap before executable preinit hooks.

use core::ffi::c_void;

type ApplicationMain = unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type LifecycleHook = unsafe extern "C" fn();

#[cfg(crabc_static_pie_tls)]
const INITIAL_TLS_VALUE: u64 = 0x746c_735f_696e_6974;
#[cfg(crabc_static_pie_tls)]
const PREINIT_TLS_VALUE: u64 = 0x7072_6569_6e69_745f;
#[cfg(crabc_static_pie_tls)]
const INIT_TLS_VALUE: u64 = 0x696e_6974_5f74_6c73;
#[cfg(crabc_static_pie_tls)]
const MAIN_TLS_VALUE: u64 = 0x6d61_696e_5f74_6c73;
#[cfg(crabc_static_pie_tls)]
const ARCH_GET_FS: usize = 0x1003;

#[cfg(crabc_static_pie_tls)]
unsafe extern "C" {
    fn crabc_x86_64_static_tls_read_initialized() -> u64;
    fn crabc_x86_64_static_tls_write_initialized(value: u64);
    fn crabc_x86_64_static_tls_read_zero() -> u64;
    fn crabc_x86_64_static_tls_write_zero(value: u64);
    fn crabc_x86_64_static_tls_thread_pointer() -> *const u8;
}

#[cfg(crabc_static_pie_tls)]
#[inline(never)]
fn installed_fs_base() -> *const u8 {
    let mut base = 0usize;
    let result: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 158usize => result,
            in("rdi") ARCH_GET_FS,
            in("rsi") (&raw mut base),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result == 0 {
        base as *const u8
    } else {
        core::ptr::null()
    }
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
    #[cfg(crabc_static_pie_tls)]
    {
        if unsafe { crabc_x86_64_static_tls_thread_pointer() }.is_null()
            || unsafe { crabc_x86_64_static_tls_read_initialized() } != PREINIT_TLS_VALUE
            || unsafe { crabc_x86_64_static_tls_read_zero() } != PREINIT_TLS_VALUE
        {
            exit(84);
        }
        unsafe {
            crabc_x86_64_static_tls_write_initialized(INIT_TLS_VALUE);
            crabc_x86_64_static_tls_write_zero(INIT_TLS_VALUE);
        }
    }
    write_stdout(b"I");
}

unsafe extern "C" fn destructor() {
    #[cfg(crabc_static_pie_tls)]
    {
        if unsafe { crabc_x86_64_static_tls_read_initialized() } != MAIN_TLS_VALUE
            || unsafe { crabc_x86_64_static_tls_read_zero() } != MAIN_TLS_VALUE
        {
            exit(85);
        }
    }
    write_stdout(b"F");
}

#[cfg(crabc_static_pie_tls)]
unsafe extern "C" fn preinit() {
    let thread_pointer = unsafe { crabc_x86_64_static_tls_thread_pointer() };
    if thread_pointer.is_null()
        || thread_pointer != installed_fs_base()
        || unsafe { crabc_x86_64_static_tls_read_initialized() } != INITIAL_TLS_VALUE
        || unsafe { crabc_x86_64_static_tls_read_zero() } != 0
    {
        exit(83);
    }
    unsafe {
        crabc_x86_64_static_tls_write_initialized(PREINIT_TLS_VALUE);
        crabc_x86_64_static_tls_write_zero(PREINIT_TLS_VALUE);
    }
    write_stdout(b"P");
}

#[cfg(crabc_static_pie_tls)]
#[used]
#[link_section = ".preinit_array"]
static PREINIT: unsafe extern "C" fn() = preinit;

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
    #[cfg(crabc_static_pie_tls)]
    {
        if unsafe { crabc_x86_64_static_tls_thread_pointer() }.is_null()
            || unsafe { crabc_x86_64_static_tls_read_initialized() } != INIT_TLS_VALUE
            || unsafe { crabc_x86_64_static_tls_read_zero() } != INIT_TLS_VALUE
        {
            return 86;
        }
        unsafe {
            crabc_x86_64_static_tls_write_initialized(MAIN_TLS_VALUE);
            crabc_x86_64_static_tls_write_zero(MAIN_TLS_VALUE);
        }
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
