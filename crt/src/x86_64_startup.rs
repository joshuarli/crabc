//! Shared Linux/x86-64 static application startup.
//!
//! This is deliberately separate from the active AArch64 startup module. It
//! is only a private static-startup foundation. `rcrt1.o` reaches it after
//! checked self-relocation and GNU RELRO; ordinary `crt1.o` reaches it after
//! final static linking. Neither path implies a dynamic-loader handoff,
//! `Scrt1.o`, installed sysroot, or public x86 support.

use core::ffi::c_int;

const MAX_INITIAL_POINTERS: usize = 1 << 20;

type ApplicationMain = unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type LifecycleHook = unsafe extern "C" fn();
type LinkerArrayEntry = *const ();

struct InitialProcess {
    argc: i32,
    argv: *const *const u8,
}

unsafe extern "C" {
    fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32;
    fn _init();
    fn _fini();
    fn __libc_start_main(
        main: Option<ApplicationMain>,
        argc: i32,
        argv: *const *const u8,
        init: Option<LifecycleHook>,
        fini: Option<LifecycleHook>,
        rtld_fini: Option<LifecycleHook>,
    ) -> !;
    fn __crabc_preinit_array_start_address() -> *const LinkerArrayEntry;
    fn __crabc_preinit_array_end_address() -> *const LinkerArrayEntry;
    fn __crabc_init_array_start_address() -> *const LinkerArrayEntry;
    fn __crabc_init_array_end_address() -> *const LinkerArrayEntry;
    fn __crabc_fini_array_start_address() -> *const LinkerArrayEntry;
    fn __crabc_fini_array_end_address() -> *const LinkerArrayEntry;
    fn __crabc_x86_static_tls_bootstrap(initial_stack: *const usize) -> c_int;
}

// The libc definition is deliberately hidden. rcrt1 uses its static-link
// handoff through an R_X86_64_RELATIVE slot after relocation; crt1 resolves a
// direct static call. Neither path is a preemptible PLT or dynamic-loader edge.
core::arch::global_asm!(".hidden __crabc_x86_static_tls_bootstrap");

impl InitialProcess {
    /// # Safety
    ///
    /// `initial_stack` must be the untouched Linux/x86-64 kernel entry stack.
    unsafe fn parse(initial_stack: *const usize) -> Option<Self> {
        if initial_stack.is_null() {
            return None;
        }
        let argc_word = unsafe { core::ptr::read(initial_stack) };
        let argc = i32::try_from(argc_word).ok()?;
        let argc = usize::try_from(argc).ok()?;
        if argc > MAX_INITIAL_POINTERS {
            return None;
        }

        let argv = initial_stack.wrapping_add(1).cast::<*const u8>();
        if !unsafe { core::ptr::read(argv.wrapping_add(argc)) }.is_null() {
            return None;
        }
        let envp = argv.wrapping_add(argc.checked_add(1)?);
        let mut environment_count = 0usize;
        loop {
            if environment_count == MAX_INITIAL_POINTERS {
                return None;
            }
            if unsafe { core::ptr::read(envp.wrapping_add(environment_count)) }.is_null() {
                break;
            }
            environment_count += 1;
        }

        Some(Self {
            argc: i32::try_from(argc).ok()?,
            argv,
        })
    }
}

/// Enter libc-owned process startup after the entry object established its
/// distinct contract: `x86_64_rcrt1.rs` applies checked relative relocations
/// and seals GNU RELRO, while `x86_64_crt1.rs` enters directly after final
/// static linking. Both must preserve the untouched entry stack until the
/// libc-owned TLS bootstrap succeeds.
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_64_static_pie_start(initial_stack: *const usize) -> ! {
    let process = match unsafe { InitialProcess::parse(initial_stack) } {
        Some(process) => process,
        None => startup_reject(),
    };
    // The x86 local-exec model dereferences `%fs` directly.  Libc owns the
    // executable's Static Initial TLS v1 template and must install the main
    // image before any lifecycle hook or libc-shaped startup boundary can use
    // TLS.  Pass the original entry stack so libc owns all auxv/PT_TLS
    // validation as well as materialization.
    if unsafe { __crabc_x86_static_tls_bootstrap(initial_stack) } != 0 {
        startup_reject();
    }
    unsafe {
        __libc_start_main(
            Some(main),
            process.argc,
            process.argv,
            Some(__crabc_x86_64_executable_init),
            Some(__crabc_x86_64_executable_fini),
            None,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_64_executable_init() {
    unsafe {
        invoke_linker_array(
            __crabc_preinit_array_start_address(),
            __crabc_preinit_array_end_address(),
            ArrayOrder::Forward,
        );
        _init();
        invoke_linker_array(
            __crabc_init_array_start_address(),
            __crabc_init_array_end_address(),
            ArrayOrder::Forward,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_64_executable_fini() {
    unsafe {
        invoke_linker_array(
            __crabc_fini_array_start_address(),
            __crabc_fini_array_end_address(),
            ArrayOrder::Reverse,
        );
        _fini();
    }
}

#[derive(Clone, Copy)]
enum ArrayOrder {
    Forward,
    Reverse,
}

unsafe fn invoke_linker_array(
    start: *const LinkerArrayEntry,
    end: *const LinkerArrayEntry,
    order: ArrayOrder,
) {
    let start_address = start.addr();
    let end_address = end.addr();
    if start_address == end_address {
        return;
    }
    let entry_size = core::mem::size_of::<LinkerArrayEntry>();
    let entry_alignment = core::mem::align_of::<LinkerArrayEntry>();
    let byte_count = match end_address.checked_sub(start_address) {
        Some(byte_count)
            if start_address % entry_alignment == 0
                && end_address % entry_alignment == 0
                && byte_count % entry_size == 0 =>
        {
            byte_count
        }
        _ => lifecycle_reject(),
    };
    let count = byte_count / entry_size;
    if count > MAX_INITIAL_POINTERS {
        lifecycle_reject();
    }
    match order {
        ArrayOrder::Forward => {
            for index in 0..count {
                unsafe { invoke_linker_entry(core::ptr::read(start.wrapping_add(index))) };
            }
        }
        ArrayOrder::Reverse => {
            let mut index = count;
            while index != 0 {
                index -= 1;
                unsafe { invoke_linker_entry(core::ptr::read(start.wrapping_add(index))) };
            }
        }
    }
}

unsafe fn invoke_linker_entry(entry: LinkerArrayEntry) {
    if entry.is_null() {
        return;
    }
    let callback: LifecycleHook = unsafe { core::mem::transmute(entry) };
    unsafe { callback() };
}

#[cold]
#[inline(never)]
fn startup_reject() -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 60usize,
            in("rdi") 127usize,
            options(noreturn, nostack),
        );
    }
}

#[cold]
#[inline(never)]
fn lifecycle_reject() -> ! {
    startup_reject()
}
