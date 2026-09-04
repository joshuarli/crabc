//! Private Linux/x86-64 dynamic-PIE application startup.
//!
//! `Scrt1.o` normally reaches this code only after an ELF interpreter has
//! relocated the main image. It deliberately follows pinned musl 1.2.6
//! x86-64's entry convention: the entry `%rdx` value is not a finalizer
//! argument, so this six-argument `__libc_start_main` handoff receives a null
//! `rtld_fini`. Pinned musl owns and invokes its own executable lifecycle; a
//! freestanding native fixture separately exercises the callback arguments
//! below. An owned crabc interpreter may instead resolve the weak data symbol
//! `__crabc_x86_64_owned_crt_handoff` after relocation. That is an explicit
//! versioned post-relocation wire, never `%rdx`; foreign loaders leave it null
//! and retain the musl-shaped null-finalizer call.
//!
//! This is not the static startup path. In particular, it must not install
//! static TLS itself or call `__crabc_x86_static_tls_bootstrap`: an interpreter
//! owns relocation and initial thread state before it transfers control here.

#[cfg(crabc_dynamic_main_thread_runtime_v1)]
use core::ffi::c_int;

const MAX_INITIAL_POINTERS: usize = 1 << 20;

type ApplicationMain = unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type LifecycleHook = unsafe extern "C" fn();
type LinkerArrayEntry = *const ();

const OWNED_CRT_HANDOFF_MAGIC: u64 = 0x4352_4142_435f_4831;
const OWNED_CRT_HANDOFF_VERSION: u32 = 1;

/// Private x86 post-relocation loader-to-CRT handoff, revision one.
///
/// The interpreter owns this immutable record. Its weak data-symbol transport
/// is intentionally read only after `_start` entered normal Rust code.
#[repr(C)]
struct OwnedCrtHandoffV1 {
    magic: u64,
    version: u32,
    abi_size: u32,
    dependency_constructors: Option<LifecycleHook>,
    process_fini: Option<LifecycleHook>,
}

static mut INITIAL_DEPENDENCY_CONSTRUCTORS: Option<LifecycleHook> = None;

core::arch::global_asm!(
    ".att_syntax prefix",
    ".weak __crabc_x86_64_owned_crt_handoff",
    ".type __crabc_x86_64_owned_crt_handoff,@object",
    ".text",
    ".global __crabc_x86_64_owned_crt_handoff_value",
    ".type __crabc_x86_64_owned_crt_handoff_value,@function",
    "__crabc_x86_64_owned_crt_handoff_value:",
    "lea __crabc_x86_64_owned_crt_handoff@GOTPCREL(%rip), %rax",
    "mov (%rax), %rax",
    "test %rax, %rax",
    "je 1f",
    "ret",
    "1:",
    "xor %eax, %eax",
    "ret",
    ".size __crabc_x86_64_owned_crt_handoff_value, .-__crabc_x86_64_owned_crt_handoff_value",
    ".intel_syntax noprefix",
);

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
    fn __crabc_x86_64_owned_crt_handoff_value() -> *const OwnedCrtHandoffV1;
    #[cfg(crabc_dynamic_main_thread_runtime_v1)]
    fn __crabc_x86_loader_tls_runtime_v1_attach() -> c_int;
}

impl InitialProcess {
    /// # Safety
    ///
    /// `initial_stack` must be the untouched Linux/x86-64 initial stack that
    /// the interpreter passes to the executable entry point.
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

        // The kernel owns this memory rather than Rust, so preserve raw
        // pointer arithmetic and bound the only scans we perform.
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

/// Enter the private six-argument libc lifecycle handoff after the ELF
/// interpreter has made the main image callable.
///
/// The null finalizer is intentional and architecture-specific: pinned musl
/// x86-64 `Scrt1.o` does not forward a loader register finalizer. Do not add a
/// guessed glibc-style `%rdx` convention here; crabc's owned-loader handoff
/// uses its checked post-relocation data wire. Pinned musl's
/// dynamic libc owns lifecycle invocation itself, so its launch behavior must
/// not be used to infer whether these callback arguments were consumed.
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_64_dynamic_start(
    initial_stack: *const usize,
    #[cfg(crabc_general_dynamic_lifecycle)] loader_finalizer: Option<LifecycleHook>,
) -> ! {
    let process = match unsafe { InitialProcess::parse(initial_stack) } {
        Some(process) => process,
        None => startup_reject(),
    };
    // The tiny assembly helper checks the unresolved weak GOT entry before it
    // reads the data word. Rust must not form a direct reference to an absent
    // weak object: that would fault on the required foreign-musl null path.
    let handoff = unsafe { __crabc_x86_64_owned_crt_handoff_value() };
    let rtld_fini = unsafe { configure_owned_loader_handoff(handoff) };
    #[cfg(crabc_general_dynamic_lifecycle)]
    let rtld_fini = {
        // A foreign-loader/null handoff cannot authorize a register value.
        // Match the captured rdx address against the validated owned record
        // before passing it into libc or invoking any executable callbacks.
        match (loader_finalizer, rtld_fini) {
            (Some(register), Some(record)) if register as usize == record as usize => Some(register),
            _ => startup_reject(),
        }
    };
    // This private Scrt1 build mode is selected only by the general
    // RuntimeV1 main-thread evidence. Its main image provides the companion
    // directly, so this is neither a weak fallback nor a libc.so import. A
    // failed descriptor observation must stop before the dynamic libc sees
    // the six-argument startup boundary or any main-image callback runs.
    #[cfg(crabc_dynamic_main_thread_runtime_v1)]
    if unsafe { __crabc_x86_loader_tls_runtime_v1_attach() } != 0 {
        startup_reject();
    }
    unsafe {
        __libc_start_main(
            Some(main),
            process.argc,
            process.argv,
            Some(__crabc_x86_64_dynamic_executable_init),
            Some(__crabc_x86_64_dynamic_executable_fini),
            rtld_fini,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_64_dynamic_executable_init() {
    unsafe {
        invoke_linker_array(
            __crabc_preinit_array_start_address(),
            __crabc_preinit_array_end_address(),
            ArrayOrder::Forward,
        );
        let dependency_constructors = core::ptr::read(core::ptr::addr_of!(INITIAL_DEPENDENCY_CONSTRUCTORS));
        core::ptr::write(core::ptr::addr_of_mut!(INITIAL_DEPENDENCY_CONSTRUCTORS), None);
        if let Some(callback) = dependency_constructors {
            callback();
        }
        _init();
        invoke_linker_array(
            __crabc_init_array_start_address(),
            __crabc_init_array_end_address(),
            ArrayOrder::Forward,
        );
    }
}

/// Decode the owned x86 post-relocation loader handoff.
///
/// A null value is the foreign-loader path and deliberately returns a null
/// finalizer. A non-null value must be the complete v1 record; malformed
/// owned state fails before libc startup rather than falling back to an
/// implicit ABI.
unsafe fn configure_owned_loader_handoff(handoff: *const OwnedCrtHandoffV1) -> Option<LifecycleHook> {
    if handoff.is_null() {
        return None;
    }
    let magic = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).magic)) };
    let version = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).version)) };
    let abi_size = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).abi_size)) };
    let dependencies = unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).dependency_constructors))
    };
    let process_fini = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).process_fini)) };
    if magic != OWNED_CRT_HANDOFF_MAGIC
        || version != OWNED_CRT_HANDOFF_VERSION
        || usize::try_from(abi_size).ok() < Some(core::mem::size_of::<OwnedCrtHandoffV1>())
        || dependencies.is_none()
        || process_fini.is_none()
    {
        startup_reject();
    }
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(INITIAL_DEPENDENCY_CONSTRUCTORS), dependencies);
    }
    process_fini
}

#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_64_dynamic_executable_fini() {
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
        _ => startup_reject(),
    };
    let count = byte_count / entry_size;
    if count > MAX_INITIAL_POINTERS {
        startup_reject();
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
