//! Common post-relocation application entry for the executable CRT objects.
//!
//! The AArch64 entry assembly passes the original kernel stack pointer in
//! `x0`. The initial stack is outside Rust allocation provenance, so this
//! module keeps it as raw pointers and uses bounded raw reads until the libc
//! startup ABI consumes `argv` and `envp`.

use core::ffi::c_void;

const MAX_INITIAL_POINTERS: usize = 1 << 20;
const MAX_AUXV_ENTRIES: usize = 4_096;
// This is a private loader-to-owned-CRT wire value, not an ELF export or a
// public libc ABI extension. `ldso/src/loader.rs` constructs it only after it
// has recognized Scrt1's private ELF note. A foreign loader continues to pass
// its conventional `rtld_fini` function directly in x0, which this code
// preserves without dereferencing as a handoff.
const OWNED_CRT_STARTUP_HANDOFF_MAGIC: u64 = 0x4352_4142_435f_4831;
const OWNED_CRT_STARTUP_HANDOFF_VERSION: u32 = 1;

type ApplicationMain = unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type LifecycleHook = unsafe extern "C" fn();
type LinkerArrayEntry = *const ();

/// Private startup callbacks supplied by crabc ldso to owned `Scrt1.o`.
///
/// The fixed magic, revision, size, and raw pointer fields make this a small
/// C-layout wire contract without publishing an ELF symbol. The dynamic CRT
/// first reads `magic` unaligned: an ordinary ELF loader's x0 finalizer is a
/// code pointer rather than this record and remains the musl ABI finalizer.
#[repr(C)]
struct OwnedCrtStartupHandoff {
    magic: u64,
    version: u32,
    abi_size: u32,
    dependency_constructors: *const c_void,
    process_fini: *const c_void,
}

#[cfg(crabc_dynamic_startup)]
static mut INITIAL_DEPENDENCY_CONSTRUCTORS: Option<LifecycleHook> = None;

struct InitialProcess {
    argc: i32,
    argv: *const *const u8,
    envp: *const *const u8,
    auxv: *const usize,
}

unsafe extern "C" {
    fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32;
    fn _init();
    fn _fini();

    // `libc/src/c_abi.rs` owns this musl-shaped six-argument ABI and never
    // returns: it routes `main` through libc's normal `exit` lifecycle.
    fn __libc_start_main(
        main: ApplicationMain,
        argc: i32,
        argv: *const *const u8,
        init: *const c_void,
        fini: *const c_void,
        rtld_fini: *const c_void,
    ) -> !;

    // These Rust-hosted AArch64 bridges return linker-script boundaries as raw
    // values. They preserve an empty array's equal start/end address without
    // asking Rust to treat two distinct extern statics as distinct objects.
    fn __crabc_preinit_array_start_address() -> *const LinkerArrayEntry;
    fn __crabc_preinit_array_end_address() -> *const LinkerArrayEntry;
    fn __crabc_init_array_start_address() -> *const LinkerArrayEntry;
    fn __crabc_init_array_end_address() -> *const LinkerArrayEntry;
    fn __crabc_fini_array_start_address() -> *const LinkerArrayEntry;
    fn __crabc_fini_array_end_address() -> *const LinkerArrayEntry;

}

impl InitialProcess {
    /// Parse the Linux initial stack without creating references to its
    /// externally owned memory.
    ///
    /// # Safety
    ///
    /// `initial_stack` must be the untouched initial AArch64 Linux stack.
    /// The kernel guarantees the conventional `argc`, argv, environment, and
    /// auxiliary-vector layout. The bounded scans convert a malformed layout
    /// into an early process exit rather than treating it as Rust memory.
    unsafe fn parse(initial_stack: *const usize) -> Option<Self> {
        if initial_stack.is_null() {
            return None;
        }

        // SAFETY: the kernel owns the first machine word of the initial stack.
        let argc_word = unsafe { core::ptr::read(initial_stack) };
        let argc = i32::try_from(argc_word).ok()?;
        let argc = usize::try_from(argc).ok()?;
        if argc > MAX_INITIAL_POINTERS {
            return None;
        }

        // `wrapping_add` avoids claiming a Rust allocation bound for the
        // kernel-created stack. The Linux startup ABI supplies the mapped
        // words subsequently read through these raw pointers.
        let argv = initial_stack.wrapping_add(1).cast::<*const u8>();
        // SAFETY: a valid initial argv is terminated by argv[argc] == NULL.
        if !unsafe { core::ptr::read(argv.wrapping_add(argc)) }.is_null() {
            return None;
        }

        let envp = argv.wrapping_add(argc.checked_add(1)?);
        let mut environment_count = 0usize;
        loop {
            if environment_count == MAX_INITIAL_POINTERS {
                return None;
            }
            // SAFETY: the kernel startup ABI terminates envp with a null word.
            if unsafe { core::ptr::read(envp.wrapping_add(environment_count)) }.is_null() {
                break;
            }
            environment_count += 1;
        }

        let auxv = envp.wrapping_add(environment_count.checked_add(1)?).cast::<usize>();
        let mut auxiliary_count = 0usize;
        loop {
            if auxiliary_count == MAX_AUXV_ENTRIES {
                return None;
            }
            let entry = auxiliary_count.checked_mul(2)?;
            // SAFETY: Linux terminates auxv with an AT_NULL tag/value pair.
            let tag = unsafe { core::ptr::read(auxv.wrapping_add(entry)) };
            if tag == 0 {
                break;
            }
            auxiliary_count += 1;
        }

        Some(Self {
            argc: i32::try_from(argc).ok()?,
            argv,
            envp,
            auxv,
        })
    }
}

/// Enter crabc's libc-owned application lifecycle after its relocation model
/// has become valid.
///
/// The entry shims call this only with the original kernel stack pointer. For
/// a dynamic executable the interpreter has already relocated the image; for
/// static PIE `rcrt1.o` applies its checked relative relocations first.
#[no_mangle]
pub unsafe extern "C" fn __crabc_start(
    initial_stack: *const usize,
    loader_startup: *const c_void,
) -> ! {
    // SAFETY: the naked entry shim preserves the kernel-provided initial stack
    // pointer and reaches this normal Rust code only once relocation is valid.
    let process = match unsafe { InitialProcess::parse(initial_stack) } {
        Some(process) => process,
        None => startup_reject(),
    };

    // Keep auxiliary-vector validation in the startup contract even though
    // the current libc ABI derives its own auxv pointer from argv.
    let _auxv = process.auxv;
    let rtld_fini = unsafe { configure_loader_startup(loader_startup) };
    unsafe {
        __libc_start_main(
            main,
            process.argc,
            process.argv,
            __crabc_executable_init as LifecycleHook as *const c_void,
            __crabc_executable_fini as LifecycleHook as *const c_void,
            rtld_fini,
        )
    }
}

/// Run the main executable's constructor lifecycle after libc has established
/// its initial process state. The dynamic loader owns dependency constructors;
/// this callback owns only the main executable's conventional sequence.
#[no_mangle]
pub unsafe extern "C" fn __crabc_executable_init() {
    // SAFETY: the executable linker defines each array as contiguous pointer
    // storage. They are invoked only after the libc startup owner has made
    // TLS and the stack guard available to application constructors.
    unsafe {
        invoke_linker_array(
            __crabc_preinit_array_start_address(),
            __crabc_preinit_array_end_address(),
            ArrayOrder::Forward,
        );
        run_initial_dependency_constructors();
        _init();
        invoke_linker_array(
            __crabc_init_array_start_address(),
            __crabc_init_array_end_address(),
            ArrayOrder::Forward,
        );
    }
}

/// Decode the private crabc-loader handoff when present, otherwise preserve a
/// conventional ELF loader's direct `rtld_fini` function pointer.
///
/// # Safety
///
/// `loader_startup` is x0 from the dynamic-loader entry ABI. It is either null
/// for static entry, a live executable function pointer from a foreign ELF
/// loader, or the exact `OwnedCrtStartupHandoff` record documented above from
/// crabc ldso. All reads are unaligned raw reads because x0 is not a Rust
/// allocation and no reference to it may outlive startup.
unsafe fn configure_loader_startup(loader_startup: *const c_void) -> *const c_void {
    #[cfg(not(crabc_dynamic_startup))]
    {
        let _ = loader_startup;
        return core::ptr::null();
    }

    #[cfg(crabc_dynamic_startup)]
    {
        if loader_startup.is_null() {
            startup_reject();
        }

        // A conventional loader provides a code address here. Code mappings
        // are readable on Linux/AArch64; a value other than our high-entropy
        // private record magic is therefore the ordinary musl-shaped fini
        // callback and must pass through untouched.
        let magic = unsafe { core::ptr::read_unaligned(loader_startup.cast::<u64>()) };
        if magic != OWNED_CRT_STARTUP_HANDOFF_MAGIC {
            return loader_startup;
        }

        let handoff = loader_startup.cast::<OwnedCrtStartupHandoff>();
        let version = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).version)) };
        let abi_size = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).abi_size)) };
        if version != OWNED_CRT_STARTUP_HANDOFF_VERSION
            || usize::try_from(abi_size).ok() < Some(core::mem::size_of::<OwnedCrtStartupHandoff>())
        {
            startup_reject();
        }
        let dependencies = unsafe {
            core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).dependency_constructors))
        };
        let process_fini = unsafe {
            core::ptr::read_unaligned(core::ptr::addr_of!((*handoff).process_fini))
        };
        if dependencies.is_null() || process_fini.is_null() {
            startup_reject();
        }

        // The loader owns both code addresses through process exit. Startup
        // is still single-threaded here, so publishing this one callback does
        // not need a synchronization primitive or TLS.
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!(INITIAL_DEPENDENCY_CONSTRUCTORS),
                Some(core::mem::transmute::<*const c_void, LifecycleHook>(dependencies)),
            );
        }
        process_fini
    }
}

/// Run the one callback that crabc ldso handed to an owned dynamic CRT after
/// the main executable's preinit array. Foreign loaders have already run the
/// dependency graph before `_start`; static links have no callback at all.
unsafe fn run_initial_dependency_constructors() {
    #[cfg(crabc_dynamic_startup)]
    {
        let callback = unsafe {
            core::ptr::read(core::ptr::addr_of!(INITIAL_DEPENDENCY_CONSTRUCTORS))
        };
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(INITIAL_DEPENDENCY_CONSTRUCTORS), None);
        }
        if let Some(callback) = callback {
            unsafe { callback() };
        }
    }
}

/// Run the main executable's finalization lifecycle after libc has discharged
/// ordinary `atexit` handlers. The linker arrays use reverse order by ELF
/// convention before the legacy `_fini` contribution closes the frame.
#[no_mangle]
pub unsafe extern "C" fn __crabc_executable_fini() {
    // SAFETY: see `__crabc_executable_init`; the fini array is traversed in
    // reverse and each non-null entry is a linker-provided function address.
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

/// Invoke one executable-owned linker array without manufacturing references
/// to its foreign linker-script storage.
///
/// # Safety
///
/// The start/end addresses must delimit a mapped, pointer-aligned linker
/// array whose non-null entries are `unsafe extern "C" fn()` targets.
unsafe fn invoke_linker_array(
    start: *const LinkerArrayEntry,
    end: *const LinkerArrayEntry,
    order: ArrayOrder,
) {
    let start_address = start.addr();
    let end_address = end.addr();
    // GNU ld/lld resolve an empty executable array's two boundary symbols to
    // the same address (zero-relative in a PIE). Return before forming any
    // array slot so that address is never mistaken for a callback entry.
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
                // SAFETY: the validated linker range contains `count` raw
                // function-address slots; no Rust reference is created.
                unsafe { invoke_linker_entry(core::ptr::read(start.wrapping_add(index))) };
            }
        }
        ArrayOrder::Reverse => {
            let mut index = count;
            while index != 0 {
                index -= 1;
                // SAFETY: see the forward traversal above.
                unsafe { invoke_linker_entry(core::ptr::read(start.wrapping_add(index))) };
            }
        }
    }
}

/// Invoke one nullable ELF array function address.
///
/// # Safety
///
/// A non-null `entry` must be a valid application constructor/destructor with
/// the no-argument C ABI.
unsafe fn invoke_linker_entry(entry: LinkerArrayEntry) {
    if entry.is_null() {
        return;
    }
    // SAFETY: ELF init/fini arrays store code addresses. The caller validated
    // the linker-defined array bounds; a non-null slot has the exact C ABI.
    let callback: LifecycleHook = unsafe { core::mem::transmute(entry) };
    // SAFETY: the linker supplied this callback in the executable lifecycle
    // array, and its C ABI has no arguments or result.
    unsafe { callback() };
}

#[cold]
#[inline(never)]
fn startup_reject() -> ! {
    // The initial stack failed bounded structural validation before libc can
    // safely own process state. Exit through the Linux ABI without allocation,
    // TLS, or a dependency on relocated global state.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 93usize,
            in("x0") 127usize,
            options(noreturn, nostack),
        );
    }
}

#[cold]
#[inline(never)]
fn lifecycle_reject() -> ! {
    // A malformed linker-array boundary is a corrupted executable image; do
    // not continue into arbitrary addresses after process finalization began.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 93usize,
            in("x0") 127usize,
            options(noreturn, nostack),
        );
    }
}
