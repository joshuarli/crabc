//! Private Linux/x86-64 signal-action ABI packing leaf.
//!
//! This is the record-conversion part of musl 1.2.6
//! `src/signal/sigaction.c`, with x86-64's `__restore` alias and
//! `__restore_rt` trampoline from `arch/x86_64/ksigaction.h` and
//! `src/signal/x86_64/restore.s`. It preserves the public-to-kernel layout,
//! one-word kernel mask, unconditional `SA_RESTORER` insertion, and private
//! syscall-15 restorer selection. It deliberately omits the public
//! `sigaction` wrapper's signal validation, handler bookkeeping, signal-mask
//! policy, syscall, errno, and old-action conversion. The typed helpers below
//! are private composition machinery for the separately selected static
//! signal-control artifact; the C-visible packing bridge remains probe-only.
//!
//! This file exports no public signal API. Its one hidden restorer symbol is
//! an x86 signal-frame implementation detail, not a C entry point.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 signal foundation requires little-endian Linux/x86-64");

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct PublicSigAction {
    pub(super) handler: usize,
    pub(super) mask: [u64; PUBLIC_SIGSET_WORDS],
    pub(super) flags: i32,
    pub(super) padding: i32,
    pub(super) restorer: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct KernelSigAction {
    pub(super) handler: usize,
    pub(super) flags: u64,
    pub(super) restorer: usize,
    pub(super) mask: u64,
}

pub(super) const PUBLIC_SIGSET_WORDS: usize = 16;
pub(super) const SA_RESTORER: u64 = 0x0400_0000;

const _: [(); 152] = [(); core::mem::size_of::<PublicSigAction>()];
const _: [(); 8] = [(); core::mem::align_of::<PublicSigAction>()];
const _: [(); 0] = [(); core::mem::offset_of!(PublicSigAction, handler)];
const _: [(); 8] = [(); core::mem::offset_of!(PublicSigAction, mask)];
const _: [(); 136] = [(); core::mem::offset_of!(PublicSigAction, flags)];
const _: [(); 144] = [(); core::mem::offset_of!(PublicSigAction, restorer)];
const _: [(); 32] = [(); core::mem::size_of::<KernelSigAction>()];
const _: [(); 8] = [(); core::mem::align_of::<KernelSigAction>()];
const _: [(); 0] = [(); core::mem::offset_of!(KernelSigAction, handler)];
const _: [(); 8] = [(); core::mem::offset_of!(KernelSigAction, flags)];
const _: [(); 16] = [(); core::mem::offset_of!(KernelSigAction, restorer)];
const _: [(); 24] = [(); core::mem::offset_of!(KernelSigAction, mask)];

core::arch::global_asm!(
    ".text",
    // Keep the leading no-op in the same position as musl's restore.s: it is
    // outside the entry symbol, whose first executed instruction is `mov`.
    "nop",
    ".global crabc_x86_64_signal_restorer",
    ".hidden crabc_x86_64_signal_restorer",
    ".type crabc_x86_64_signal_restorer,@function",
    "crabc_x86_64_signal_restorer:",
    "mov rax, 15",
    "syscall",
    "ud2",
    ".size crabc_x86_64_signal_restorer, .-crabc_x86_64_signal_restorer",
    ".section .note.GNU-stack,\"\",@progbits",
);

unsafe extern "C" {
    fn crabc_x86_64_signal_restorer() -> !;
}

/// Return the private syscall-15 restorer's address.
#[inline]
pub(super) fn restorer_address() -> usize {
    crabc_x86_64_signal_restorer as *const () as usize
}

/// Pack a valid public musl record into Linux's 32-byte `rt_sigaction` record.
///
/// This fixed-source leaf always adds the private non-returning syscall-15
/// restorer, exactly as the pinned musl conversion does. Null pointers are
/// outside this unsafe bridge's contract; no public C API is selected here.
///
/// # Safety
///
/// `public` must be valid to read a complete musl x86 `struct sigaction` and
/// `kernel` must be valid to write a complete Linux kernel action record for
/// this call.
pub(super) unsafe fn pack_public_action(
    public: *const PublicSigAction,
    kernel: *mut KernelSigAction,
) {
    // Read only the fixed public fields consumed by musl's conversion through
    // raw unaligned operations. That preserves the unsafe caller contract
    // without introducing Rust reference validity checks or a panic runtime
    // into this source-only object.
    let public = public.cast::<u8>();
    // SAFETY: the bridge contract guarantees all three fixed fields are valid
    // to read for the stated public-record extent.
    let handler = unsafe { core::ptr::read_unaligned(public.cast::<usize>()) };
    // SAFETY: the public mask starts at byte eight on x86-64 and the kernel
    // consumes only its first machine word.
    let mask = unsafe { core::ptr::read_unaligned(public.add(8).cast::<u64>()) };
    // SAFETY: the public flags field is at byte 136 by the compile-time
    // layout assertions above.
    let flags = unsafe { core::ptr::read_unaligned(public.add(136).cast::<i32>()) };

    // SAFETY: the bridge contract gives exclusive writable access to one
    // complete kernel record. An unaligned write keeps this leaf free of Rust
    // reference validity checks and their panic path.
    unsafe {
        core::ptr::write_unaligned(
            kernel,
            KernelSigAction {
                handler,
                // Musl first assigns the signed public `int` field to the
                // x86 kernel record's `unsigned long`, then ORs in
                // `SA_RESTORER`. Preserve that sign extension for otherwise
                // unrecognised high flag bits too.
                flags: (flags as i64 as u64) | SA_RESTORER,
                restorer: restorer_address(),
                mask,
            },
        );
    }
}

/// Expand Linux's compact old-action record into musl's partial public x86
/// record update used by the selected static C artifact.
///
/// Linux returns one signal-mask word. Musl writes only the public handler,
/// that word, and flags, deliberately preserving the caller-resident tail,
/// padding, and nonstandard restorer field. Keep that observable partial-write
/// contract instead of manufacturing a fully initialized public record.
///
/// # Safety
///
/// `kernel` must be valid to read one complete Linux kernel action record and
/// `public` must be valid to write the handler, first mask word, and flags of
/// one musl x86 `struct sigaction`.
#[allow(dead_code)] // The source-only packing probe intentionally does not query old actions.
pub(super) unsafe fn unpack_kernel_action(
    kernel: *const KernelSigAction,
    public: *mut PublicSigAction,
) {
    // SAFETY: the caller gives a complete kernel record. An unaligned read
    // keeps this private ABI helper free of Rust-reference assumptions.
    let kernel = unsafe { core::ptr::read_unaligned(kernel) };
    let public = public.cast::<u8>();

    // SAFETY: the caller gives a complete writable public record. These exact
    // offsets are the x86 musl public ABI fields which its sigaction wrapper
    // updates after a successful kernel query; all other bytes stay untouched.
    unsafe {
        core::ptr::write_unaligned(public.cast::<usize>(), kernel.handler);
        core::ptr::write_unaligned(public.add(8).cast::<u64>(), kernel.mask);
        core::ptr::write_unaligned(public.add(136).cast::<i32>(), kernel.flags as i32);
    }
}
