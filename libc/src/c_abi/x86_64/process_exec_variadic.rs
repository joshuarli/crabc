//! Private Linux/x86-64 C-variadic exec argv storage.
//!
//! Pinned musl 1.2.6 `src/process/{execl,execle,execlp}.c` creates a VLA after
//! counting the caller-supplied null terminator. Rust has no equivalent VLA,
//! so this private sibling clones the ABI `VaList` to count it, maps an exactly
//! sized anonymous pointer vector, then refills that vector from the original
//! list. Arithmetic overflow and kernel mapping failure report their normal
//! `E2BIG` or kernel errno; there is no artificial argv-entry cap. The mapping
//! is released only when image replacement fails and returns.
//! This preserves ordinary valid finite C-varargs construction, but deliberately
//! does not claim musl's VLA stack-exhaustion or extreme resource-failure
//! behavior: anonymous-mapping admission is a distinct private boundary.
//!
//! This helper has no public C entry and is deliberately separate from direct,
//! environment-forwarding, and PATH-search exec archive members.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 variadic exec helper requires little-endian Linux/x86-64");

use core::{
    ffi::{c_char, c_int, VaList},
    mem::size_of,
    ptr,
};

use super::{errno, raw_syscall};

const E2BIG: c_int = 7;
const PROT_READ: i64 = 0x1;
const PROT_WRITE: i64 = 0x2;
const MAP_PRIVATE: i64 = 0x2;
const MAP_ANONYMOUS: i64 = 0x20;

/// An exactly sized temporary argv vector for a C-variadic exec wrapper.
///
/// This owns a successful private anonymous mapping even if Linux happens to
/// place it at address zero. Raw `munmap` intentionally does not translate
/// errors, so releasing a valid vector cannot overwrite the `exec*` errno.
pub(super) struct ArgumentVector {
    pointers: *mut *const c_char,
    bytes: usize,
}

impl ArgumentVector {
    /// Map space for every argv pointer plus the terminating null pointer.
    ///
    /// # Safety
    ///
    /// The caller must initialize the returned slots before passing the
    /// vector to a Linux exec syscall. The mapping is private to this leaf.
    unsafe fn allocate(argument_count: usize) -> Result<Self, ()> {
        let Some(slot_count) = argument_count.checked_add(1) else {
            // SAFETY: an unrepresentable argv-vector size cannot reach the
            // kernel; `E2BIG` is the normal exec-family size failure.
            unsafe { errno::set_errno(E2BIG) };
            return Err(());
        };
        let Some(bytes) = slot_count.checked_mul(size_of::<*const c_char>()) else {
            // SAFETY: as above, this cannot form a representable argv vector.
            unsafe { errno::set_errno(E2BIG) };
            return Err(());
        };

        // SAFETY: Linux/x86-64 mmap receives an anonymous private mapping
        // request with scalar flags, no file descriptor, and zero offset.
        let result = unsafe {
            raw_syscall::syscall6(
                raw_syscall::SYS_MMAP,
                0,
                bytes as i64,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if result < 0 && result >= -super::LINUX_ERRNO_MAX {
            // SAFETY: the checked Linux raw-result range encodes one errno.
            unsafe { errno::set_errno(result.wrapping_neg() as c_int) };
            return Err(());
        }

        Ok(Self {
            pointers: result as usize as *mut *const c_char,
            bytes,
        })
    }

    #[inline]
    pub(super) fn as_argv(&self) -> *const *const c_char {
        self.pointers.cast_const()
    }
}

impl Drop for ArgumentVector {
    fn drop(&mut self) {
        // SAFETY: a live `ArgumentVector` owns exactly this successful mmap
        // range. The raw result is intentionally ignored so a returning exec
        // failure retains its already-published errno.
        let _ = unsafe {
            raw_syscall::syscall2(
                raw_syscall::SYS_MUNMAP,
                self.pointers as usize as i64,
                self.bytes as i64,
            )
        };
    }
}

/// Count the extra C variadic argv entries without advancing the original
/// list. A missing null sentinel is a C caller-contract violation, exactly as
/// with musl's VLA scan.
unsafe fn variadic_argument_count(args: &VaList<'_>) -> Result<usize, ()> {
    let mut scan = args.clone();
    let mut count = 1usize;
    loop {
        // SAFETY: a valid execl-family invocation supplies pointer varargs
        // through a terminal null, so this reads one such ABI word.
        let argument: *const c_char = unsafe { scan.next_arg() };
        if argument.is_null() {
            return Ok(count);
        }
        let Some(next_count) = count.checked_add(1) else {
            // SAFETY: the count cannot describe a representable argv vector.
            unsafe { errno::set_errno(E2BIG) };
            return Err(());
        };
        count = next_count;
    }
}

/// Materialize musl's VLA-shaped argv vector from an original C `VaList`.
/// The original list ends immediately after the terminal null, allowing
/// `execle` to read its following environment-vector argument.
pub(super) unsafe fn variadic_argv(
    first: *const c_char,
    args: &mut VaList<'_>,
) -> Result<ArgumentVector, ()> {
    let count = unsafe { variadic_argument_count(args) }?;
    let argv = unsafe { ArgumentVector::allocate(count) }?;

    // SAFETY: `allocate` reserved `count + 1` pointer slots. The first C
    // fixed argument occupies slot zero; the loop fills exactly through the
    // count-th trailing null that the cloned scan already observed.
    unsafe { ptr::write(argv.pointers, first) };
    let mut index = 1usize;
    loop {
        // SAFETY: the caller's terminal-null contract was used to count this
        // same original list without consuming it.
        let argument: *const c_char = unsafe { args.next_arg() };
        // SAFETY: `index` reaches at most `count`, which is inside the
        // `count + 1` mapping established above.
        unsafe { ptr::write(argv.pointers.add(index), argument) };
        if argument.is_null() {
            debug_assert_eq!(index, count);
            return Ok(argv);
        }
        index += 1;
    }
}
