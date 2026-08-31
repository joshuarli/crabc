//! Linux/x86-64 selected static C `l64a` leaf.
//!
//! Provenance is fixed to musl 1.2.6
//! (`9fa28ece75d8a2191de7c5bb53bed224c5947417`) under musl's MIT license
//! recorded in its `COPYRIGHT` file. The exact source is `src/misc/a64l.c`:
//! its `l64a` half casts the incoming `long` to `uint32_t`, emits low-to-high
//! radix-64 digits into one `static char s[7]`, terminates that buffer, and
//! returns its address.
//!
//! The same source file and `a64l.lo` also define the state-free `a64l`
//! decoder. This target-private source split selects only `l64a`'s mutable
//! seven-byte result-buffer half. It deliberately does not import `a64l`, a
//! byte-string helper, errno/TLS, locale, allocation, syscall, or runtime
//! state. The one shared buffer is musl's non-reentrant C contract, not an
//! allocation substitute or a general numeric-conversion facility. This is a
//! private selected static artifact, not a libc.so, CRT, loader, sysroot,
//! family-completion, promotion, or public x86 support claim.

use core::ffi::{c_char, c_long};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C l64a leaf requires little-endian Linux/x86-64");

/// The exact low-to-high radix-64 alphabet in musl's `src/misc/a64l.c`.
const DIGITS: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Musl's one shared seven-byte `l64a` result object.
///
/// A 32-bit source payload consumes at most six radix-64 digits, leaving one
/// terminator byte. Every call overwrites this process-global object exactly
/// as musl's `static char s[7]` does.
static mut L64A_RESULT: [u8; 7] = [0; 7];

/// Return musl's shared radix-64 representation of the low 32 bits of `value`.
///
/// The x86-64 C ABI passes the LP64 `long` in `rdi` and returns the address of
/// one mutable process-global C string in `rax`. The output uses the exact
/// `./0-9A-Za-z` alphabet, emits least-significant six-bit digits first, and
/// produces an empty string for a zero 32-bit payload.
///
/// # Safety
///
/// The returned pointer designates musl-compatible shared static storage. A
/// later `l64a` call overwrites its NUL-terminated contents. Concurrent callers
/// and readers of a prior result must externally synchronize access; this leaf
/// deliberately adds neither locking nor thread-local storage to musl's
/// non-reentrant C contract.
#[no_mangle]
pub unsafe extern "C" fn l64a(value: c_long) -> *mut c_char {
    // Musl's `uint32_t x = x0` retains only the low 32 bits of LP64 long.
    let mut remaining = value as u32;
    let result = core::ptr::addr_of_mut!(L64A_RESULT).cast::<u8>();
    let mut index = 0usize;

    while remaining != 0 {
        // SAFETY: a 32-bit value yields no more than six six-bit digits, so
        // `index` remains in the six data bytes preceding the terminator slot.
        unsafe { result.add(index).write(DIGITS[(remaining & 63) as usize]) };
        remaining >>= 6;
        index += 1;
    }

    // SAFETY: `index` is at most six, so this writes musl's terminator inside
    // the seven-byte static result object.
    unsafe { result.add(index).write(0) };
    result.cast::<c_char>()
}
