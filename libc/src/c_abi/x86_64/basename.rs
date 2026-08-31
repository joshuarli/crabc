//! Selected static Linux/x86-64 `basename` C ABI boundary.
//!
//! This leaf translates exactly pinned musl 1.2.6's small mutable-path
//! operation at release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license:
//!
//! - `src/misc/basename.c::basename` maps directly to [`basename`] below.
//! - `weak_alias(basename, __xpg_basename)` maps to the weak same-address ELF
//!   alias immediately below; a Rust forwarding wrapper would change its
//!   function address and fail to preserve musl's ABI relation.
//!
//! Musl scans one caller-owned NUL-terminated writable byte string backward,
//! removes every trailing slash except a leading root slash in place, and
//! returns one position in that input or immutable `"."` storage. Its source
//! calls `strlen`; this target-local translation performs the same C-string
//! scan locally rather than selecting a byte-string archive helper. It owns no
//! pathname lookup, filesystem syscall, locale, errno, TLS, allocator, process
//! state, or mutable static path buffer. It is a private selected static
//! artifact, not `dirname`, general path normalization, libc.so, a CRT,
//! loader, sysroot, or public x86 support.

use core::ffi::c_char;

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C basename leaf requires little-endian Linux/x86-64");

static DOT: [u8; 2] = *b".\0";
const SLASH: c_char = b'/' as c_char;

#[inline]
fn static_dot() -> *mut c_char {
    DOT.as_ptr().cast_mut().cast::<c_char>()
}

// Musl's weak_alias(basename, __xpg_basename) requires equal ELF symbol
// values. A Rust forwarding wrapper would have a different address and would
// silently weaken the pinned static-ABI contract.
core::arch::global_asm!(
    ".weak __xpg_basename",
    ".set __xpg_basename, basename",
);

/// Return the last pathname component using musl's exact in-place algorithm.
///
/// A null or empty input returns immutable `"."` storage. For a nonempty
/// input, `path` must designate a writable NUL-terminated C byte string for
/// the complete backward scan; musl replaces every trailing slash after byte
/// zero with NUL. The returned pointer always aliases `path` for a nonempty
/// input, including root-only input. Callers must not modify or free the
/// immutable `"."` result storage.
///
/// # Safety
///
/// For a non-null input, `path` must satisfy the mutable C-string contract
/// above. Unterminated, unreadable, or unwritable input is outside musl's
/// direct-dereference contract.
#[no_mangle]
pub unsafe extern "C" fn basename(path: *mut c_char) -> *mut c_char {
    if path.is_null() {
        return static_dot();
    }

    // SAFETY: a non-null input has at least its first C-string byte under the
    // caller's contract.
    if unsafe { path.read() } == 0 {
        return static_dot();
    }

    let mut index = 0usize;
    loop {
        // SAFETY: the caller retains the complete readable C string through
        // its terminator, exactly as musl's strlen call requires. Keep this
        // as the source-level byte walk rather than allowing the optimizer to
        // select the separately owned strlen archive leaf.
        if core::hint::black_box(unsafe { path.add(index).read() }) == 0 {
            break;
        }
        index += 1;
    }
    // The nonempty check above means the byte before the terminator exists.
    index -= 1;

    while index != 0 {
        // SAFETY: index remains within the caller-owned C string.
        if unsafe { path.add(index).read() } != SLASH {
            break;
        }
        // SAFETY: trailing-slash bytes are caller-owned writable C-string
        // storage. This is musl's exact `s[i] = 0` mutation.
        unsafe { path.add(index).write(0) };
        index -= 1;
    }

    while index != 0 {
        // SAFETY: `index - 1` remains within the caller-owned C string.
        if unsafe { path.add(index - 1).read() } == SLASH {
            break;
        }
        index -= 1;
    }

    // SAFETY: index is either zero or one past the retained final slash, both
    // within the caller-supplied nonempty C string.
    unsafe { path.add(index) }
}
