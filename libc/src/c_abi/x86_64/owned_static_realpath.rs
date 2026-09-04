//! Owned-static Linux/x86-64 `realpath` support.
//!
//! This is a source-faithful translation of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/misc/realpath.c::slash_len` and `::realpath`.  In particular it keeps
//! musl's bounded remaining-component stack, component/`..` cancellation,
//! relative symlink expansion, double-slash spelling, `PATH_MAX` and
//! `SYMLOOP_MAX` limits, final directory check, caller-buffer versus allocated
//! result split, and every named errno exit.
//!
//! The existing x86 owners supply the source's adjacent ABI boundaries:
//! `byte_strings::strchrnul`/`strnlen`/`strlen`,
//! `pathname_lifecycle::readlink`/`getcwd`, and the opt-in
//! `allocator_string_duplication::strdup`.  That reuses their independently
//! tested semantics instead of reintroducing the pinned musl `strchrnul.lo`,
//! `strdup.lo`, or syscall support objects.  The only intentional lexical
//! difference is expressing C pointer arithmetic and `memcpy`/`memmove` in
//! bounded Rust raw-pointer operations over the same fixed local arrays.
//!
//! This owner is a C ABI compatibility boundary, not a filesystem sandbox:
//! pathname races, symlink authority, and all caller pointer/lifetime
//! requirements remain the caller's responsibility.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("owned static realpath support requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int};
use core::ptr::null_mut;

use super::{allocator_string_duplication, byte_strings, errno, pathname_lifecycle};

const PATH_MAX: usize = 4096;
const SYMLOOP_MAX: usize = 40;

const ENOENT: c_int = 2;
const EINVAL: c_int = 22;
const ENAMETOOLONG: c_int = 36;
const ELOOP: c_int = 40;

/// Return the contiguous slash run beginning at `cursor`.
///
/// # Safety
///
/// `cursor` must point into a NUL-terminated remainder of the private stack
/// array.  This exactly matches musl's source helper, including its one-byte
/// reads through the final terminator.
#[inline]
unsafe fn slash_len(mut cursor: *const u8) -> usize {
    let start = cursor;
    // SAFETY: the helper contract retains a readable current private-stack
    // byte until the first non-slash, including its NUL terminator.
    while unsafe { cursor.read() } == b'/' {
        // SAFETY: a slash is non-NUL, so this private C-string remainder has
        // a following byte.
        cursor = unsafe { cursor.add(1) };
    }
    cursor as usize - start as usize
}

/// Consume following slashes after one musl main-loop iteration.
///
/// # Safety
///
/// `position` must name a valid private-stack index whose suffix has the
/// NUL-termination invariant established by [`realpath`].
#[inline]
unsafe fn advance_slashes(stack: &[u8; PATH_MAX + 1], position: &mut usize) {
    // SAFETY: all caller states preserve the private stack remainder's
    // terminator and position bounds exactly as the C source's loop update.
    *position += unsafe { slash_len(stack.as_ptr().add(*position)) };
}

#[inline]
fn failure(error: c_int) -> *mut c_char {
    // SAFETY: this target-local C ABI owner publishes errors only through the
    // existing calling-thread initial-TLS errno slot.
    unsafe { errno::set_errno(error) };
    null_mut()
}

/// Resolve one C pathname with musl 1.2.6's component and symlink algorithm.
///
/// # Safety
///
/// `filename` must be null or point to a readable NUL-terminated pathname.
/// When non-null, `resolved` must be writable for the result's complete
/// terminator-inclusive byte range; as in C's `restrict` declaration, it may
/// not overlap `filename`.  A null `resolved` selects allocation through the
/// existing `strdup` owner.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn realpath(
    filename: *const c_char,
    resolved: *mut c_char,
) -> *mut c_char {
    let mut stack = [0_u8; PATH_MAX + 1];
    let mut output = [0_u8; PATH_MAX];
    let mut p: usize;
    let mut q: usize = 0;
    let mut component_length: usize;
    let mut original_component_length: usize;
    let mut links_seen: usize = 0;
    let mut upward_components: usize = 0;
    let mut check_directory = false;

    if filename.is_null() {
        return failure(EINVAL);
    }
    // SAFETY: the C API requires a readable filename C string; the bounded
    // scan is exactly the source's `strnlen(filename, sizeof stack)`.
    let filename_length = unsafe { byte_strings::strnlen(filename, stack.len()) };
    if filename_length == 0 {
        return failure(ENOENT);
    }
    if filename_length >= PATH_MAX {
        return failure(ENAMETOOLONG);
    }
    p = stack.len() - filename_length - 1;
    // SAFETY: `filename_length < PATH_MAX` reserves this complete copied
    // source prefix and NUL terminator in the fixed private stack.
    unsafe {
        core::ptr::copy_nonoverlapping(
            filename.cast::<u8>(),
            stack.as_mut_ptr().add(p),
            filename_length + 1,
        );
    }

    // `restart` is musl's label used after pushing a symlink target into the
    // remaining-component stack.  Every other loop continuation performs the
    // source's `p += slash_len(stack+p)` update explicitly.
    'restart: loop {
        loop {
            if stack[p] == b'/' {
                check_directory = false;
                upward_components = 0;
                q = 0;
                output[q] = b'/';
                q += 1;
                p += 1;
                // Preserve musl's initial `//` spelling, but collapse a
                // longer slash run to one slash.
                if stack[p] == b'/' && stack[p + 1] != b'/' {
                    output[q] = b'/';
                    q += 1;
                }
                // SAFETY: the private stack remains NUL-terminated.
                unsafe { advance_slashes(&stack, &mut p) };
                continue;
            }

            let component_start = p;
            // SAFETY: `p` identifies the beginning of the current private
            // stack component, whose suffix stays NUL-terminated throughout
            // the source algorithm.
            let component_start_pointer = unsafe { stack.as_ptr().add(component_start) };
            // SAFETY: `stack + p` is a private NUL-terminated C string.
            let component_end = unsafe {
                byte_strings::strchrnul(stack.as_ptr().add(p).cast(), b'/' as c_int)
            }
            .cast::<u8>();
            original_component_length = component_end as usize - component_start_pointer as usize;
            component_length = original_component_length;

            if component_length == 0 && !check_directory {
                break;
            }

            // Keep `check_directory` intact for a `.` component, precisely as
            // musl does before it moves to the following slash run.
            if component_length == 1 && stack[p] == b'.' {
                p += component_length;
                // SAFETY: the private stack remains NUL-terminated.
                unsafe { advance_slashes(&stack, &mut p) };
                continue;
            }

            // Prepend the output separator to the remaining stack component
            // when output currently ends in a name.  `p == 0` is the source's
            // exact remaining-stack exhaustion failure.
            if q != 0 && output[q - 1] != b'/' {
                if p == 0 {
                    return failure(ENAMETOOLONG);
                }
                p -= 1;
                stack[p] = b'/';
                component_length += 1;
            }
            if q + component_length >= PATH_MAX {
                return failure(ENAMETOOLONG);
            }
            // SAFETY: source and destination are distinct fixed arrays, and
            // the preceding bound reserves the copied bytes plus output NUL.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    stack.as_ptr().add(p),
                    output.as_mut_ptr().add(q),
                    component_length,
                );
            }
            output[q + component_length] = 0;
            p += component_length;

            let mut upward = false;
            if original_component_length == 2
                && stack[p - 2] == b'.'
                && stack[p - 1] == b'.'
            {
                upward = true;
                // The source stores unmatched leading `..` components in the
                // output until a later relative-CWD reconciliation.
                if q <= 3 * upward_components {
                    upward_components += 1;
                    q += component_length;
                    // SAFETY: the private stack remains NUL-terminated.
                    unsafe { advance_slashes(&stack, &mut p) };
                    continue;
                }
            }

            // Musl skips readlink for a cancellable `..` only when the prior
            // component was not known to be a directory.  Otherwise preserve
            // its temporary output spelling and ask the kernel whether it is
            // a symlink before cancellation.
            let skip_readlink = upward && !check_directory;
            let link_length = if skip_readlink {
                -1
            } else {
                // SAFETY: `output` is NUL-terminated at the copied component
                // and `stack` reserves `p` writable target bytes.
                unsafe {
                    pathname_lifecycle::readlink(
                        output.as_ptr().cast(),
                        stack.as_mut_ptr().cast(),
                        p,
                    )
                }
            };

            if link_length == p as isize {
                return failure(ENAMETOOLONG);
            }
            if link_length == 0 {
                return failure(ENOENT);
            }
            if link_length < 0 {
                // A normal non-symlink component reports EINVAL.  The
                // skip-readlink branch enters this same source label without
                // observing errno.
                if !skip_readlink && unsafe { errno::get_errno() } != EINVAL {
                    return null_mut();
                }
                check_directory = false;
                if upward {
                    while q != 0 && output[q - 1] != b'/' {
                        q -= 1;
                    }
                    if q > 1 && (q > 2 || output[0] != b'/') {
                        q -= 1;
                    }
                    // SAFETY: the private stack remains NUL-terminated.
                    unsafe { advance_slashes(&stack, &mut p) };
                    continue;
                }
                if original_component_length != 0 {
                    q += component_length;
                }
                check_directory = stack[p] != 0;
                // SAFETY: the private stack remains NUL-terminated.
                unsafe { advance_slashes(&stack, &mut p) };
                continue;
            }

            links_seen += 1;
            if links_seen == SYMLOOP_MAX {
                return failure(ELOOP);
            }
            let link_length = link_length as usize;

            // If a link target has a trailing slash, consume already-pending
            // slashes before pushing it.  This preserves musl's `//` and
            // PATH_MAX behavior exactly.
            if stack[link_length - 1] == b'/' {
                while stack[p] == b'/' {
                    p += 1;
                }
            }
            p -= link_length;
            // SAFETY: `link_length < p_before` above reserves the destination
            // prefix.  `ptr::copy` is Rust's overlap-safe `memmove`, matching
            // the source's self-stack move.
            unsafe {
                core::ptr::copy(stack.as_ptr(), stack.as_mut_ptr().add(p), link_length);
            }
            continue 'restart;
        }

        output[q] = 0;
        if output[0] != b'/' {
            // SAFETY: stack is complete private writable PATH_MAX+1 storage.
            if unsafe { pathname_lifecycle::getcwd(stack.as_mut_ptr().cast(), stack.len()) }
                .is_null()
            {
                return null_mut();
            }
            // SAFETY: successful getcwd returned a NUL-terminated private C
            // string, matching the source's `strlen(stack)`.
            let mut cwd_length = unsafe { byte_strings::strlen(stack.as_ptr().cast()) };
            p = 0;
            while upward_components != 0 {
                while cwd_length > 1 && stack[cwd_length - 1] != b'/' {
                    cwd_length -= 1;
                }
                if cwd_length > 1 {
                    cwd_length -= 1;
                }
                p += 2;
                if p < q {
                    p += 1;
                }
                upward_components -= 1;
            }
            if q - p != 0 && stack[cwd_length - 1] != b'/' {
                stack[cwd_length] = b'/';
                cwd_length += 1;
            }
            if cwd_length + (q - p) + 1 >= PATH_MAX {
                return failure(ENAMETOOLONG);
            }
            // SAFETY: the source's `memmove` range is bounded by the length
            // check above and `q` includes the NUL at this point.
            unsafe {
                core::ptr::copy(
                    output.as_ptr().add(p),
                    output.as_mut_ptr().add(cwd_length),
                    q - p + 1,
                );
                core::ptr::copy_nonoverlapping(
                    stack.as_ptr(),
                    output.as_mut_ptr(),
                    cwd_length,
                );
            }
            q = cwd_length + q - p;
        }

        if !resolved.is_null() {
            // SAFETY: the caller supplied a non-overlapping output range for
            // the source-computed terminator-inclusive result length.
            unsafe { core::ptr::copy_nonoverlapping(output.as_ptr().cast(), resolved, q + 1) };
            return resolved;
        }
        // SAFETY: output is a complete private NUL-terminated C string; the
        // selected existing duplication owner returns allocation-owned output
        // or its own ENOMEM failure without retaining a partial result.
        return unsafe { allocator_string_duplication::strdup(output.as_ptr().cast()) };
    }
}
