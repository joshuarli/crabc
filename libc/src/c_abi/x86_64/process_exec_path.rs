//! Private Linux/x86-64 PATH-search process-image replacement boundary.
//!
//! This leaf owns `execvp`, strong `__execvpe`, and weak same-address
//! `execvpe`. It composes selected `getenv`/`__environ`, byte-string search,
//! and the direct `execve` sibling, but it does not inspect C varargs or map
//! argv storage. It is not spawn/fork/runtime integration or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/process/execvp.c` maps to the `__execvpe` pathname search, `execvp`,
//! and weak public `execvpe` alias below.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 execvp PATH leaf requires little-endian Linux/x86-64");

use core::{ffi::{c_char, c_int}, ptr};

use super::{environment, errno, process_exec_env, raw_syscall};

const ENOENT: c_int = 2;
const EACCES: c_int = 13;
const ENOTDIR: c_int = 20;
const ENAMETOOLONG: c_int = 36;

const NAME_MAX: usize = 255;
const PATH_MAX: usize = 4_096;

const PATH_NAME: &[u8] = b"PATH\0";
const DEFAULT_PATH: &[u8] = b"/usr/local/bin:/bin:/usr/bin\0";

/// Musl's `__execvpe` pathname-search implementation.
unsafe fn execvpe_impl(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    // Musl performs the PATH lookup before setting its initial ENOENT result.
    let inherited_path = unsafe { environment::getenv(PATH_NAME.as_ptr().cast()) };
    // SAFETY: this is `__execvpe`'s initial no-candidate error state.
    unsafe { errno::set_errno(ENOENT) };

    let result = unsafe { execvpe_raw(file, argv, envp, inherited_path, ptr::null_mut()) };
    if result < 0 { unsafe { errno::set_errno(-result as c_int) }; -1 }
    else { result as c_int }
}

// These scalar string walks keep the clone-vfork child inside private Rust
// code, not an interposable public C string function or a TLS/loader callback.
unsafe fn bounded_length(p: *const c_char, maximum: usize) -> usize {
    let mut n = 0;
    unsafe { while n < maximum && *p.add(n) != 0 { n += 1; } }
    n
}
unsafe fn delimiter(mut p: *const c_char, byte: u8) -> *const c_char {
    unsafe { while *p != 0 && *p as u8 != byte { p = p.add(1); } }
    p
}
unsafe fn record_error(error: c_int, slot: *mut c_int) -> i64 {
    if !slot.is_null() { unsafe { slot.write(error) }; }
    -(error as i64)
}

/// Shared musl PATH algorithm with no errno/TLS/allocator access. Spawn passes
/// its parent's inherited PATH, not envp's PATH. An optional parent-owned slot
/// records each source errno transition across CLONE_VM, including a failed
/// candidate followed by successful exec; the suspended parent publishes it.
/// # Safety
/// File/vectors/PATH remain valid through exec. A non-null error slot names
/// exclusively writable int storage, not a TLS errno address. This function
/// may replace the process and never calls application callbacks.
pub(super) unsafe fn execvpe_raw(
    file: *const c_char, argv: *const *const c_char, envp: *const *const c_char,
    inherited_path: *const c_char, error_slot: *mut c_int,
) -> i64 {
    unsafe { record_error(ENOENT, error_slot); }

    // Like musl, C callers own a non-null readable `file` C string.
    if unsafe { file.cast::<u8>().read() } == 0 {
        return -(ENOENT as i64);
    }
    if unsafe { *delimiter(file, b'/') } != 0 {
        let result = unsafe { raw_syscall::syscall3(59, file as i64, argv as i64, envp as i64) };
        if result < 0 { unsafe { record_error(-result as c_int, error_slot); } }
        return result;
    }

    let path = if inherited_path.is_null() {
        DEFAULT_PATH.as_ptr().cast::<c_char>()
    } else {
        inherited_path
    };
    // This is musl's `strnlen(path, PATH_MAX-1)+1` VLA prefix bound.
    let path_limit = unsafe { bounded_length(path, PATH_MAX - 1) } + 1;
    let file_length = unsafe { bounded_length(file, NAME_MAX + 1) };
    if file_length > NAME_MAX {
        // SAFETY: musl rejects a bare search name longer than NAME_MAX before
        // building any candidate pathname.
        return unsafe { record_error(ENAMETOOLONG, error_slot) };
    }

    // `path_limit <= PATH_MAX`; a nonempty component is strictly shorter than
    // that limit and gains one slash, while the complete file C string is at
    // most NAME_MAX + 1 bytes. This is the fixed Rust storage equivalent of
    // musl's one VLA candidate, not a PATH-search cap.
    let mut candidate = [0u8; PATH_MAX + NAME_MAX + 1];
    let mut cursor = path;
    let mut seen_eacces = false;
    let mut last_error = ENOENT;

    loop {
        // SAFETY: `cursor` stays within the caller's or default terminated
        // PATH string. The private scalar delimiter preserves musl's
        // __strchrnul behavior without an interposable C call in the child.
        let boundary = unsafe { delimiter(cursor, b':') };
        // SAFETY: `boundary` is the colon or terminator found within the same
        // C string that starts at `cursor`.
        let directory_length = unsafe { boundary.offset_from(cursor) as usize };

        if directory_length < path_limit {
            let file_offset = directory_length + usize::from(directory_length != 0);
            if directory_length != 0 {
                // SAFETY: the checked component range and slash fit the
                // fixed candidate storage described above.
                unsafe {
                    ptr::copy_nonoverlapping(
                        cursor.cast::<u8>(),
                        candidate.as_mut_ptr(),
                        directory_length,
                    );
                    ptr::write(candidate.as_mut_ptr().add(directory_length), b'/');
                }
            }
            // SAFETY: the checked file range, including its terminal null,
            // fits immediately after the optional directory slash.
            unsafe {
                ptr::copy_nonoverlapping(
                    file.cast::<u8>(),
                    candidate.as_mut_ptr().add(file_offset),
                    file_length + 1,
                )
            };

            let result = unsafe { raw_syscall::syscall3(59, candidate.as_ptr() as i64, argv as i64, envp as i64) };
            if result >= 0 {
                // Linux execve never normally returns a successful result;
                // preserve any unexpected non-error return rather than
                // inventing a pathname-search errno.
                return result;
            }
            last_error = -result as c_int;
            unsafe { record_error(last_error, error_slot); }
            match last_error {
                EACCES => seen_eacces = true,
                ENOENT | ENOTDIR => {}
                _ => return result,
            }
        }

        // SAFETY: `strchrnul` supplied this readable colon or terminator.
        if unsafe { boundary.read() } == 0 {
            break;
        }
        // SAFETY: a non-null colon has one following byte in the terminated
        // PATH string, including a possible final empty component.
        cursor = unsafe { boundary.add(1) };
    }

    if seen_eacces {
        // SAFETY: match musl's final EACCES precedence over later ENOENT or
        // ENOTDIR candidates. Without EACCES, preserve the final candidate
        // errno exactly as musl does.
        last_error = EACCES;
    }
    unsafe { record_error(last_error, error_slot) }
}

/// Search the selected process `PATH` before replacing the current image.
/// C callers own the file and argv C-string/vector validity requirements.
#[no_mangle]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    let envp = unsafe { process_exec_env::current_environment() };
    unsafe { __execvpe(file, argv, envp) }
}

/// Search the selected process PATH and replace the current image using `envp`.
///
/// C callers must supply a non-null readable NUL-terminated `file` and
/// Linux-valid null-terminated `argv` and `envp` vectors for the syscall
/// duration. PATH is read from the selected global environment, not `envp`;
/// successful image replacement does not return.
#[no_mangle]
pub unsafe extern "C" fn __execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    unsafe { execvpe_impl(file, argv, envp) }
}

// Pinned musl exposes the public GNU/BSD spelling as a weak alias, not a
// forwarding body. Keeping `execvpe` at the same ELF address means a static
// consumer can provide a strong public replacement without creating a second
// implementation or changing the internal `__execvpe` owner.
core::arch::global_asm!(
    r#"
    .weak execvpe
    .set execvpe, __execvpe
    .section .note.GNU-stack,"",@progbits
"#,
);
