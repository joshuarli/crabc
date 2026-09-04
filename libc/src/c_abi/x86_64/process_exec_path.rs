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

use super::{byte_strings, environment, errno, process_exec, process_exec_env};

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

    // Like musl, C callers own a non-null readable `file` C string.
    if unsafe { file.cast::<u8>().read() } == 0 {
        return -1;
    }
    if !unsafe { byte_strings::strchr(file, b'/' as c_int) }.is_null() {
        return unsafe { process_exec::execve_result(file, argv, envp) };
    }

    let path = if inherited_path.is_null() {
        DEFAULT_PATH.as_ptr().cast::<c_char>()
    } else {
        inherited_path.cast_const()
    };
    // This is musl's `strnlen(path, PATH_MAX-1)+1` VLA prefix bound.
    let path_limit = unsafe { byte_strings::strnlen(path, PATH_MAX - 1) } + 1;
    let file_length = unsafe { byte_strings::strnlen(file, NAME_MAX + 1) };
    if file_length > NAME_MAX {
        // SAFETY: musl rejects a bare search name longer than NAME_MAX before
        // building any candidate pathname.
        unsafe { errno::set_errno(ENAMETOOLONG) };
        return -1;
    }

    // `path_limit <= PATH_MAX`; a nonempty component is strictly shorter than
    // that limit and gains one slash, while the complete file C string is at
    // most NAME_MAX + 1 bytes. This is the fixed Rust storage equivalent of
    // musl's one VLA candidate, not a PATH-search cap.
    let mut candidate = [0u8; PATH_MAX + NAME_MAX + 1];
    let mut cursor = path;
    let mut seen_eacces = false;

    loop {
        // SAFETY: `cursor` stays within the caller's or default terminated
        // PATH string. The selected byte-string leaf implements musl's
        // scalar `__strchrnul` behavior.
        let boundary = unsafe { byte_strings::strchrnul(cursor, b':' as c_int) }.cast_const();
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

            let result = unsafe { process_exec::execve_result(candidate.as_ptr().cast(), argv, envp) };
            if result != -1 {
                // Linux execve never normally returns a successful result;
                // preserve any unexpected non-error return rather than
                // inventing a pathname-search errno.
                return result;
            }
            match unsafe { errno::get_errno() } {
                EACCES => seen_eacces = true,
                ENOENT | ENOTDIR => {}
                _ => return -1,
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
        unsafe { errno::set_errno(EACCES) };
    }
    -1
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
