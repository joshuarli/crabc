//! Select the process-name pointers published during x86 libc startup.

use core::ffi::{c_char, c_int};

static EMPTY_PROGRAM_NAME: [u8; 1] = [0];

/// Select full and short process names from the initial argv and `AT_EXECFN`.
///
/// # Safety
///
/// The caller must provide a readable argv vector of at least `argc + 1`
/// pointers and readable NUL-terminated strings for non-null entries. `execfn`
/// must be null or a readable NUL-terminated kernel auxiliary-vector value.
pub(super) unsafe fn select(
    argc: c_int,
    argv: *const *const c_char,
    execfn: *const c_char,
) -> (*const c_char, *const c_char) {
    let full = if argc > 0 && !argv.is_null() && !unsafe { *argv }.is_null() {
        unsafe { *argv }
    } else if !execfn.is_null() {
        execfn
    } else {
        EMPTY_PROGRAM_NAME.as_ptr().cast()
    };
    let mut short = full;
    let mut cursor = full;
    while unsafe { *cursor } != 0 {
        if unsafe { *cursor } as u8 == b'/' {
            short = unsafe { cursor.add(1) };
        }
        cursor = unsafe { cursor.add(1) };
    }
    (full, short)
}

#[cfg(test)]
mod tests {
    use super::select;
    use core::ffi::c_char;

    #[test]
    fn null_argv0_uses_execfn_and_extracts_basename() {
        static EXECFN: &[u8] = b"/srv/app/no-argv0\0";
        let argv = [core::ptr::null::<c_char>()];
        let (full, short) = unsafe {
            select(0, argv.as_ptr(), EXECFN.as_ptr().cast::<c_char>())
        };
        assert_eq!(full, EXECFN.as_ptr().cast());
        assert_eq!(short, unsafe { EXECFN.as_ptr().add(9) }.cast());
    }

    #[test]
    fn absent_execfn_uses_the_empty_program_name() {
        let argv = [core::ptr::null::<c_char>()];
        let (full, short) = unsafe { select(0, argv.as_ptr(), core::ptr::null()) };
        assert_eq!(unsafe { *full }, 0);
        assert_eq!(short, full);
    }
}
