//! Local shadow-file C ABI for the owned Linux/x86-64 runtime.
//!
//! Source map and provenance: musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license
//! (`COPYRIGHT`, pinned in `compat/upstreams.toml`).
//!
//! | musl source (SHA-256) | definition here |
//! | --- | --- |
//! | `src/passwd/getspent.c` (`ff51e025d46e18d362ff37ba68c5025cd18437d4f08e499db2b8e48af3e01f99`) | [`setspent`], [`endspent`], [`getspent`] |
//! | `src/passwd/fgetspent.c` (`0e81db6aebfa337e30d478d10a933044d7960a1fd8b8e952a6d250d33b8b504a`) | [`fgetspent`] and `FGETSPENT_*` |
//! | `src/passwd/getspnam.c` (`dbc13dbbd8fcc7698801cb82845adc1196e5aaa280356fccf5678a7f4fed1466`) | [`getspnam`] and `GETSPNAM_*` |
//! | `src/passwd/getspnam_r.c` (`f40349a00c75b2d2a8075fdc6a80e54daa9ddc9b162b89cd358a5bc93bd5d884`) | `xatol`/`__parsespent`/`cleanup`/`getspnam_r` → `spent_decimal`, `parse_spent`, `close_stream`, [`getspnam_r`] |
//! | `src/passwd/putspent.c` (`39cbd6f3f9a82830a7c7772ca1760ab31a92f3d354450d2e332857e22988531b`) | [`putspent`] |
//! | `src/passwd/lckpwdf.c` (`744d2f5a8b33aabec44f36b31f58ab3b5d845c10b88ede2fa86fce397b06a7a6`) | [`lckpwdf`], [`ulckpwdf`] |
//! | `src/passwd/pwf.h` (`61df7ac8807db4a8f838ca67f96072cc0c62d2be3a114ee06fea77bdc94a523a`) | source declarations, `Shadow`, and selected owned stdio/errno/cancellation boundary |
//!
//! This is C ABI compatibility machinery over conventional local files, not
//! an authentication service. Password-hash fields are opaque bytes. It adds
//! no hash, PRNG, provider/NSS lookup, cache, plugin, policy, or account
//! mutation. `getspnam_r` retains musl's bounded Openwall-style TCB probe:
//! `/etc/tcb/NAME/shadow` is opened with no symlink following or blocking,
//! checked as a regular file, and falls back to `/etc/shadow` only when that
//! TCB pathname is absent or has a non-directory component.
//!
//! The non-reentrant `fgetspent` and `getspnam` storage is process global,
//! exactly as in the source. Callers serialize each API and every use of its
//! borrowed result. `getspent`, `setspent`, `endspent`, `lckpwdf`, and
//! `ulckpwdf` deliberately remain source no-ops; they do not introduce a
//! shadow cursor, lock file, or authentication lock. The caller-owned `_r`
//! API has the usual C pointer/range obligations documented below.

use core::{
    ffi::{c_char, c_int, c_long, c_ulong, c_void},
    mem::MaybeUninit,
    ptr,
};

use super::{
    descriptor_entry, descriptor_io, errno, pthread_cancel, stat_compat,
    stdio_format_scan, stdio_standard as stdio,
};
use stdio::StandardStream;

const EINVAL: c_int = 22;
const ENOENT: c_int = 2;
const ENOTDIR: c_int = 20;
const ERANGE: c_int = 34;
const PTHREAD_CANCEL_DISABLE: c_int = 1;
const LINE_LIM: usize = 256;
const NAME_MAX: usize = 255;
const TCB_PATH_CAPACITY: usize = 20 + NAME_MAX;
const O_NONBLOCK: c_int = 0o4000;
const O_NOFOLLOW: c_int = 0o400000;
const O_CLOEXEC: c_int = 0o2000000;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

const TCB_PREFIX: &[u8] = b"/etc/tcb/";
const TCB_SUFFIX: &[u8] = b"/shadow";
const SHADOW_PATH: &[u8] = b"/etc/shadow\0";
const READ_BINARY_MODE: &[u8] = b"rb\0";
const READ_BINARY_CLOEXEC_MODE: &[u8] = b"rbe\0";

/// The installed LP64 `struct spwd` record from `include/shadow.h`.
#[repr(C)]
pub struct Shadow {
    pub name: *mut c_char,
    pub password: *mut c_char,
    pub last_change: c_long,
    pub minimum: c_long,
    pub maximum: c_long,
    pub warning: c_long,
    pub inactive: c_long,
    pub expire: c_long,
    pub flag: c_ulong,
}

const EMPTY_SHADOW: Shadow = Shadow {
    name: ptr::null_mut(),
    password: ptr::null_mut(),
    last_change: 0,
    minimum: 0,
    maximum: 0,
    warning: 0,
    inactive: 0,
    expire: 0,
    flag: 0,
};

// `fgetspent.c` gives each call a fresh `size = 0`, while retaining these
// process-global line/record objects. Do not fold this into an enumerator:
// musl's getspent.c is deliberately a null-returning no-op.
static mut FGETSPENT_LINE: *mut c_char = ptr::null_mut();
static mut FGETSPENT_RECORD: Shadow = EMPTY_SHADOW;

// getspnam.c retains exactly one fixed 256-byte public-malloc line and one
// record. It is independent from fgetspent's static line and record.
static mut GETSPNAM_LINE: *mut c_char = ptr::null_mut();
static mut GETSPNAM_RECORD: Shadow = EMPTY_SHADOW;

// `getspnam.c` calls ordinary C malloc. Retain an opaque call edge so a
// same-crate Rust declaration cannot fold the source client into a known
// allocator provider before the public ELF boundary. The allocation persists
// for process lifetime in the source, so there is intentionally no free tail.
core::arch::global_asm!(r#"
    .text
    .p2align 4
    .globl __crabc_x86_shadow_cabi_malloc
    .hidden __crabc_x86_shadow_cabi_malloc
    .type __crabc_x86_shadow_cabi_malloc,@function
__crabc_x86_shadow_cabi_malloc:
    jmp malloc
    .size __crabc_x86_shadow_cabi_malloc, .-__crabc_x86_shadow_cabi_malloc
"#);

unsafe extern "C" {
    #[link_name = "__crabc_x86_shadow_cabi_malloc"]
    fn shadow_cabi_malloc(size: usize) -> *mut c_void;
}

#[inline]
unsafe fn c_strlen(mut text: *const c_char) -> usize {
    let mut length = 0usize;
    unsafe {
        while *text != 0 {
            length += 1;
            text = text.add(1);
        }
    }
    length
}

#[inline]
unsafe fn c_strchr(mut text: *mut c_char, needle: c_char) -> *mut c_char {
    unsafe {
        while *text != 0 {
            if *text == needle {
                return text;
            }
            text = text.add(1);
        }
    }
    ptr::null_mut()
}

// This is musl getspnam_r.c's xatol. An empty field is -1; otherwise only
// initial decimal bytes are consumed. The source's signed-long arithmetic is
// retained as target-width wrapping arithmetic rather than adding a range or
// sign policy around administrator-owned file bytes.
#[inline]
unsafe fn spent_decimal(cursor: &mut *mut c_char) -> c_long {
    unsafe {
        if **cursor == b':' as c_char || **cursor == b'\n' as c_char {
            return -1;
        }
        let mut value: c_long = 0;
        while (**cursor as u8).wrapping_sub(b'0') < 10 {
            value = value
                .wrapping_mul(10)
                .wrapping_add((**cursor as u8 - b'0') as c_long);
            *cursor = (*cursor).add(1);
        }
        value
    }
}

// Direct in-place translation of __parsespent. It deliberately leaves partial
// record writes visible on malformed input, accepts empty numeric fields as
// -1, requires a literal final newline, and does not add a text encoding rule.
unsafe fn parse_spent(mut text: *mut c_char, record: *mut Shadow) -> c_int {
    unsafe {
        (*record).name = text;
        text = c_strchr(text, b':' as c_char);
        if text.is_null() {
            return -1;
        }
        *text = 0;

        text = text.add(1);
        (*record).password = text;
        text = c_strchr(text, b':' as c_char);
        if text.is_null() {
            return -1;
        }
        *text = 0;

        text = text.add(1);
        (*record).last_change = spent_decimal(&mut text);
        if *text != b':' as c_char {
            return -1;
        }
        text = text.add(1);
        (*record).minimum = spent_decimal(&mut text);
        if *text != b':' as c_char {
            return -1;
        }
        text = text.add(1);
        (*record).maximum = spent_decimal(&mut text);
        if *text != b':' as c_char {
            return -1;
        }
        text = text.add(1);
        (*record).warning = spent_decimal(&mut text);
        if *text != b':' as c_char {
            return -1;
        }
        text = text.add(1);
        (*record).inactive = spent_decimal(&mut text);
        if *text != b':' as c_char {
            return -1;
        }
        text = text.add(1);
        (*record).expire = spent_decimal(&mut text);
        if *text != b':' as c_char {
            return -1;
        }
        text = text.add(1);
        (*record).flag = spent_decimal(&mut text) as c_ulong;
        if *text != b'\n' as c_char {
            return -1;
        }
        0
    }
}

#[inline]
unsafe fn name_prefix_matches(name: *const c_char, line: *const c_char, length: usize) -> bool {
    unsafe {
        for offset in 0..length {
            if *name.add(offset) != *line.add(offset) {
                return false;
            }
        }
    }
    true
}

/// Source cleanup callback for the `getspnam_r` scan.
///
/// The stream pointer is registered in the current selected pthread cleanup
/// chain before the scan begins. It stays a raw C pointer, rather than a Rust
/// borrow, across calls which may retire the current task.
unsafe extern "C" fn close_stream(argument: *mut c_void) {
    let stream = argument.cast::<StandardStream>();
    if !stream.is_null() {
        unsafe {
            let _ = stdio::fclose(stream);
        }
    }
}

/// Do nothing, exactly as musl `src/passwd/getspent.c::setspent`.
///
/// # Safety
/// This function owns no state and dereferences no caller data. It does not
/// reset a shadow cursor because this selected source has no cursor.
#[no_mangle]
pub unsafe extern "C" fn setspent() {}

/// Do nothing, exactly as musl `src/passwd/getspent.c::endspent`.
///
/// # Safety
/// This function owns no state and dereferences no caller data.
#[no_mangle]
pub unsafe extern "C" fn endspent() {}

/// Return null, exactly as musl `getspent.c`.
///
/// # Safety
/// This source compatibility entry has no caller pointers and does not read a
/// shadow file. Use [`getspnam`] or [`getspnam_r`] for the selected lookup.
#[no_mangle]
pub unsafe extern "C" fn getspent() -> *mut Shadow {
    ptr::null_mut()
}

/// Parse exactly one caller-owned FILE line into fgetspent's shared record.
///
/// # Safety
/// `stream` is a live readable owned FILE for this call. Callers serialize
/// `fgetspent` and every use of its result; a later call can reallocate the
/// shared line and overwrite the record. The stream remains caller-owned.
#[no_mangle]
pub unsafe extern "C" fn fgetspent(stream: *mut StandardStream) -> *mut Shadow {
    unsafe {
        let mut size = 0usize;
        let mut result = ptr::null_mut();
        let mut cancellation_state = 0;
        pthread_cancel::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut cancellation_state);
        if stdio::getline(&raw mut FGETSPENT_LINE, &mut size, stream) >= 0
            && parse_spent(FGETSPENT_LINE, &raw mut FGETSPENT_RECORD) >= 0
        {
            result = &raw mut FGETSPENT_RECORD;
        }
        pthread_cancel::pthread_setcancelstate(cancellation_state, ptr::null_mut());
        result
    }
}

/// Look up one local shadow record in caller-owned record and byte storage.
///
/// # Safety
/// `name` is readable through NUL. `record`, `buffer` for `size` bytes, and
/// `result` are writable, aligned, and mutually non-overlapping. `result`
/// must be valid even on input errors because musl stores null into it before
/// validation. On success, strings in `record` borrow `buffer`; do not use
/// partial record writes when this function returns a nonzero value or a null
/// result. The caller owns file-resolution races and serializes mutations of
/// the conventional files it selects.
#[no_mangle]
pub unsafe extern "C" fn getspnam_r(
    name: *const c_char,
    record: *mut Shadow,
    buffer: *mut c_char,
    size: usize,
    result: *mut *mut Shadow,
) -> c_int {
    unsafe {
        let original_errno = errno::get_errno();
        let name_length = c_strlen(name);
        *result = ptr::null_mut();

        // Keep the source's validation order and errno/output behavior.
        if *name == b'.' as c_char || c_strchr(name.cast_mut(), b'/' as c_char) != ptr::null_mut()
            || name_length == 0
        {
            errno::set_errno(EINVAL);
            return EINVAL;
        }
        if size < name_length.wrapping_add(100) {
            errno::set_errno(ERANGE);
            return ERANGE;
        }

        let mut path = [0 as c_char; TCB_PATH_CAPACITY];
        let required_path_bytes = TCB_PREFIX
            .len()
            .wrapping_add(name_length)
            .wrapping_add(TCB_SUFFIX.len());
        if required_path_bytes >= path.len() {
            errno::set_errno(EINVAL);
            return EINVAL;
        }
        for (index, byte) in TCB_PREFIX.iter().enumerate() {
            path[index] = *byte as c_char;
        }
        for index in 0..name_length {
            path[TCB_PREFIX.len() + index] = *name.add(index);
        }
        for (index, byte) in TCB_SUFFIX.iter().enumerate() {
            path[TCB_PREFIX.len() + name_length + index] = *byte as c_char;
        }

        let descriptor = descriptor_entry::open(
            path.as_ptr(),
            O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
            0,
        );
        let stream: *mut StandardStream;
        if descriptor >= 0 {
            // The source preloads EINVAL for a non-regular descriptor and
            // returns the errno left by fstat/fdopen/close in this branch.
            errno::set_errno(EINVAL);
            let regular = match stat_compat::fstat_mode(descriptor) {
                Ok(mode) => mode & S_IFMT == S_IFREG,
                Err(error) => {
                    errno::set_errno(error);
                    false
                }
            };
            stream = if regular {
                stdio::fdopen(descriptor, READ_BINARY_MODE.as_ptr().cast())
            } else {
                ptr::null_mut()
            };
            if stream.is_null() {
                let mut cancellation_state = 0;
                pthread_cancel::pthread_setcancelstate(
                    PTHREAD_CANCEL_DISABLE,
                    &mut cancellation_state,
                );
                let _ = descriptor_io::close(descriptor);
                pthread_cancel::pthread_setcancelstate(cancellation_state, ptr::null_mut());
                return errno::get_errno();
            }
        } else {
            let open_error = errno::get_errno();
            if open_error != ENOENT && open_error != ENOTDIR {
                return open_error;
            }
            stream = stdio::fopen(SHADOW_PATH.as_ptr().cast(), READ_BINARY_CLOEXEC_MODE.as_ptr().cast());
            if stream.is_null() {
                let fallback_error = errno::get_errno();
                if fallback_error != ENOENT && fallback_error != ENOTDIR {
                    return fallback_error;
                }
                return 0;
            }
        }

        // This is pthread_cleanup_push(cleanup, stream) around musl's fgets
        // loop. The raw node stays valid until the explicit pop or selected
        // pthread retirement; no Rust destructor or borrowed stream reference
        // crosses that cancellation boundary.
        let mut cleanup = MaybeUninit::<pthread_cancel::CleanupNode>::uninit();
        pthread_cancel::_pthread_cleanup_push(
            cleanup.as_mut_ptr(),
            Some(close_stream),
            stream.cast(),
        );

        let mut return_value = 0;
        let mut skip = false;
        loop {
            if stdio::fgets(buffer, size as c_int, stream).is_null() {
                break;
            }
            let line_length = c_strlen(buffer);
            // `while (fgets(...) && (k=strlen(buf))>0)` exits on an embedded
            // initial NUL rather than treating it as an invalid line to skip.
            if line_length == 0 {
                break;
            }
            if skip || !name_prefix_matches(name, buffer, name_length)
                || *buffer.add(name_length) != b':' as c_char
            {
                skip = *buffer.add(line_length - 1) != b'\n' as c_char;
                continue;
            }
            if *buffer.add(line_length - 1) != b'\n' as c_char {
                return_value = ERANGE;
                break;
            }
            if parse_spent(buffer, record) < 0 {
                continue;
            }
            *result = record;
            break;
        }

        // Source uses pthread_cleanup_pop(1), so the ordinary path closes the
        // file through the same callback used by selected deferred retirement.
        pthread_cancel::_pthread_cleanup_pop(cleanup.as_mut_ptr(), 1);
        errno::set_errno(if return_value != 0 {
            return_value
        } else {
            original_errno
        });
        return_value
    }
}

/// Look up one local shadow record in getspnam's shared 256-byte line.
///
/// # Safety
/// `name` is readable through NUL. Callers serialize this function and all
/// access to its borrowed shared result; any later call can overwrite it.
#[no_mangle]
pub unsafe extern "C" fn getspnam(name: *const c_char) -> *mut Shadow {
    unsafe {
        // getspnam.c saves this before its one-time ordinary-malloc call.
        // Successful allocation is not permitted to change the caller's
        // observable errno on a successful or absent lookup.
        let original_errno = errno::get_errno();
        if GETSPNAM_LINE.is_null() {
            GETSPNAM_LINE = shadow_cabi_malloc(LINE_LIM).cast();
        }
        if GETSPNAM_LINE.is_null() {
            return ptr::null_mut();
        }
        let mut result = ptr::null_mut();
        let error = getspnam_r(
            name,
            &raw mut GETSPNAM_RECORD,
            GETSPNAM_LINE,
            LINE_LIM,
            &mut result,
        );
        errno::set_errno(if error != 0 { error } else { original_errno });
        result
    }
}

/// Write one shadow record with musl's literal precision-based empty `-1` form.
///
/// # Safety
/// `record` points to one readable `struct spwd`; non-null string fields are
/// readable through NUL. `stream` is a live writable owned FILE. Fields are
/// emitted literally without escaping or validation.
#[no_mangle]
pub unsafe extern "C" fn putspent(record: *const Shadow, stream: *mut StandardStream) -> c_int {
    unsafe {
        let source = &*record;
        let string = |value: *mut c_char| {
            if value.is_null() { c"".as_ptr() } else { value as *const c_char }
        };
        let signed_precision = |value: c_long| if value == -1 { 0 } else { -1 };
        let signed_value = |value: c_long| if value == -1 { 0 } else { value };
        let flag_precision = |value: c_ulong| if value == c_ulong::MAX { 0 } else { -1 };
        let flag_value = |value: c_ulong| if value == c_ulong::MAX { 0 } else { value };
        if stdio_format_scan::fprintf(
            stream,
            c"%s:%s:%.*ld:%.*ld:%.*ld:%.*ld:%.*ld:%.*ld:%.*lu\n".as_ptr(),
            string(source.name),
            string(source.password),
            signed_precision(source.last_change), signed_value(source.last_change),
            signed_precision(source.minimum), signed_value(source.minimum),
            signed_precision(source.maximum), signed_value(source.maximum),
            signed_precision(source.warning), signed_value(source.warning),
            signed_precision(source.inactive), signed_value(source.inactive),
            signed_precision(source.expire), signed_value(source.expire),
            flag_precision(source.flag), flag_value(source.flag),
        ) < 0 {
            -1
        } else {
            0
        }
    }
}

/// Return success without acquiring a password lock, as musl `lckpwdf.c` does.
///
/// # Safety
/// This source-compatible no-op neither dereferences caller data nor owns a
/// file descriptor or lock state.
#[no_mangle]
pub unsafe extern "C" fn lckpwdf() -> c_int {
    0
}

/// Return success without releasing a password lock, as musl `lckpwdf.c` does.
///
/// # Safety
/// This source-compatible no-op neither dereferences caller data nor owns a
/// file descriptor or lock state.
#[no_mangle]
pub unsafe extern "C" fn ulckpwdf() -> c_int {
    0
}
