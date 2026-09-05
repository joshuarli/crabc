//! Source-faithful musl 1.2.6 `src/regex/glob.c` expansion owner.
//!
//! `glob_t` owns a vector of pointers into one `Match` allocation per result;
//! `globfree` recovers each allocation from that flexible-array pointer. The
//! public C record is therefore deliberately kept at this boundary instead of
//! borrowing the Rust facade's explicit-root traversal result type. Tilde
//! lookup calls the separately owned conventional-passwd C ABI, exactly as
//! musl's source calls `getpwnam_r`/`getpwuid_r`; there is no host-libc or
//! oracle fallback.

use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    mem::size_of,
    ptr,
};

use super::super::{
    directory_streams, environment, errno, owned_passwd, process_context, stat_compat,
};

const PATH_MAX: usize = 4_096;
const DT_DIR: u8 = 4;
const DT_LNK: u8 = 10;
const DT_REG: u8 = 8;
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

const ENOENT: c_int = 2;
const ENOMEM: c_int = 12;

const FNM_NOESCAPE: c_int = 0x2;
const FNM_PERIOD: c_int = 0x4;

const GLOB_ERR: c_int = 0x01;
const GLOB_MARK: c_int = 0x02;
const GLOB_NOSORT: c_int = 0x04;
const GLOB_DOOFFS: c_int = 0x08;
const GLOB_NOCHECK: c_int = 0x10;
const GLOB_APPEND: c_int = 0x20;
const GLOB_NOESCAPE: c_int = 0x40;
const GLOB_PERIOD: c_int = 0x80;
const GLOB_TILDE: c_int = 0x1000;
const GLOB_TILDE_CHECK: c_int = 0x4000;

const GLOB_NOSPACE: c_int = 1;
const GLOB_ABORTED: c_int = 2;
const GLOB_NOMATCH: c_int = 3;

const HOME: &[u8] = b"HOME\0";
const EMPTY: &[u8] = b"\0";

/// Installed x86 `glob_t`, whose header is the public layout authority.
#[repr(C)]
pub(super) struct Glob {
    path_count: usize,
    path_vector: *mut *mut c_char,
    offsets: usize,
    _dummy1: c_int,
    _dummy2: [*mut c_void; 5],
}

/// Musl's flexible `struct match`; the pathname begins immediately after this
/// one pointer word in the same allocation.
#[repr(C)]
struct Match {
    next: *mut Match,
}

type ErrorFunction = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type SortFunction = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

unsafe extern "C" {
    #[link_name = "malloc"]
    fn cabi_malloc(size: usize) -> *mut c_void;
    #[link_name = "realloc"]
    fn cabi_realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn cabi_free(pointer: *mut c_void);
    #[link_name = "qsort"]
    fn cabi_qsort(base: *mut c_void, count: usize, size: usize, compare: SortFunction);
    fn getpwnam_r(
        name: *const c_char,
        passwd: *mut owned_passwd::Passwd,
        buffer: *mut c_char,
        capacity: usize,
        result: *mut *mut owned_passwd::Passwd,
    ) -> c_int;
    fn getpwuid_r(
        uid: c_uint,
        passwd: *mut owned_passwd::Passwd,
        buffer: *mut c_char,
        capacity: usize,
        result: *mut *mut owned_passwd::Passwd,
    ) -> c_int;
}

#[inline]
unsafe fn byte(pointer: *const c_char) -> u8 {
    // SAFETY: every call uses a C string or one validated directory entry.
    unsafe { pointer.read() as u8 }
}

#[inline]
unsafe fn string_length(mut value: *const c_char) -> usize {
    let mut length = 0usize;
    while unsafe { byte(value) } != 0 {
        value = unsafe { value.add(1) };
        length += 1;
    }
    length
}

#[inline]
unsafe fn match_name(record: *mut Match) -> *mut c_char {
    // SAFETY: every Match allocation reserves its flexible pathname region.
    unsafe { record.cast::<u8>().add(size_of::<Match>()).cast() }
}

/// `append` from musl: allocate one node and copy one NUL-terminated pathname.
unsafe fn append(tail: &mut *mut Match, name: *const c_char, length: usize, mark: bool) -> c_int {
    let Some(allocation_size) = size_of::<Match>().checked_add(length).and_then(|size| size.checked_add(2)) else {
        return -1;
    };
    let record = unsafe { cabi_malloc(allocation_size).cast::<Match>() };
    if record.is_null() {
        return -1;
    }
    let destination = unsafe { match_name(record) };
    unsafe {
        (*record).next = ptr::null_mut();
        ptr::copy_nonoverlapping(name, destination, length + 1);
    }
    if mark && length != 0 && unsafe { byte(name.add(length - 1)) } != b'/' {
        unsafe {
            destination.add(length).write(b'/' as c_char);
            destination.add(length + 1).write(0);
        }
    }
    unsafe { (**tail).next = record };
    *tail = record;
    0
}

unsafe fn free_list(head: *mut Match) {
    let mut record = unsafe { (*head).next };
    while !record.is_null() {
        let next = unsafe { (*record).next };
        unsafe { cabi_free(record.cast()) };
        record = next;
    }
}

#[inline]
unsafe fn find_byte(mut pointer: *mut c_char, needle: u8) -> *mut c_char {
    loop {
        if unsafe { byte(pointer) } == needle {
            return pointer;
        }
        if unsafe { byte(pointer) } == 0 {
            return ptr::null_mut();
        }
        pointer = unsafe { pointer.add(1) };
    }
}

#[inline]
unsafe fn c_string_compare(mut left: *const c_char, mut right: *const c_char) -> c_int {
    loop {
        let left_byte = unsafe { byte(left) };
        let right_byte = unsafe { byte(right) };
        if left_byte != right_byte {
            return left_byte as c_int - right_byte as c_int;
        }
        if left_byte == 0 {
            return 0;
        }
        left = unsafe { left.add(1) };
        right = unsafe { right.add(1) };
    }
}

unsafe extern "C" fn sort(left: *const c_void, right: *const c_void) -> c_int {
    // SAFETY: qsort supplies pointers to initialized pathname-pointer slots.
    let left_path = unsafe { left.cast::<*const c_char>().read() };
    let right_path = unsafe { right.cast::<*const c_char>().read() };
    unsafe { c_string_compare(left_path, right_path) }
}

unsafe extern "C" fn ignore_error(_path: *const c_char, _error: c_int) -> c_int {
    0
}

/// Musl `expand_tilde`, retaining its dependency on the standard public
/// passwd lookup ABI rather than embedding a second account-file parser.
unsafe fn expand_tilde(
    pattern: &mut *mut c_char,
    buffer: &mut [u8; PATH_MAX],
    position: &mut usize,
) -> Result<(), c_int> {
    let mut user = unsafe { (*pattern).add(1) };
    let mut name_end = user;
    while unsafe { byte(name_end) } != 0 && unsafe { byte(name_end) } != b'/' {
        name_end = unsafe { name_end.add(1) };
    }
    let delimiter = unsafe { byte(name_end) };
    if delimiter != 0 {
        unsafe { name_end.write(0) };
        name_end = unsafe { name_end.add(1) };
    }
    *pattern = name_end;

    let mut home = if unsafe { byte(user) } == 0 {
        // SAFETY: HOME is one immutable NUL-terminated C lookup key.
        unsafe { environment::getenv(HOME.as_ptr().cast()) }
    } else {
        ptr::null_mut()
    };
    if home.is_null() {
        let mut passwd: owned_passwd::Passwd = unsafe { core::mem::zeroed() };
        let mut result: *mut owned_passwd::Passwd = ptr::null_mut();
        let lookup = if unsafe { byte(user) } != 0 {
            unsafe {
                getpwnam_r(
                    user,
                    &mut passwd,
                    buffer.as_mut_ptr().cast(),
                    PATH_MAX,
                    &mut result,
                )
            }
        } else {
            unsafe {
                getpwuid_r(
                    process_context::getuid(),
                    &mut passwd,
                    buffer.as_mut_ptr().cast(),
                    PATH_MAX,
                    &mut result,
                )
            }
        };
        if lookup == ENOMEM {
            return Err(GLOB_NOSPACE);
        }
        if lookup != 0 || result.is_null() || unsafe { (*result).directory.is_null() } {
            return Err(GLOB_NOMATCH);
        }
        home = unsafe { (*result).directory };
    }

    let mut copied = 0usize;
    while copied < PATH_MAX - 2 && unsafe { byte(home.add(copied)) } != 0 {
        buffer[copied] = unsafe { byte(home.add(copied)) };
        copied += 1;
    }
    if unsafe { byte(home.add(copied)) } != 0 {
        return Err(GLOB_NOMATCH);
    }
    buffer[copied] = delimiter;
    if delimiter != 0 {
        copied += 1;
        buffer[copied] = 0;
    }
    *position = copied;
    Ok(())
}

#[inline]
unsafe fn report_error(error: ErrorFunction, path: *const c_char, code: c_int, flags: c_int) -> bool {
    (unsafe { error(path, code) }) != 0 || flags & GLOB_ERR != 0
}

/// Recursive `do_glob` translation. The stack buffer remains one source-owned
/// PATH_MAX pathname and each recursive level mutates only its current suffix.
unsafe fn do_glob(
    buffer: &mut [u8; PATH_MAX],
    mut position: usize,
    mut entry_type: u8,
    mut pattern: *mut c_char,
    flags: c_int,
    error: ErrorFunction,
    tail: &mut *mut Match,
) -> c_int {
    if entry_type == 0 && flags & GLOB_MARK == 0 {
        entry_type = DT_REG;
    }
    if unsafe { byte(pattern) } != 0 && entry_type != DT_DIR {
        entry_type = 0;
    }
    while position + 1 < PATH_MAX && unsafe { byte(pattern) } == b'/' {
        buffer[position] = b'/';
        position += 1;
        pattern = unsafe { pattern.add(1) };
    }

    // This loop intentionally follows musl's i/j reset around each literal
    // slash. In particular, an escaped slash is copied once while the
    // recursive pattern starts immediately after it.
    let mut i: isize = 0;
    let mut j: isize = 0;
    let mut in_bracket = false;
    let mut overflow = false;
    while unsafe { byte(pattern.offset(i)) } != b'*'
        && unsafe { byte(pattern.offset(i)) } != b'?'
        && (!in_bracket || unsafe { byte(pattern.offset(i)) } != b']')
    {
        let current = unsafe { byte(pattern.offset(i)) };
        if current == 0 {
            if overflow {
                return 0;
            }
            pattern = unsafe { pattern.offset(i) };
            position += j as usize;
            i = 0;
            j = 0;
            break;
        }
        if current == b'[' {
            in_bracket = true;
        } else if current == b'\\' && flags & GLOB_NOESCAPE == 0 {
            if in_bracket && unsafe { byte(pattern.offset(i + 1)) } == b']' {
                break;
            }
            if unsafe { byte(pattern.offset(i + 1)) } == 0 {
                return 0;
            }
            i += 1;
        }
        if unsafe { byte(pattern.offset(i)) } == b'/' {
            if overflow {
                return 0;
            }
            in_bracket = false;
            pattern = unsafe { pattern.offset(i + 1) };
            i = -1;
            position += (j + 1) as usize;
            j = -1;
        }
        let end = position as isize + j + 1;
        if end >= 0 && (end as usize) < PATH_MAX {
            let output = position as isize + j;
            debug_assert!(output >= 0);
            buffer[output as usize] = unsafe { byte(pattern.offset(i)) };
            j += 1;
        } else if in_bracket {
            overflow = true;
        } else {
            return 0;
        }
        // Once this source loop has consumed any component character, a
        // caller-provided `d_type` no longer describes the constructed path.
        entry_type = 0;
        i += 1;
    }
    buffer[position] = 0;

    if unsafe { byte(pattern) } == 0 {
        if flags & GLOB_MARK != 0 && (entry_type == 0 || entry_type == DT_LNK) {
            match unsafe { stat_compat::fstatat_mode(AT_FDCWD, buffer.as_ptr().cast(), 0) } {
                Ok(mode) => {
                    entry_type = if mode & 0o170_000 == 0o040_000 { DT_DIR } else { DT_REG };
                }
                // The following lstat may succeed for a dangling link, but
                // musl retains this failed stat's errno publication.
                Err(code) => unsafe { errno::set_errno(code) },
            }
        }
        if entry_type == 0 {
            match unsafe {
                stat_compat::fstatat_mode(
                    AT_FDCWD,
                    buffer.as_ptr().cast(),
                    AT_SYMLINK_NOFOLLOW,
                )
            } {
                Ok(_) => {}
                Err(code) => {
                    // `lstat` in the source publishes its failure before the
                    // callback and preserves it when the error is ignored.
                    unsafe { errno::set_errno(code) };
                    if code != ENOENT && unsafe { report_error(error, buffer.as_ptr().cast(), code, flags) } {
                        return GLOB_ABORTED;
                    }
                    return 0;
                }
            }
        }
        return if unsafe { append(tail, buffer.as_ptr().cast(), position, flags & GLOB_MARK != 0 && entry_type == DT_DIR) } != 0 {
            GLOB_NOSPACE
        } else {
            0
        };
    }

    let mut separator = unsafe { find_byte(pattern, b'/') };
    let mut saved_separator = b'/';
    if !separator.is_null() && flags & GLOB_NOESCAPE == 0 {
        let mut cursor = separator;
        while cursor != pattern && unsafe { byte(cursor.sub(1)) } == b'\\' {
            cursor = unsafe { cursor.sub(1) };
        }
        if unsafe { separator.offset_from(cursor) } % 2 != 0 {
            separator = unsafe { separator.sub(1) };
            saved_separator = b'\\';
        }
    }
    let directory = if position != 0 {
        buffer.as_ptr().cast()
    } else {
        b".\0".as_ptr().cast()
    };
    let stream = unsafe { directory_streams::opendir(directory) };
    if stream.is_null() {
        let code = unsafe { errno::get_errno() };
        return if unsafe { report_error(error, buffer.as_ptr().cast(), code, flags) } {
            GLOB_ABORTED
        } else {
            0
        };
    }
    let old_errno = unsafe { errno::get_errno() };
    let read_error;
    loop {
        unsafe { errno::set_errno(0) };
        let entry = match unsafe { directory_streams::next_entry_name(stream) } {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                read_error = 0;
                break;
            }
            Err(code) => {
                unsafe { errno::set_errno(code) };
                read_error = code;
                break;
            }
        };
        // DT_UNKNOWN (zero) follows the source's stat/open path. Only a
        // known non-directory, non-symlink may be skipped early.
        if !separator.is_null() && entry.entry_type != 0
            && entry.entry_type != DT_DIR && entry.entry_type != DT_LNK
        {
            continue;
        }
        let length = entry.length;
        if length >= PATH_MAX - position {
            continue;
        }
        if !separator.is_null() {
            unsafe { separator.write(0) };
        }
        let fnmatch_flags = if flags & GLOB_NOESCAPE != 0 { FNM_NOESCAPE } else { 0 }
            | if flags & GLOB_PERIOD == 0 { FNM_PERIOD } else { 0 };
        if unsafe { super::owned_fnmatch::fnmatch(pattern, entry.bytes, fnmatch_flags) } != 0 {
            continue;
        }
        if !separator.is_null() && flags & GLOB_PERIOD != 0 && unsafe { byte(entry.bytes) } == b'.'
            && (unsafe { byte(entry.bytes.add(1)) } == 0
                || unsafe { byte(entry.bytes.add(1)) } == b'.' && unsafe { byte(entry.bytes.add(2)) } == 0)
            && unsafe { super::owned_fnmatch::fnmatch(pattern, entry.bytes, fnmatch_flags | FNM_PERIOD) } != 0
        {
            continue;
        }
        unsafe { ptr::copy_nonoverlapping(entry.bytes, buffer.as_mut_ptr().add(position).cast(), length + 1) };
        if !separator.is_null() {
            unsafe { separator.write(saved_separator as c_char) };
        }
        let remainder = if separator.is_null() {
            EMPTY.as_ptr().cast_mut().cast()
        } else {
            // Source recurses from p2 itself; do_glob consumes the separator
            // in its leading-slash loop before matching the next component.
            separator
        };
        let result = unsafe {
            do_glob(buffer, position + length, entry.entry_type, remainder, flags, error, tail)
        };
        if result != 0 {
            let _ = unsafe { directory_streams::closedir(stream) };
            return result;
        }
    }
    if !separator.is_null() {
        unsafe { separator.write(saved_separator as c_char) };
    }
    let _ = unsafe { directory_streams::closedir(stream) };
    if read_error != 0 && unsafe { report_error(error, buffer.as_ptr().cast(), unsafe { errno::get_errno() }, flags) } {
        return GLOB_ABORTED;
    }
    unsafe { errno::set_errno(old_errno) };
    0
}

unsafe fn duplicate_string(source: *const c_char) -> *mut c_char {
    let length = unsafe { string_length(source) };
    let Some(size) = length.checked_add(1) else {
        return ptr::null_mut();
    };
    let copy = unsafe { cabi_malloc(size).cast::<c_char>() };
    if !copy.is_null() {
        unsafe { ptr::copy_nonoverlapping(source, copy, size) };
    }
    copy
}

/// Expand a C pathname pattern with musl's result-vector ownership protocol.
///
/// # Safety
///
/// `pattern` is a readable NUL-terminated C string and `result` is writable.
/// With `GLOB_APPEND`, `result` must retain one exclusively owned valid prior
/// result from this entry; `globfree` releases every successful result.
#[no_mangle]
pub unsafe extern "C" fn glob(
    pattern: *const c_char,
    flags: c_int,
    error: Option<ErrorFunction>,
    result: *mut Glob,
) -> c_int {
    let error = error.unwrap_or(ignore_error);
    let mut head = Match { next: ptr::null_mut() };
    let mut tail: *mut Match = &mut head;
    let mut offsets = if flags & GLOB_DOOFFS != 0 { unsafe { (*result).offsets } } else { 0 };
    let mut glob_error = 0;

    if flags & GLOB_APPEND == 0 {
        unsafe {
            (*result).offsets = offsets;
            (*result).path_count = 0;
            (*result).path_vector = ptr::null_mut();
        }
    }
    if unsafe { byte(pattern) } != 0 {
        let copy = unsafe { duplicate_string(pattern) };
        if copy.is_null() {
            return GLOB_NOSPACE;
        }
        let mut buffer = [0u8; PATH_MAX];
        let mut position = 0usize;
        let mut walk_pattern = copy;
        if flags & (GLOB_TILDE | GLOB_TILDE_CHECK) != 0 && unsafe { byte(copy) } == b'~' {
            if let Err(code) = unsafe { expand_tilde(&mut walk_pattern, &mut buffer, &mut position) } {
                glob_error = code;
            }
        }
        if glob_error == 0 {
            glob_error = unsafe { do_glob(&mut buffer, position, 0, walk_pattern, flags, error, &mut tail) };
        }
        unsafe { cabi_free(copy.cast()) };
    }

    let mut count = 0usize;
    let mut record = head.next;
    while !record.is_null() {
        count += 1;
        record = unsafe { (*record).next };
    }
    if glob_error == GLOB_NOSPACE {
        unsafe { free_list(&mut head) };
        return glob_error;
    }
    if count == 0 {
        if flags & GLOB_NOCHECK != 0 {
            tail = &mut head;
            if unsafe { append(&mut tail, pattern, string_length(pattern), false) } != 0 {
                return GLOB_NOSPACE;
            }
            count += 1;
        } else if glob_error == 0 {
            return GLOB_NOMATCH;
        }
    }

    let vector_count = if flags & GLOB_APPEND != 0 {
        unsafe { offsets.checked_add((*result).path_count) }
    } else {
        Some(offsets)
    }.and_then(|count_before| count_before.checked_add(count)).and_then(|count_after| count_after.checked_add(1));
    let Some(vector_count) = vector_count else {
        unsafe { free_list(&mut head) };
        return GLOB_NOSPACE;
    };
    let Some(vector_bytes) = vector_count.checked_mul(size_of::<*mut c_char>()) else {
        unsafe { free_list(&mut head) };
        return GLOB_NOSPACE;
    };
    let vector = if flags & GLOB_APPEND != 0 {
        unsafe { cabi_realloc((*result).path_vector.cast(), vector_bytes).cast::<*mut c_char>() }
    } else {
        unsafe { cabi_malloc(vector_bytes).cast::<*mut c_char>() }
    };
    if vector.is_null() {
        unsafe { free_list(&mut head) };
        return GLOB_NOSPACE;
    }
    if flags & GLOB_APPEND != 0 {
        offsets += unsafe { (*result).path_count };
    } else {
        for index in 0..offsets {
            unsafe { vector.add(index).write(ptr::null_mut()) };
        }
    }
    unsafe { (*result).path_vector = vector };
    let mut record = head.next;
    for index in 0..count {
        unsafe {
            vector.add(offsets + index).write(match_name(record));
            record = (*record).next;
        }
    }
    unsafe {
        vector.add(offsets + count).write(ptr::null_mut());
        (*result).path_count += count;
    }
    if flags & GLOB_NOSORT == 0 {
        unsafe {
            cabi_qsort(
                vector.add(offsets).cast(),
                count,
                size_of::<*mut c_char>(),
                sort,
            );
        }
    }
    glob_error
}

/// Release a `glob` result without altering the caller's selected offset.
///
/// # Safety
///
/// `result` is an exclusively owned successful `glob` record. It must not be
/// null, copied, manually mutated, or freed through another allocator route.
#[no_mangle]
pub unsafe extern "C" fn globfree(result: *mut Glob) {
    let count = unsafe { (*result).path_count };
    let vector = unsafe { (*result).path_vector };
    let offsets = unsafe { (*result).offsets };
    for index in 0..count {
        let path = unsafe { vector.add(offsets + index).read() };
        unsafe { cabi_free(path.cast::<u8>().sub(size_of::<Match>()).cast()) };
    }
    unsafe {
        cabi_free(vector.cast());
        (*result).path_count = 0;
        (*result).path_vector = ptr::null_mut();
    }
}
