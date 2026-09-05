//! Local passwd-file C ABI, translated from musl 1.2.6 (MIT), revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, src/passwd/{getpwent_a,
//! getpw_a,getpw_r,getpwent,fgetpwent,putpwent}.c. The explicit local-only
//! profile omits getpw_a.c's nscd branch. Byte parsing, allocation capacity,
//! cancellation intervals and shared storage otherwise follow that source.

use core::{ffi::{c_char, c_int, c_void}, ptr};
use super::{errno, pthread_cancel, stdio_standard as stdio};
use stdio::StandardStream;

/// Installed LP64 struct passwd; uid_t and gid_t are 32-bit unsigned values.
#[repr(C)]
pub struct Passwd {
    pub name: *mut c_char,
    pub password: *mut c_char,
    pub uid: u32,
    pub gid: u32,
    pub gecos: *mut c_char,
    pub directory: *mut c_char,
    pub shell: *mut c_char,
}
const EMPTY: Passwd = Passwd { name: ptr::null_mut(), password: ptr::null_mut(),
    uid: 0, gid: 0, gecos: ptr::null_mut(), directory: ptr::null_mut(), shell: ptr::null_mut() };

// Musl shares these across enumeration and non-reentrant lookups, but opens
// a separate FILE for a lookup. Callers serialize the APIs and borrowed data.
static mut ENUMERATION: *mut StandardStream = ptr::null_mut();
static mut SHARED_LINE: *mut c_char = ptr::null_mut();
static mut SHARED_CAPACITY: usize = 0;
static mut SHARED_RECORD: Passwd = EMPTY;
// fgetpwent has a separate record/line and a freshly zeroed capacity per call.
static mut STREAM_LINE: *mut c_char = ptr::null_mut();
static mut STREAM_RECORD: Passwd = EMPTY;

unsafe extern "C" { fn free(allocation: *mut c_void); }

unsafe fn disable_cancellation() -> c_int {
    let mut old = 0;
    unsafe { pthread_cancel::pthread_setcancelstate(1, &mut old) };
    old
}
unsafe fn restore_cancellation(old: c_int) {
    unsafe { pthread_cancel::pthread_setcancelstate(old, ptr::null_mut()) };
}
unsafe fn colon(mut text: *mut c_char) -> *mut c_char {
    unsafe {
        while *text != 0 {
            if *text == b':' as c_char { return text; }
            text = text.add(1);
        }
    }
    ptr::null_mut()
}
unsafe fn unsigned_decimal(text: &mut *mut c_char) -> u32 {
    let mut value = 0u32;
    unsafe {
        while (**text as u8).wrapping_sub(b'0') < 10 {
            value = value.wrapping_mul(10).wrapping_add((**text as u8 - b'0') as u32);
            *text = (*text).add(1);
        }
    }
    value
}
unsafe fn equal(mut left: *const c_char, mut right: *const c_char) -> bool {
    unsafe {
        while *left == *right {
            if *left == 0 { return true; }
            left = left.add(1); right = right.add(1);
        }
    }
    false
}

// Preserve source's partial record writes on malformed lines and its final
// byte removal even without a newline. EOF/error frees the line but leaves
// capacity untouched; getline resets capacity when it next sees a null line.
unsafe fn next_record(stream: *mut StandardStream, record: *mut Passwd,
    line: *mut *mut c_char, capacity: *mut usize, result: *mut *mut Passwd) -> c_int {
    unsafe {
        let old = disable_cancellation();
        let mut error = 0;
        let mut found = record;
        loop {
            let length = stdio::getline(line, capacity, stream);
            if length < 0 {
                error = if stdio::ferror(stream) != 0 { errno::get_errno() } else { 0 };
                free((*line).cast()); *line = ptr::null_mut(); found = ptr::null_mut(); break;
            }
            *(*line).add(length as usize - 1) = 0;
            (*record).name = *line;
            let mut text = colon((*line).add(1));
            if text.is_null() { continue; }
            *text = 0; text = text.add(1); (*record).password = text;
            text = colon(text); if text.is_null() { continue; }
            *text = 0; text = text.add(1); (*record).uid = unsigned_decimal(&mut text);
            if *text != b':' as c_char { continue; }
            *text = 0; text = text.add(1); (*record).gid = unsigned_decimal(&mut text);
            if *text != b':' as c_char { continue; }
            *text = 0; text = text.add(1); (*record).gecos = text;
            text = colon(text); if text.is_null() { continue; }
            *text = 0; text = text.add(1); (*record).directory = text;
            text = colon(text); if text.is_null() { continue; }
            *text = 0; (*record).shell = text.add(1); break;
        }
        restore_cancellation(old);
        *result = found;
        if error != 0 { errno::set_errno(error); }
        error
    }
}

unsafe fn lookup(name: *const c_char, uid: u32, record: *mut Passwd,
    line: *mut *mut c_char, capacity: *mut usize, result: *mut *mut Passwd) -> c_int {
    unsafe {
        *result = ptr::null_mut();
        let old = disable_cancellation();
        let stream = stdio::fopen(c"/etc/passwd".as_ptr(), c"rbe".as_ptr());
        let mut error;
        if stream.is_null() { error = errno::get_errno(); }
        else {
            loop {
                error = next_record(stream, record, line, capacity, result);
                if error != 0 || (*result).is_null()
                    || (!name.is_null() && equal(name, (*record).name))
                    || (name.is_null() && (*record).uid == uid) { break; }
            }
            stdio::fclose(stream);
            // Deliberately no nscd/socket/provider query after a local miss.
        }
        restore_cancellation(old);
        if error != 0 { errno::set_errno(error); }
        error
    }
}

unsafe fn lookup_reentrant(name: *const c_char, uid: u32, record: *mut Passwd,
    buffer: *mut c_char, capacity: usize, result: *mut *mut Passwd) -> c_int {
    unsafe {
        let mut line = ptr::null_mut();
        let mut allocated = 0;
        let old = disable_cancellation();
        let mut error = lookup(name, uid, record, &mut line, &mut allocated, result);
        if !(*result).is_null() && capacity < allocated {
            *result = ptr::null_mut(); error = 34;
        }
        if !(*result).is_null() {
            // Musl copies getline's entire allocation, not just the record's
            // used bytes; an earlier long rejected line can therefore cause
            // ERANGE. Copy as raw storage without interpreting spare bytes.
            ptr::copy_nonoverlapping(line, buffer, allocated);
            (*record).name = buffer.add((*record).name.offset_from(line) as usize);
            (*record).password = buffer.add((*record).password.offset_from(line) as usize);
            (*record).gecos = buffer.add((*record).gecos.offset_from(line) as usize);
            (*record).directory = buffer.add((*record).directory.offset_from(line) as usize);
            (*record).shell = buffer.add((*record).shell.offset_from(line) as usize);
        }
        free(line.cast());
        restore_cancellation(old);
        if error != 0 { errno::set_errno(error); }
        error
    }
}

/// Look up the first local record with a matching byte-string name.
/// # Safety
/// `name` is readable through NUL. `record`, `result`, and `buffer` (for
/// `capacity` bytes) are writable and mutually nonoverlapping. The name does
/// not overlap writable arguments. Inspect record pointers only on success
/// with a non-null result; their lifetime is the caller's buffer lifetime.
#[no_mangle]
pub unsafe extern "C" fn getpwnam_r(name: *const c_char, record: *mut Passwd,
    buffer: *mut c_char, capacity: usize, result: *mut *mut Passwd) -> c_int {
    unsafe { lookup_reentrant(name, 0, record, buffer, capacity, result) }
}

/// Look up the first local record with a matching uid.
/// # Safety
/// The writable argument, non-overlap and returned-pointer obligations are
/// the same as getpwnam_r; no name argument is required.
#[no_mangle]
pub unsafe extern "C" fn getpwuid_r(uid: u32, record: *mut Passwd,
    buffer: *mut c_char, capacity: usize, result: *mut *mut Passwd) -> c_int {
    unsafe { lookup_reentrant(ptr::null(), uid, record, buffer, capacity, result) }
}

/// Close the enumeration cursor, retaining shared record allocation.
/// # Safety
/// Serialize this call with setpwent/endpwent/getpwent/getpwnam/getpwuid and
/// every use of their borrowed records. The next getpwent opens a fresh FILE.
#[no_mangle]
pub unsafe extern "C" fn setpwent() {
    unsafe {
        if !ENUMERATION.is_null() { stdio::fclose(ENUMERATION); }
        ENUMERATION = ptr::null_mut();
    }
}
core::arch::global_asm!(".weak endpwent", ".set endpwent, setpwent");

/// Read the next valid local passwd record, opening the cursor lazily.
/// # Safety
/// Serialize all shared-record APIs and use of their borrowed records as
/// documented for setpwent. Any subsequent shared-record lookup may replace
/// or free returned storage, including an unsuccessful lookup or EOF.
#[no_mangle]
pub unsafe extern "C" fn getpwent() -> *mut Passwd {
    unsafe {
        if ENUMERATION.is_null() { ENUMERATION = stdio::fopen(c"/etc/passwd".as_ptr(), c"rbe".as_ptr()); }
        if ENUMERATION.is_null() { return ptr::null_mut(); }
        let mut result = ptr::null_mut();
        next_record(ENUMERATION, &raw mut SHARED_RECORD, &raw mut SHARED_LINE,
            &raw mut SHARED_CAPACITY, &mut result);
        result
    }
}

/// Look up a name using the shared record without moving enumeration's FILE.
/// # Safety
/// `name` is readable through NUL and does not alias shared record storage.
/// Shared-call serialization and result lifetime obligations are getpwent's.
#[no_mangle]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut Passwd {
    unsafe {
        let mut result = ptr::null_mut();
        lookup(name, 0, &raw mut SHARED_RECORD, &raw mut SHARED_LINE,
            &raw mut SHARED_CAPACITY, &mut result);
        result
    }
}

/// Look up a uid using the shared record without moving enumeration's FILE.
/// # Safety
/// Shared-call serialization and result lifetime obligations are getpwent's.
#[no_mangle]
pub unsafe extern "C" fn getpwuid(uid: u32) -> *mut Passwd {
    unsafe {
        let mut result = ptr::null_mut();
        lookup(ptr::null(), uid, &raw mut SHARED_RECORD, &raw mut SHARED_LINE,
            &raw mut SHARED_CAPACITY, &mut result);
        result
    }
}

/// Parse a caller-owned FILE using fgetpwent's separate shared record.
/// # Safety
/// `stream` is a live FILE, retained throughout the call. Serialize fgetpwent
/// calls and all uses of their borrowed results. The next fgetpwent call can
/// replace or free the record's storage, including on EOF or error.
#[no_mangle]
pub unsafe extern "C" fn fgetpwent(stream: *mut StandardStream) -> *mut Passwd {
    unsafe {
        let mut capacity = 0;
        let mut result = ptr::null_mut();
        next_record(stream, &raw mut STREAM_RECORD, &raw mut STREAM_LINE,
            &mut capacity, &mut result);
        result
    }
}

/// Write seven passwd fields with musl's literal fprintf formatting.
/// # Safety
/// `record` and its five NUL-terminated strings are readable and stable for
/// the call. `stream` is a live writable FILE. Formatting neither validates
/// nor escapes embedded delimiters or newlines in the fields.
#[no_mangle]
pub unsafe extern "C" fn putpwent(record: *const Passwd, stream: *mut StandardStream) -> c_int {
    unsafe {
        if super::stdio_format_scan::fprintf(stream, c"%s:%s:%u:%u:%s:%s:%s\n".as_ptr(),
            (*record).name, (*record).password, (*record).uid, (*record).gid,
            (*record).gecos, (*record).directory, (*record).shell) < 0 { -1 } else { 0 }
    }
}
