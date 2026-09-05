//! Conventional local `/etc/group` C ABI for the owned Linux/x86-64 runtime.
//!
//! Source map and provenance: pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT; `COPYRIGHT` and
//! `compat/upstreams.toml`) maps `src/passwd/{getgrent_a,getgr_a,getgr_r,
//! getgrent,fgetgrent,getgrouplist,putgrent}.c` and
//! `src/misc/initgroups.c` to this module. `getgrent_a` supplies the byte
//! parser, getline allocation, cancellation interval, member-vector layout,
//! and shared-result lifetime. `getgr_a` and `getgrouplist` contain musl's
//! optional nscd socket query paths after or alongside local-file work. The
//! selected profile deliberately omits those nscd paths: this leaf consults
//! only the conventional local `/etc/group` file and never opens an nscd
//! socket, starts NSS, loads a provider, or retains an account cache. A local
//! lookup miss is therefore final and a lookup's local open/read failure stays
//! local. `getgrouplist` retains its musl local-file `ENOENT`/`ENOTDIR` branch:
//! it reports the primary gid/count while leaving that open errno observable;
//! other local open/read failures remain failures.
//!
//! `StandardStream` is the existing owned `FILE` owner, including its stream
//! locks, cancellation exclusion for ordinary FILE I/O, and fork registry.
//! This module owns neither a second parser framework nor a second `FILE`
//! representation. As in musl, `getgrent`, `getgrnam`, `getgrgid`, and
//! `fgetgrent` expose process-global borrowed storage; callers serialize those
//! APIs and all use of their results. The `_r` lookup APIs and `getgrouplist`
//! allocate only call-local parsing state. `initgroups` delegates its final
//! credential transition to the existing selected `setgroups` boundary; it
//! does not add musl's all-thread credential rendezvous.

use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

use super::{errno, pthread_cancel, stdio_format_scan, stdio_standard as stdio};
use stdio::StandardStream;

const ENOENT: c_int = 2;
const ENOMEM: c_int = 12;
const ENOTDIR: c_int = 20;
const ERANGE: c_int = 34;

/// Installed LP64 `struct group`; Linux `gid_t` is a 32-bit unsigned word.
#[repr(C)]
pub struct Group {
    pub gr_name: *mut c_char,
    pub gr_passwd: *mut c_char,
    pub gr_gid: u32,
    pub gr_mem: *mut *mut c_char,
}

const EMPTY_GROUP: Group = Group {
    gr_name: ptr::null_mut(),
    gr_passwd: ptr::null_mut(),
    gr_gid: 0,
    gr_mem: ptr::null_mut(),
};

// Musl retains the global line and member allocations across cursor resets.
// Its shared lookup and enumeration result is intentionally one record.
static mut ENUMERATION: *mut StandardStream = ptr::null_mut();
static mut SHARED_LINE: *mut c_char = ptr::null_mut();
static mut SHARED_MEMBERS: *mut *mut c_char = ptr::null_mut();
static mut SHARED_RECORD: Group = EMPTY_GROUP;

// fgetgrent has its own static record and storage, separate from the regular
// enumeration/lookup storage, exactly as musl's fgetgrent.c does.
static mut STREAM_LINE: *mut c_char = ptr::null_mut();
static mut STREAM_MEMBERS: *mut *mut c_char = ptr::null_mut();
static mut STREAM_RECORD: Group = EMPTY_GROUP;

unsafe extern "C" {
    fn calloc(count: usize, size: usize) -> *mut c_void;
    fn free(allocation: *mut c_void);
}

#[inline]
unsafe fn disable_cancellation() -> c_int {
    let mut old = 0;
    // The group source suppresses deferred cancellation while a getline
    // allocation or static record is transiently inconsistent.
    unsafe { pthread_cancel::pthread_setcancelstate(1, &mut old) };
    old
}

#[inline]
unsafe fn restore_cancellation(old: c_int) {
    unsafe { pthread_cancel::pthread_setcancelstate(old, ptr::null_mut()) };
}

#[inline]
unsafe fn colon(mut text: *mut c_char) -> *mut c_char {
    unsafe {
        while *text != 0 {
            if *text == b':' as c_char {
                return text;
            }
            text = text.add(1);
        }
    }
    ptr::null_mut()
}

// Musl's atou intentionally accepts an empty field as zero and wraps a
// wider decimal value into gid_t. Keep that byte-level behavior here.
#[inline]
unsafe fn unsigned_decimal(text: &mut *mut c_char) -> u32 {
    let mut value = 0u32;
    unsafe {
        while (**text as u8).wrapping_sub(b'0') < 10 {
            value = value
                .wrapping_mul(10)
                .wrapping_add((**text as u8 - b'0') as u32);
            *text = (*text).add(1);
        }
    }
    value
}

#[inline]
unsafe fn equal(mut left: *const c_char, mut right: *const c_char) -> bool {
    unsafe {
        while *left == *right {
            if *left == 0 {
                return true;
            }
            left = left.add(1);
            right = right.add(1);
        }
    }
    false
}

/// Translate musl's `__getgrent_a` over the existing owned FILE engine.
///
/// The caller supplies live storage and serializes any shared record it uses.
/// `line`, `members`, and their allocations belong to the caller's selected
/// storage slot. Pointer validity and non-overlap follow C's internal ABI.
unsafe fn next_record(
    stream: *mut StandardStream,
    record: *mut Group,
    line: *mut *mut c_char,
    capacity: *mut usize,
    members: *mut *mut *mut c_char,
    member_count: *mut usize,
    result: *mut *mut Group,
) -> c_int {
    unsafe {
        let old = disable_cancellation();
        let mut error = 0;
        let mut found = record;

        let member_text = loop {
            let length = stdio::getline(line, capacity, stream);
            if length < 0 {
                error = if stdio::ferror(stream) != 0 {
                    errno::get_errno()
                } else {
                    0
                };
                free((*line).cast());
                *line = ptr::null_mut();
                found = ptr::null_mut();
                restore_cancellation(old);
                *result = found;
                if error != 0 {
                    errno::set_errno(error);
                }
                return error;
            }

            // getline returns a positive length on every successful record;
            // musl removes its last byte, including when the input lacks '\n'.
            *(*line).add(length as usize - 1) = 0;
            let mut text = *line;
            (*record).gr_name = text;
            text = text.add(1);
            text = colon(text);
            if text.is_null() {
                continue;
            }
            *text = 0;
            text = text.add(1);
            (*record).gr_passwd = text;
            text = colon(text);
            if text.is_null() {
                continue;
            }
            *text = 0;
            text = text.add(1);
            (*record).gr_gid = unsigned_decimal(&mut text);
            if *text != b':' as c_char {
                continue;
            }
            *text = 0;
            break text.add(1);
        };

        let mut count = usize::from(*member_text != 0);
        let mut scan = member_text;
        while *scan != 0 {
            if *scan == b',' as c_char {
                count = match count.checked_add(1) {
                    Some(value) => value,
                    None => {
                        error = ENOMEM;
                        free((*line).cast());
                        *line = ptr::null_mut();
                        found = ptr::null_mut();
                        restore_cancellation(old);
                        *result = found;
                        errno::set_errno(error);
                        return error;
                    }
                };
            }
            scan = scan.add(1);
        }

        // Pinned musl uses calloc(sizeof(char *), nmem + 1), both to reserve
        // the terminator and to zero it before splitting the member bytes.
        let Some(slots) = count.checked_add(1) else {
            error = ENOMEM;
            free((*line).cast());
            *line = ptr::null_mut();
            found = ptr::null_mut();
            restore_cancellation(old);
            *result = found;
            errno::set_errno(error);
            return error;
        };
        free((*members).cast());
        *members = calloc(slots, core::mem::size_of::<*mut c_char>()).cast();
        if (*members).is_null() {
            error = errno::get_errno();
            free((*line).cast());
            *line = ptr::null_mut();
            found = ptr::null_mut();
            restore_cancellation(old);
            *result = found;
            if error != 0 {
                errno::set_errno(error);
            }
            return error;
        }

        if *member_text != 0 {
            **members = member_text;
            let mut index = 0usize;
            scan = member_text;
            while *scan != 0 {
                if *scan == b',' as c_char {
                    *scan = 0;
                    scan = scan.add(1);
                    index += 1;
                    *(*members).add(index) = scan;
                    continue;
                }
                scan = scan.add(1);
            }
            *(*members).add(index + 1) = ptr::null_mut();
        } else {
            **members = ptr::null_mut();
        }

        *member_count = count;
        (*record).gr_mem = *members;
        restore_cancellation(old);
        *result = found;
        error
    }
}

/// Local-only form of musl's `__getgr_a`.
///
/// `getgr_a.c` would issue an nscd query after a local miss or qualifying
/// local-path error. This selected profile stops at the local result, so it
/// never calls a socket/provider path and preserves a local failure directly.
unsafe fn lookup(
    name: *const c_char,
    gid: u32,
    record: *mut Group,
    line: *mut *mut c_char,
    capacity: *mut usize,
    members: *mut *mut *mut c_char,
    member_count: *mut usize,
    result: *mut *mut Group,
) -> c_int {
    unsafe {
        *result = ptr::null_mut();
        let old = disable_cancellation();
        let stream = stdio::fopen(c"/etc/group".as_ptr(), c"rbe".as_ptr());
        let mut error;
        if stream.is_null() {
            error = errno::get_errno();
        } else {
            loop {
                error = next_record(
                    stream,
                    record,
                    line,
                    capacity,
                    members,
                    member_count,
                    result,
                );
                if error != 0
                    || (*result).is_null()
                    || (!name.is_null() && equal(name, (*record).gr_name))
                    || (name.is_null() && (*record).gr_gid == gid)
                {
                    break;
                }
            }
            stdio::fclose(stream);
        }
        restore_cancellation(old);
        if error != 0 {
            errno::set_errno(error);
        }
        error
    }
}

unsafe fn lookup_reentrant(
    name: *const c_char,
    gid: u32,
    record: *mut Group,
    buffer: *mut c_char,
    capacity: usize,
    result: *mut *mut Group,
) -> c_int {
    unsafe {
        let mut line = ptr::null_mut();
        let mut line_capacity = 0usize;
        let mut members = ptr::null_mut();
        let mut member_count = 0usize;
        let old = disable_cancellation();
        let mut error = lookup(
            name,
            gid,
            record,
            &mut line,
            &mut line_capacity,
            &mut members,
            &mut member_count,
            result,
        );

        let pointer_bytes = member_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(core::mem::size_of::<*mut c_char>()));
        let required = pointer_bytes
            .and_then(|bytes| line_capacity.checked_add(bytes))
            .and_then(|bytes| bytes.checked_add(32));
        if !(*result).is_null() && required.is_none_or(|required| capacity < required) {
            *result = ptr::null_mut();
            error = ERANGE;
        }

        if !(*result).is_null() {
            // This is the source's `(16-(uintptr_t)buf)%16` placement. The
            // fixed 32-byte reserve above remains deliberately source-shaped.
            let padding = buffer.align_offset(16);
            let member_output = buffer.add(padding).cast::<*mut c_char>();
            let line_output = member_output.add(member_count + 1).cast::<c_char>();
            ptr::copy_nonoverlapping(line, line_output, line_capacity);
            (*record).gr_mem = member_output;
            (*record).gr_name = line_output.add((*record).gr_name.offset_from(line) as usize);
            (*record).gr_passwd = line_output.add((*record).gr_passwd.offset_from(line) as usize);
            for index in 0..member_count {
                *member_output.add(index) =
                    line_output.add((*members.add(index)).offset_from(line) as usize);
            }
            *member_output.add(member_count) = ptr::null_mut();
        }

        free(members.cast());
        free(line.cast());
        restore_cancellation(old);
        if error != 0 {
            errno::set_errno(error);
        }
        error
    }
}

/// Look up one local group record by byte-string name.
///
/// # Safety
/// `name` is readable through NUL. `record`, `result`, and `buffer` for
/// `capacity` bytes are writable, mutually non-overlapping C storage. The
/// returned record is usable only when `*result` equals `record`; its pointers
/// borrow `buffer` for the caller-selected lifetime.
#[no_mangle]
pub unsafe extern "C" fn getgrnam_r(
    name: *const c_char,
    record: *mut Group,
    buffer: *mut c_char,
    capacity: usize,
    result: *mut *mut Group,
) -> c_int {
    unsafe { lookup_reentrant(name, 0, record, buffer, capacity, result) }
}

/// Look up one local group record by Linux `gid_t`.
///
/// # Safety
/// The writable storage and returned-record requirements are the same as
/// `getgrnam_r`; no name string is read for this form.
#[no_mangle]
pub unsafe extern "C" fn getgrgid_r(
    gid: u32,
    record: *mut Group,
    buffer: *mut c_char,
    capacity: usize,
    result: *mut *mut Group,
) -> c_int {
    unsafe { lookup_reentrant(ptr::null(), gid, record, buffer, capacity, result) }
}

/// Close the process-global enumeration stream without freeing borrowed data.
///
/// # Safety
/// Serialize this call with `getgrent`, shared lookups, and use of all results
/// backed by this module's process-global record.
#[no_mangle]
pub unsafe extern "C" fn setgrent() {
    unsafe {
        if !ENUMERATION.is_null() {
            stdio::fclose(ENUMERATION);
        }
        ENUMERATION = ptr::null_mut();
    }
}

// `getgrent.c` exposes endgrent as a same-address weak alias of setgrent.
core::arch::global_asm!(".weak endgrent", ".set endgrent, setgrent");

/// Return the next valid conventional local group record.
///
/// # Safety
/// Serialize calls and all use of the borrowed process-global result. The
/// stream and line storage are inherited across `fork` through the existing
/// owned stdio fork transaction, as with musl's global cursor.
#[no_mangle]
pub unsafe extern "C" fn getgrent() -> *mut Group {
    unsafe {
        if ENUMERATION.is_null() {
            ENUMERATION = stdio::fopen(c"/etc/group".as_ptr(), c"rbe".as_ptr());
        }
        if ENUMERATION.is_null() {
            return ptr::null_mut();
        }
        let mut capacity = 0usize;
        let mut member_count = 0usize;
        let mut result = ptr::null_mut();
        next_record(
            ENUMERATION,
            &raw mut SHARED_RECORD,
            &raw mut SHARED_LINE,
            &mut capacity,
            &raw mut SHARED_MEMBERS,
            &mut member_count,
            &mut result,
        );
        result
    }
}

/// Look up a name through the local `/etc/group` provider.
///
/// # Safety
/// `name` is readable through NUL. The result shares the global group record;
/// serialize it with every other non-reentrant group operation and use it only
/// until a later such call replaces or frees its backing storage.
#[no_mangle]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut Group {
    unsafe {
        let mut capacity = 0usize;
        let mut member_count = 0usize;
        let mut result = ptr::null_mut();
        lookup(
            name,
            0,
            &raw mut SHARED_RECORD,
            &raw mut SHARED_LINE,
            &mut capacity,
            &raw mut SHARED_MEMBERS,
            &mut member_count,
            &mut result,
        );
        result
    }
}

/// Look up a Linux `gid_t` through the local `/etc/group` provider.
///
/// # Safety
/// The result has the same shared-storage and serialization requirements as
/// `getgrnam`.
#[no_mangle]
pub unsafe extern "C" fn getgrgid(gid: u32) -> *mut Group {
    unsafe {
        let mut capacity = 0usize;
        let mut member_count = 0usize;
        let mut result = ptr::null_mut();
        lookup(
            ptr::null(),
            gid,
            &raw mut SHARED_RECORD,
            &raw mut SHARED_LINE,
            &mut capacity,
            &raw mut SHARED_MEMBERS,
            &mut member_count,
            &mut result,
        );
        result
    }
}

/// Parse the next valid group record from a caller-owned owned-runtime FILE.
///
/// # Safety
/// `stream` must be a live `FILE` supplied by the owned stdio engine and must
/// remain live for the call. Serialize `fgetgrent` calls and use the returned
/// borrowed global record only until the next `fgetgrent` call.
#[no_mangle]
pub unsafe extern "C" fn fgetgrent(stream: *mut StandardStream) -> *mut Group {
    unsafe {
        let mut capacity = 0usize;
        let mut member_count = 0usize;
        let mut result = ptr::null_mut();
        next_record(
            stream,
            &raw mut STREAM_RECORD,
            &raw mut STREAM_LINE,
            &mut capacity,
            &raw mut STREAM_MEMBERS,
            &mut member_count,
            &mut result,
        );
        result
    }
}

/// Write one group record in musl's literal colon/comma/newline form.
///
/// # Safety
/// `record` and its NUL-terminated name/password/member strings are readable
/// and stable for the call. `stream` is a live writable owned FILE. Embedded
/// separators and newlines are not validated or escaped, matching musl.
#[no_mangle]
pub unsafe extern "C" fn putgrent(record: *const Group, stream: *mut StandardStream) -> c_int {
    unsafe {
        stdio::flockfile(stream);
        let mut written = stdio_format_scan::fprintf(
            stream,
            c"%s:%s:%u:".as_ptr(),
            (*record).gr_name,
            (*record).gr_passwd,
            (*record).gr_gid,
        );
        if written >= 0 && !(*record).gr_mem.is_null() {
            let mut index = 0usize;
            while !(*(*record).gr_mem.add(index)).is_null() {
                written = stdio_format_scan::fprintf(
                    stream,
                    c"%s%s".as_ptr(),
                    if index == 0 {
                        c"".as_ptr()
                    } else {
                        c",".as_ptr()
                    },
                    *(*record).gr_mem.add(index),
                );
                if written < 0 {
                    break;
                }
                index += 1;
            }
        }
        if written >= 0 {
            written = stdio::fputc(b'\n' as c_int, stream);
        }
        stdio::funlockfile(stream);
        if written < 0 { -1 } else { 0 }
    }
}

/// Return primary and local supplementary group IDs for one byte-string user.
///
/// This is the local-file part of musl's `getgrouplist.c`: group IDs are kept
/// in file order and deliberately not deduplicated. A too-small output array
/// returns `-1`, updates `*count`, and leaves errno alone, as musl does.
///
/// # Safety
/// `user` is a readable NUL-terminated string; `count` is writable; and when
/// its initial positive value permits writes, `groups` names that many writable
/// `gid_t` words. The caller owns output and must provide non-overlapping C
/// storage for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn getgrouplist(
    user: *const c_char,
    gid: u32,
    mut groups: *mut u32,
    count: *mut c_int,
) -> c_int {
    unsafe {
        let limit = *count;
        let mut discovered: isize = 1;
        let mut result = -1;
        let mut stream = ptr::null_mut();
        let mut line = ptr::null_mut();
        let mut line_capacity = 0usize;
        let mut members = ptr::null_mut();
        let mut member_count = 0usize;
        let mut record = EMPTY_GROUP;
        let mut parsed = ptr::null_mut();

        if limit >= 1 {
            *groups = gid;
            groups = groups.add(1);
        }

        stream = stdio::fopen(c"/etc/group".as_ptr(), c"rbe".as_ptr());
        if stream.is_null() {
            // Keep getgrouplist.c's local-file rule after omitting its earlier
            // nscd query: a missing path or nondirectory still yields the
            // primary gid/count and leaves fopen's errno observable. Other
            // local open failures remain errors.
            let error = errno::get_errno();
            if error != ENOENT && error != ENOTDIR {
                cleanup_local_group_scan(&mut stream, line, members);
                return -1;
            }
        } else {
            loop {
                let error = next_record(
                    stream,
                    &mut record,
                    &mut line,
                    &mut line_capacity,
                    &mut members,
                    &mut member_count,
                    &mut parsed,
                );
                if error != 0 {
                    errno::set_errno(error);
                    cleanup_local_group_scan(&mut stream, line, members);
                    return -1;
                }
                if parsed.is_null() {
                    break;
                }
                let mut index = 0usize;
                while !(*record.gr_mem.add(index)).is_null()
                    && !equal(user, *record.gr_mem.add(index))
                {
                    index += 1;
                }
                if (*record.gr_mem.add(index)).is_null() {
                    continue;
                }
                discovered += 1;
                if discovered <= limit as isize {
                    *groups = record.gr_gid;
                    groups = groups.add(1);
                }
            }
        }

        result = if discovered > limit as isize {
            -1
        } else {
            discovered as c_int
        };
        *count = discovered as c_int;
        cleanup_local_group_scan(&mut stream, line, members);
        result
    }
}

// Keep source cleanup explicit around local-file exits. Rust's control flow
// avoids duplicating the source cleanup label while preserving close/free order
// and errno.
unsafe fn cleanup_local_group_scan(
    stream: &mut *mut StandardStream,
    line: *mut c_char,
    members: *mut *mut c_char,
) {
    unsafe {
        if !(*stream).is_null() {
            stdio::fclose(*stream);
            *stream = ptr::null_mut();
        }
        free(line.cast());
        free(members.cast());
    }
}

/// Set the calling task's supplementary group list from local `/etc/group`.
///
/// # Safety
/// `user` is readable through NUL. A successful call changes Linux credentials
/// through the selected `setgroups` syscall boundary; callers must supply the
/// authority, all-thread coordination, and recovery policy required for that
/// process-sensitive transition.
#[no_mangle]
pub unsafe extern "C" fn initgroups(user: *const c_char, gid: u32) -> c_int {
    unsafe {
        let mut stack = [0u32; 32];
        let mut groups = stack.as_mut_ptr();
        let mut count = stack.len() as c_int;
        let mut previous_count = count;

        while getgrouplist(user, gid, groups, &mut count) < 0 {
            if groups != stack.as_mut_ptr() {
                free(groups.cast());
            }
            if count <= previous_count {
                return -1;
            }
            if count < previous_count + (previous_count >> 1) {
                count = previous_count + (previous_count >> 1);
            }
            groups = calloc(count as usize, core::mem::size_of::<u32>()).cast();
            if groups.is_null() {
                return -1;
            }
            previous_count = count;
        }

        let status = super::credentials::setgroups(count as usize, groups);
        if groups != stack.as_mut_ptr() {
            free(groups.cast());
        }
        status
    }
}
