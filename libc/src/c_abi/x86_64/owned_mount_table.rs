//! Owned Linux/x86-64 mount-table FILE interfaces.
//!
//! Semantic source: musl 1.2.6 commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, `src/misc/mntent.c`
//! (MIT; upstream `COPYRIGHT`, pin in `compat/upstreams.toml`). The five
//! functions below retain that source's FILE operations, scanf grammar,
//! in-place unescape algorithm, and shared getline storage. `hasmntopt`
//! remains in its independently qualified leaf. This reads caller-selected
//! conventional text files; it introduces no mount cache or namespace policy.
//!
//! In particular, missing fields are accepted, zero octal escapes remain
//! literal, and addmntent writes the supplied fields without escaping them.
//! A bounded read drains an overlong line and reports ERANGE; the FILE EOF
//! flag takes precedence, including an unterminated final record.

use core::{ffi::{c_char, c_int}, ptr};
use super::{errno, stdio_format_scan as scan, stdio_standard as stdio};
use stdio::StandardStream;

/// Installed LP64 `struct mntent`; string fields borrow the parse buffer.
#[repr(C)]
pub struct MountEntry {
    pub mnt_fsname: *mut c_char,
    pub mnt_dir: *mut c_char,
    pub mnt_type: *mut c_char,
    pub mnt_opts: *mut c_char,
    pub mnt_freq: c_int,
    pub mnt_passno: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<MountEntry>() == 40);
    assert!(core::mem::align_of::<MountEntry>() == 8);
    assert!(core::mem::offset_of!(MountEntry, mnt_fsname) == 0);
    assert!(core::mem::offset_of!(MountEntry, mnt_dir) == 8);
    assert!(core::mem::offset_of!(MountEntry, mnt_type) == 16);
    assert!(core::mem::offset_of!(MountEntry, mnt_opts) == 24);
    assert!(core::mem::offset_of!(MountEntry, mnt_freq) == 32);
    assert!(core::mem::offset_of!(MountEntry, mnt_passno) == 36);
};

// Musl's getmntent retains this allocation and record across stream closes.
// The shared API and all uses of its returned storage require serialization.
static mut SHARED_LINE: *mut c_char = ptr::null_mut();
static mut SHARED_CAPACITY: usize = 0;
static mut SHARED_ENTRY: MountEntry = MountEntry {
    mnt_fsname: ptr::null_mut(), mnt_dir: ptr::null_mut(),
    mnt_type: ptr::null_mut(), mnt_opts: ptr::null_mut(),
    mnt_freq: 0, mnt_passno: 0,
};

unsafe fn unescape(text: *mut c_char) -> *mut c_char {
    let mut source = text.cast::<u8>();
    let mut destination = source;
    unsafe {
        while *source != 0 {
            if *source != b'\\' {
                *destination = *source;
                source = source.add(1);
            } else if *source.add(1) == b'\\' {
                *destination = b'\\';
                source = source.add(2);
            } else {
                let mut end = source.add(1);
                let mut value = 0u8;
                for _ in 0..3 {
                    if *end < b'0' || *end > b'7' { break; }
                    value = value.wrapping_mul(8).wrapping_add(*end - b'0');
                    end = end.add(1);
                }
                if value != 0 {
                    *destination = value;
                    source = end;
                } else {
                    *destination = *source;
                    source = source.add(1);
                }
            }
            destination = destination.add(1);
        }
        *destination = 0;
    }
    text
}

/// Open a caller-selected mount table with ordinary fopen semantics.
///
/// # Safety
/// `path` and `mode` must be readable NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn setmntent(path: *const c_char, mode: *const c_char) -> *mut StandardStream {
    unsafe { stdio::fopen(path, mode) }
}

/// Close a mount table; musl returns one even for NULL or a close error.
///
/// # Safety
/// A non-null `stream` must be a live owned FILE exclusively available for
/// closing. It and its FILE aliases are invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn endmntent(stream: *mut StandardStream) -> c_int {
    if !stream.is_null() { unsafe { stdio::fclose(stream) }; }
    1
}

unsafe fn read_entry(stream: *mut StandardStream, entry: *mut MountEntry,
    mut line: *mut c_char, capacity: c_int, shared: bool) -> *mut MountEntry {
    unsafe {
        (*entry).mnt_freq = 0;
        (*entry).mnt_passno = 0;
        loop {
            if shared {
                stdio::getline(&raw mut SHARED_LINE, &raw mut SHARED_CAPACITY, stream);
                line = SHARED_LINE;
            } else {
                stdio::fgets(line, capacity, stream);
            }
            if stdio::feof(stream) != 0 || stdio::ferror(stream) != 0 {
                return ptr::null_mut();
            }
            let mut length = 0usize;
            let mut newline = false;
            while *line.add(length) != 0 {
                newline |= *line.add(length) == b'\n' as c_char;
                length += 1;
            }
            if !newline {
                scan::fscanf(stream, c"%*[^\n]%*[\n]".as_ptr());
                errno::set_errno(34);
                return ptr::null_mut();
            }
            if length > c_int::MAX as usize { continue; }
            let mut offsets = [length as c_int; 8];
            let n = offsets.as_mut_ptr();
            scan::sscanf(line,
                c" %n%*[^ \t\n]%n %n%*[^ \t\n]%n %n%*[^ \t\n]%n %n%*[^ \t\n]%n %d %d".as_ptr(),
                n, n.add(1), n.add(2), n.add(3), n.add(4), n.add(5), n.add(6), n.add(7),
                &raw mut (*entry).mnt_freq, &raw mut (*entry).mnt_passno);
            if *line.add(offsets[0] as usize) == b'#' as c_char || offsets[1] == length as c_int {
                continue;
            }
            for i in [1, 3, 5, 7] { *line.add(offsets[i] as usize) = 0; }
            (*entry).mnt_fsname = unescape(line.add(offsets[0] as usize));
            (*entry).mnt_dir = unescape(line.add(offsets[2] as usize));
            (*entry).mnt_type = unescape(line.add(offsets[4] as usize));
            (*entry).mnt_opts = unescape(line.add(offsets[6] as usize));
            return entry;
        }
    }
}

/// Read a record into caller-owned storage using musl's mount-table grammar.
///
/// # Safety
/// `stream` must be a live owned readable FILE, `entry` writable and aligned,
/// and `buffer` writable for positive `capacity` bytes, disjoint from `entry`.
/// Neither destination may be concurrently accessed. Returned strings borrow
/// `buffer` and remain valid only until it is modified or destroyed.
#[no_mangle]
pub unsafe extern "C" fn getmntent_r(stream: *mut StandardStream, entry: *mut MountEntry,
    buffer: *mut c_char, capacity: c_int) -> *mut MountEntry {
    unsafe { read_entry(stream, entry, buffer, capacity, false) }
}

/// Read a mount record into process-global growable storage.
///
/// # Safety
/// `stream` must be a live owned readable FILE. Callers must serialize this
/// function and all access to its result across threads. A subsequent call
/// overwrites the record and can invalidate every returned string pointer.
#[no_mangle]
pub unsafe extern "C" fn getmntent(stream: *mut StandardStream) -> *mut MountEntry {
    unsafe { read_entry(stream, &raw mut SHARED_ENTRY, ptr::null_mut(), 0, true) }
}

/// Append literal fields after seeking to the end of the mount table.
///
/// # Safety
/// `stream` must be a live owned writable FILE. `entry` must be readable and
/// aligned, and all four string fields must be readable NUL-terminated strings
/// for this call. The record and strings must not be concurrently mutated.
#[no_mangle]
pub unsafe extern "C" fn addmntent(stream: *mut StandardStream, entry: *const MountEntry) -> c_int {
    unsafe {
        if stdio::fseek(stream, 0, 2) != 0 { return 1; }
        (scan::fprintf(stream, c"%s\t%s\t%s\t%s\t%d\t%d\n".as_ptr(),
            (*entry).mnt_fsname, (*entry).mnt_dir, (*entry).mnt_type, (*entry).mnt_opts,
            (*entry).mnt_freq, (*entry).mnt_passno) < 0) as c_int
    }
}
