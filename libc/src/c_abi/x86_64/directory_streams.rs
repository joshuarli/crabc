//! Selected static Linux/x86-64 C directory-stream boundary.
//!
//! This leaf owns one bounded native C `DIR`/`dirent` block: `opendir`,
//! `fdopendir`, `closedir`, `dirfd`, `readdir`, `readdir_r`, `rewinddir`,
//! `seekdir`, `telldir`, C-locale `alphasort`, GNU/BSD `getdents`, and
//! `posix_getdents`. It composes only the raw Linux syscall-register boundary,
//! selected initial-TLS C `errno`, and the private x86 `stat` layout owner. It
//! is not `scandir`, `versionsort`, a C allocator, a general directory-walk
//! policy, a general locale/collation subsystem, libc.so, CRT, pthread/TLS
//! lifecycle, dynamic TLS, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/dirent/opendir.c`, `fdopendir.c`, `closedir.c`, and `dirfd.c` map
//!   to descriptor acquisition, validation, ownership, and release below.
//! - `src/dirent/readdir.c`, `readdir_r.c`, `rewinddir.c`, `seekdir.c`, and
//!   `telldir.c` map to the private buffered record/cursor state machine.
//! - `src/dirent/alphasort.c`, `getdents.c`, and `posix_getdents.c` map to
//!   the selected comparator and raw-record wrappers.
//!
//! Musl allocates stream state through `calloc` and releases it through
//! `free`. This deliberately allocation-free static archive does not select a
//! public or hidden C allocator. Instead, each `DIR` state object owns one
//! private anonymous 4 KiB mapping and `closedir` releases that exact mapping;
//! it is a bounded implementation detail, not a reusable allocator. The
//! selected direct syscall paths omit musl cancellation-point machinery. The
//! project supports only `C`, `POSIX`, and `C.UTF-8` locale profiles, whose
//! selected `alphasort` behavior is byte collation; broad locale collation is
//! intentionally absent. `scandir` would return allocation-owned storage and
//! `versionsort` requires the separately unselected `strverscmp`, so neither
//! is exported here.
//!
//! Linux 5.10 is the project baseline. The source preserves musl's deleted
//! directory `ENOENT`-as-end-of-stream behavior and record-length/NUL checks;
//! malformed kernel records report `EIO` before being exposed through the C
//! ABI. Linux owns pathname races, descriptor state, directory mutation,
//! opaque cookies, and all raw getdents record content.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr;

use super::{c_ssize_status, c_status, errno, raw_syscall, stat_compat};

const DIRECTORY_BUFFER_SIZE: usize = 2_048;
const DIRECTORY_MAPPING_SIZE: usize = 4_096;
const LINUX_DIRENT64_HEADER_SIZE: usize = 19;
const DIRECTORY_NAME_MAX: usize = 255;
const DIRECTORY_RESULT_MAX: usize = 0x7fff_ffff;
const LINUX_ERRNO_MAX: i64 = 4_095;

const EBADF: c_int = 9;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENOMEM: c_int = 12;
const ENOTDIR: c_int = 20;
const EOPNOTSUPP: c_int = 95;

const AT_FDCWD: c_int = -100;
const FD_CLOEXEC: c_int = 1;
const F_GETFL: c_int = 3;
const F_SETFD: c_int = 2;
const MAP_ANONYMOUS: c_int = 0x20;
const MAP_PRIVATE: c_int = 0x02;
const O_CLOEXEC: c_int = 0x80_000;
const O_DIRECTORY: c_int = 0x1_0000;
const O_LARGEFILE: c_int = 0x8_000;
const O_PATH: c_int = 0x20_0000;
const O_RDONLY: c_int = 0;
const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const SEEK_SET: c_int = 0;
const S_IFDIR: u32 = 0o040_000;
const S_IFMT: u32 = 0o170_000;

/// The exact public x86 `struct dirent` record returned from a buffered Linux
/// `getdents64` block. The installed C header owns its public spelling.
#[repr(C)]
pub(super) struct Dirent {
    inode: u64,
    offset: i64,
    record_length: u16,
    entry_type: u8,
    name: [c_char; DIRECTORY_NAME_MAX + 1],
}

/// Private state behind the opaque public `DIR` typedef.
#[repr(C)]
pub(super) struct DirectoryStream {
    tell: c_long,
    file_descriptor: c_int,
    buffer_position: usize,
    buffer_end: usize,
    buffer: [u8; DIRECTORY_BUFFER_SIZE],
}

const _: () = {
    assert!(size_of::<Dirent>() == 280);
    assert!(align_of::<Dirent>() == 8);
    assert!(offset_of!(Dirent, inode) == 0);
    assert!(offset_of!(Dirent, offset) == 8);
    assert!(offset_of!(Dirent, record_length) == 16);
    assert!(offset_of!(Dirent, entry_type) == 18);
    assert!(offset_of!(Dirent, name) == 19);
    assert!(align_of::<DirectoryStream>() <= align_of::<usize>());
    assert!(offset_of!(DirectoryStream, buffer) % align_of::<Dirent>() == 0);
    assert!(size_of::<DirectoryStream>() <= DIRECTORY_MAPPING_SIZE);
};

#[inline]
fn is_linux_error(result: i64) -> bool {
    result < 0 && result >= -LINUX_ERRNO_MAX
}

#[inline]
unsafe fn set_linux_error(result: i64) {
    debug_assert!(is_linux_error(result));
    // SAFETY: the checked Linux error range encodes one positive errno for the
    // selected static C ABI's initial-TLS errno slot.
    unsafe { errno::set_errno(result.wrapping_neg() as c_int) };
}

#[inline]
unsafe fn directory_failure(error: c_int) -> *mut DirectoryStream {
    // SAFETY: this selected C boundary owns publication of its concrete local
    // validation/ownership error through the initial-TLS errno slot.
    unsafe { errno::set_errno(error) };
    ptr::null_mut()
}

/// Allocate one private, zero-filled stream-state mapping without selecting a
/// C allocator.
#[inline(always)]
unsafe fn allocate_stream_mapping() -> *mut DirectoryStream {
    // SAFETY: this is the fixed private anonymous mapping contract: no input
    // address, a page-sized writable buffer, no descriptor, and zero offset.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_MMAP,
            0,
            DIRECTORY_MAPPING_SIZE as i64,
            i64::from(PROT_READ | PROT_WRITE),
            i64::from(MAP_PRIVATE | MAP_ANONYMOUS),
            -1,
            0,
        )
    };
    if is_linux_error(result) {
        // SAFETY: the result was checked as Linux's errno encoding.
        unsafe { set_linux_error(result) };
        return ptr::null_mut();
    }
    let stream = result as usize as *mut DirectoryStream;
    if stream.is_null() {
        // A zero mapping address cannot represent successful C `DIR *`
        // allocation. Release it if a permissive host allowed it, then retain
        // C's null result/error contract instead of leaking private state.
        let _ = unsafe {
            raw_syscall::syscall2(raw_syscall::SYS_MUNMAP, 0, DIRECTORY_MAPPING_SIZE as i64)
        };
        // SAFETY: this selected mapping boundary owns the definite failure.
        unsafe { errno::set_errno(ENOMEM) };
    }
    stream
}

/// Validate a descriptor and create state that owns it on success.
#[inline(always)]
unsafe fn allocate_directory_stream(file_descriptor: c_int) -> *mut DirectoryStream {
    let mode = match unsafe { stat_compat::fstat_mode(file_descriptor) } {
        Ok(mode) => mode,
        Err(error) => {
            // SAFETY: the private stat owner returned a checked Linux errno.
            return unsafe { directory_failure(error) };
        }
    };
    let status_flags = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FCNTL,
            i64::from(file_descriptor),
            i64::from(F_GETFL),
            0,
        )
    };
    if is_linux_error(status_flags) {
        // SAFETY: the result was checked as Linux's errno encoding.
        unsafe { set_linux_error(status_flags) };
        return ptr::null_mut();
    }
    if status_flags as c_int & O_PATH != 0 {
        // SAFETY: selected `fdopendir` rejects O_PATH descriptors before it
        // assumes ownership, matching musl's EBADF boundary.
        return unsafe { directory_failure(EBADF) };
    }
    if mode & S_IFMT != S_IFDIR {
        // SAFETY: selected `fdopendir` retains the C ENOTDIR boundary.
        return unsafe { directory_failure(ENOTDIR) };
    }

    let stream = unsafe { allocate_stream_mapping() };
    if stream.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `stream` is a fresh, page-aligned private mapping large enough
    // for `DirectoryStream`; its bytes are zero-filled by anonymous mmap.
    unsafe {
        (*stream).tell = 0;
        (*stream).file_descriptor = file_descriptor;
        (*stream).buffer_position = 0;
        (*stream).buffer_end = 0;
    }
    // Musl makes a best-effort close-on-exec update after descriptor
    // validation. Its result is deliberately ignored: ownership has already
    // transferred and the stream remains usable if the update is unavailable.
    let _ = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FCNTL,
            i64::from(file_descriptor),
            i64::from(F_SETFD),
            i64::from(FD_CLOEXEC),
        )
    };
    stream
}

/// Refill and validate one private buffered Linux `getdents64` record.
#[inline(always)]
unsafe fn next_record(stream: &mut DirectoryStream) -> *mut Dirent {
    if stream.buffer_position >= stream.buffer_end {
        let result = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_GETDENTS64,
                i64::from(stream.file_descriptor),
                stream.buffer.as_mut_ptr() as usize as i64,
                DIRECTORY_BUFFER_SIZE as i64,
            )
        };
        if result == 0 {
            return ptr::null_mut();
        }
        if is_linux_error(result) {
            // Musl presents deletion of an already-open directory as a normal
            // exhausted stream. Other kernel failures remain observable.
            if result != -i64::from(ENOENT) {
                // SAFETY: the result was checked as Linux's errno encoding.
                unsafe { set_linux_error(result) };
            }
            return ptr::null_mut();
        }
        let length = result as usize;
        if length > DIRECTORY_BUFFER_SIZE {
            // SAFETY: a kernel result larger than the submitted buffer cannot
            // form a valid stream record boundary for this C ABI leaf.
            unsafe { errno::set_errno(EIO) };
            return ptr::null_mut();
        }
        stream.buffer_position = 0;
        stream.buffer_end = length;
    }

    let record = unsafe { stream.buffer.as_mut_ptr().add(stream.buffer_position) };
    let remaining = stream.buffer_end - stream.buffer_position;
    if remaining < LINUX_DIRENT64_HEADER_SIZE {
        stream.buffer_position = stream.buffer_end;
        // SAFETY: selected malformed-record handling owns the C errno result.
        unsafe { errno::set_errno(EIO) };
        return ptr::null_mut();
    }
    let record_length = unsafe { ptr::read_unaligned(record.add(16) as *const u16) } as usize;
    if record_length < LINUX_DIRENT64_HEADER_SIZE || record_length > remaining {
        stream.buffer_position = stream.buffer_end;
        // SAFETY: selected malformed-record handling owns the C errno result.
        unsafe { errno::set_errno(EIO) };
        return ptr::null_mut();
    }
    let name = unsafe { record.add(LINUX_DIRENT64_HEADER_SIZE) };
    let name_limit = record_length - LINUX_DIRENT64_HEADER_SIZE;
    let mut name_length = 0;
    while name_length < name_limit && unsafe { *name.add(name_length) } != 0 {
        name_length += 1;
    }
    if name_length == name_limit || name_length > DIRECTORY_NAME_MAX {
        stream.buffer_position = stream.buffer_end;
        // SAFETY: selected malformed-record handling owns the C errno result.
        unsafe { errno::set_errno(EIO) };
        return ptr::null_mut();
    }

    stream.buffer_position += record_length;
    stream.tell = unsafe { ptr::read_unaligned(record.add(8) as *const i64) } as c_long;
    record as *mut Dirent
}

/// Open one pathname as an owned close-on-exec directory stream.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the complete
/// raw Linux `openat(2)` call, unless the caller deliberately exercises a
/// kernel pointer-fault path. The caller owns pathname resolution races.
#[no_mangle]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut DirectoryStream {
    // SAFETY: the caller owns the raw pathname contract; Linux x86's fourth
    // openat word is zero mode and `syscall4` places it in r10.
    let descriptor = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_OPENAT,
            i64::from(AT_FDCWD),
            path as usize as i64,
            i64::from(O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_LARGEFILE),
            0,
        )
    };
    if is_linux_error(descriptor) {
        // SAFETY: the result was checked as Linux's errno encoding.
        unsafe { set_linux_error(descriptor) };
        return ptr::null_mut();
    }
    let stream = unsafe { allocate_directory_stream(descriptor as c_int) };
    if stream.is_null() {
        // Preserve the ownership-validation/allocation failure across raw
        // descriptor cleanup, exactly as a failed opendir must report its
        // original stream-construction error rather than close's result.
        let saved_errno = unsafe { errno::get_errno() };
        let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor) };
        // SAFETY: this selected C ABI restores its own already-published
        // stream-construction error after cleanup.
        unsafe { errno::set_errno(saved_errno) };
    }
    stream
}

/// Transfer one existing descriptor into a directory stream on success.
///
/// A failure leaves the descriptor owned by the caller. The selected leaf
/// rejects an `O_PATH` descriptor with `EBADF` and a non-directory descriptor
/// with `ENOTDIR`; all other descriptor behavior remains Linux-owned.
#[no_mangle]
pub extern "C" fn fdopendir(file_descriptor: c_int) -> *mut DirectoryStream {
    // SAFETY: Linux validates the scalar descriptor and the helper does not
    // dereference caller-provided memory.
    unsafe { allocate_directory_stream(file_descriptor) }
}

/// Close the owned descriptor and release its private stream mapping.
///
/// # Safety
///
/// `stream` must be a live, exclusive `DIR *` previously returned by this
/// leaf. The pointer becomes invalid on every return path, and callers must
/// not concurrently access it or retain `readdir` record pointers afterward.
#[no_mangle]
pub unsafe extern "C" fn closedir(stream: *mut DirectoryStream) -> c_int {
    if stream.is_null() {
        // SAFETY: this selected C ABI owns its defensive null-stream errno.
        unsafe { errno::set_errno(EBADF) };
        return -1;
    }
    let file_descriptor = unsafe { (*stream).file_descriptor };
    let close_result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_CLOSE, i64::from(file_descriptor))
    };
    // The mapping is private state with a known address and fixed length. Its
    // unmap failure cannot arise for a valid stream; preserve musl's public
    // closedir result from close rather than expose a second allocator-like
    // failure channel.
    let _ = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MUNMAP,
            stream as usize as i64,
            DIRECTORY_MAPPING_SIZE as i64,
        )
    };
    c_status(close_result)
}

/// Return the descriptor owned by one live directory stream.
///
/// # Safety
///
/// `stream` must be a live, exclusively accessible `DIR *` returned by this
/// leaf for the duration of the read.
#[no_mangle]
pub unsafe extern "C" fn dirfd(stream: *mut DirectoryStream) -> c_int {
    if stream.is_null() {
        // SAFETY: this selected C ABI owns its defensive null-stream errno.
        unsafe { errno::set_errno(EBADF) };
        -1
    } else {
        unsafe { (*stream).file_descriptor }
    }
}

/// Read the next validated directory record, or return null at exhaustion.
///
/// # Safety
///
/// `stream` must be a live, exclusively accessible `DIR *` returned by this
/// leaf. A non-null record pointer borrows private stream storage and remains
/// valid only until the next directory operation on that stream or `closedir`.
#[no_mangle]
pub unsafe extern "C" fn readdir(stream: *mut DirectoryStream) -> *mut Dirent {
    if stream.is_null() {
        // SAFETY: this selected C ABI owns its defensive null-stream errno.
        unsafe { errno::set_errno(EBADF) };
        return ptr::null_mut();
    }
    // SAFETY: the caller's documented live/exclusive stream requirement
    // permits a temporary mutable view of its private state.
    unsafe { next_record(&mut *stream) }
}

/// Copy the next directory record into caller-owned `struct dirent` storage.
///
/// # Safety
///
/// `stream` must be live and exclusively accessible. `buffer` must designate
/// writable storage for one complete x86 `struct dirent`, and `result` must
/// designate writable storage for one record pointer; those regions must not
/// overlap the private stream state in a way that violates the copy contract.
#[no_mangle]
pub unsafe extern "C" fn readdir_r(
    stream: *mut DirectoryStream,
    buffer: *mut Dirent,
    result: *mut *mut Dirent,
) -> c_int {
    if stream.is_null() || buffer.is_null() || result.is_null() {
        return EBADF;
    }
    let saved_errno = unsafe { errno::get_errno() };
    // SAFETY: a zero errno distinguishes normal exhaustion from readdir's
    // selected error result for this legacy C API.
    unsafe { errno::set_errno(0) };
    let record = unsafe { readdir(stream) };
    let read_errno = unsafe { errno::get_errno() };
    if read_errno != 0 {
        return read_errno;
    }
    // SAFETY: normal EOF must leave the caller's previous errno observable.
    unsafe { errno::set_errno(saved_errno) };
    if record.is_null() {
        unsafe { *result = ptr::null_mut() };
        return 0;
    }
    let record_length = unsafe { (*record).record_length } as usize;
    // SAFETY: `next_record` validates that this raw record fits in the private
    // buffer and in the public 280-byte dirent layout; the caller provides one
    // complete output dirent and result pointer as documented above.
    unsafe {
        ptr::copy_nonoverlapping(record.cast::<u8>(), buffer.cast::<u8>(), record_length);
        *result = buffer;
    }
    0
}

/// Reset a stream to Linux directory offset zero and discard buffered records.
///
/// # Safety
///
/// `stream` must be a live, exclusively accessible `DIR *` returned by this
/// leaf. The caller owns concurrent directory mutation and cookie semantics.
#[no_mangle]
pub unsafe extern "C" fn rewinddir(stream: *mut DirectoryStream) {
    if stream.is_null() {
        // SAFETY: this selected C ABI owns its defensive null-stream errno.
        unsafe { errno::set_errno(EBADF) };
        return;
    }
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from((*stream).file_descriptor),
            0,
            i64::from(SEEK_SET),
        )
    };
    if is_linux_error(result) {
        // SAFETY: the result was checked as Linux's errno encoding.
        unsafe { set_linux_error(result) };
    }
    unsafe {
        (*stream).buffer_position = 0;
        (*stream).buffer_end = 0;
        (*stream).tell = 0;
    }
}

/// Seek to one opaque directory cookie and discard buffered records.
///
/// # Safety
///
/// `stream` must be a live, exclusively accessible `DIR *` returned by this
/// leaf. `offset` must be a cookie previously obtained from this stream for
/// portable behavior; all other kernel cookie semantics remain Linux-owned.
#[no_mangle]
pub unsafe extern "C" fn seekdir(stream: *mut DirectoryStream, offset: c_long) {
    if stream.is_null() {
        // SAFETY: this selected C ABI owns its defensive null-stream errno.
        unsafe { errno::set_errno(EBADF) };
        return;
    }
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from((*stream).file_descriptor),
            offset,
            i64::from(SEEK_SET),
        )
    };
    unsafe {
        if is_linux_error(result) {
            set_linux_error(result);
            (*stream).tell = -1;
        } else {
            (*stream).tell = result as c_long;
        }
        (*stream).buffer_position = 0;
        (*stream).buffer_end = 0;
    }
}

/// Return the last opaque directory cookie observed by this stream.
///
/// # Safety
///
/// `stream` must be a live, exclusively accessible `DIR *` returned by this
/// leaf for the duration of the read.
#[no_mangle]
pub unsafe extern "C" fn telldir(stream: *mut DirectoryStream) -> c_long {
    if stream.is_null() {
        // SAFETY: this selected C ABI owns its defensive null-stream errno.
        unsafe { errno::set_errno(EBADF) };
        -1
    } else {
        unsafe { (*stream).tell }
    }
}

/// Compare two directory entries using the selected C/POSIX/C.UTF-8 byte
/// collation profile.
///
/// # Safety
///
/// `left` and `right` must each point to one valid pointer to a `struct
/// dirent` whose `d_name` is a readable NUL-terminated byte string.
#[no_mangle]
pub unsafe extern "C" fn alphasort(
    left: *const *const Dirent,
    right: *const *const Dirent,
) -> c_int {
    let mut left_name = unsafe { (*left).cast::<u8>().add(offset_of!(Dirent, name)) };
    let mut right_name = unsafe { (*right).cast::<u8>().add(offset_of!(Dirent, name)) };
    loop {
        let left_byte = unsafe { *left_name };
        let right_byte = unsafe { *right_name };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
        if left_byte == 0 {
            return 0;
        }
        left_name = unsafe { left_name.add(1) };
        right_name = unsafe { right_name.add(1) };
    }
}

/// Fill one caller buffer with raw Linux `getdents64` records.
///
/// # Safety
///
/// `buffer` must designate `length` writable bytes for Linux's complete
/// `getdents64(2)` call. The caller owns descriptor lifetime, buffer parsing,
/// filesystem mutation, and any record-pointer lifetime.
#[no_mangle]
pub unsafe extern "C" fn getdents(
    file_descriptor: c_int,
    buffer: *mut Dirent,
    length: usize,
) -> c_int {
    let length = length.min(DIRECTORY_RESULT_MAX);
    // SAFETY: the caller supplies the full raw Linux output-buffer contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_GETDENTS64,
            i64::from(file_descriptor),
            buffer as usize as i64,
            length as i64,
        )
    };
    c_status(result)
}

/// Fill one caller buffer with raw Linux records when no POSIX extension flag
/// is requested.
///
/// # Safety
///
/// `buffer` must designate `length` writable bytes for Linux's complete
/// `getdents64(2)` call when `flags` is zero. The caller owns descriptor and
/// output-buffer lifetime, filesystem mutation, and record parsing.
#[no_mangle]
pub unsafe extern "C" fn posix_getdents(
    file_descriptor: c_int,
    buffer: *mut c_void,
    length: usize,
    flags: c_int,
) -> isize {
    if flags != 0 {
        // SAFETY: selected POSIX extension flags have one explicit unsupported
        // boundary rather than a broad flag-translation layer.
        unsafe { errno::set_errno(EOPNOTSUPP) };
        return -1;
    }
    let length = length.min(DIRECTORY_RESULT_MAX);
    // SAFETY: the caller supplies the full raw Linux output-buffer contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_GETDENTS64,
            i64::from(file_descriptor),
            buffer as usize as i64,
            length as i64,
        )
    };
    c_ssize_status(result)
}
