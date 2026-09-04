//! Owned-static native x86 descriptor stream engine.
//!
//! Source map: pinned musl 1.2.6 commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT; see
//! `compat/upstreams.toml`): stdio_impl.h and stdin/stdout/stderr.c map to
//! StandardStream and permanent storage; __stdio_read/__toread/__uflow and
//! __stdio_write/__towrite/__overflow map to the byte/block helpers retained
//! from the existing x86 stdio_standard.rs translation. fdopen/fopen/fclose,
//! ofl/ofl_add, flockfile/ftrylockfile/funlockfile, fflush, setvbuf, and
//! fseek/ftell map to the corresponding lifecycle below. Public FILE is opaque.
//!
//! The registry owns only dynamic streams; allocation precedes insertion and
//! freeing follows removal, with neither allocator call under a stream or list
//! lock. Permanent streams require no heap allocation, including allocator
//! diagnostics before main. Registry walks hold the list lock before stream
//! locks. Like fclose in C, stream destruction requires callers to exclude
//! concurrent use. Recursive locks use Linux thread IDs and private futexes.
//!
//! This component supplies descriptor byte streams. The existing formatter and
//! scanner retain their separately bounded grammar; wide,
//! memory, cookie, popen, freopen, cancellation and fork lock recovery remain separate
//! integration obligations. This is not completion of the stdio family.

use core::{ffi::{c_char, c_int, c_void}, ptr, sync::atomic::{AtomicI32, Ordering}};
use super::{c_off_status, c_ssize_status, c_status, errno, raw_syscall};

const BUFSIZ: usize = 1024;
const UNGET: usize = 8;
const EOF: c_int = -1;
const EIO: c_int = 5;
const EINVAL: c_int = 22;
const EOVERFLOW: c_int = 75;
const F_PERM: u32 = 1;
const F_NORD: u32 = 4;
const F_NOWR: u32 = 8;
const F_EOF: u32 = 16;
const F_ERR: u32 = 32;
const F_APP: u32 = 128;
const F_IO_STARTED: u32 = 512;
const SEEK_SET: c_int = 0;
const SEEK_CUR: c_int = 1;
const SEEK_END: c_int = 2;

#[repr(C)]
struct IoVec { base: *mut c_void, length: usize }

/// Opaque FILE state. Only pointers returned by this engine are valid.
#[repr(C)]
pub struct StandardStream {
    flags: u32,
    file_descriptor: c_int,
    buffer: *mut u8,
    capacity: usize,
    read_position: *mut u8,
    read_end: *mut u8,
    write_position: *mut u8,
    owner: AtomicI32,
    lock_count: usize,
    next: *mut StandardStream,
    previous: *mut StandardStream,
    line_buffered: bool,
    storage: [u8; BUFSIZ + UNGET],
}

impl StandardStream {
    const fn new(fd: c_int, flags: u32, capacity: usize) -> Self {
        Self { flags, file_descriptor: fd, buffer: ptr::null_mut(), capacity,
            read_position: ptr::null_mut(), read_end: ptr::null_mut(),
            write_position: ptr::null_mut(), owner: AtomicI32::new(0),
            lock_count: 0, next: ptr::null_mut(), previous: ptr::null_mut(),
            line_buffered: false, storage: [0; BUFSIZ + UNGET] }
    }
}

static mut STDIN_STREAM: StandardStream = StandardStream::new(0, F_PERM | F_NOWR, BUFSIZ);
static mut STDOUT_STREAM: StandardStream = StandardStream::new(1, F_PERM | F_NORD, BUFSIZ);
static mut STDERR_STREAM: StandardStream = StandardStream::new(2, F_PERM | F_NORD, 0);
static LIST_LOCK: AtomicI32 = AtomicI32::new(0);
static mut OPEN_STREAMS: *mut StandardStream = ptr::null_mut();

#[no_mangle]
pub static mut stdin: *mut StandardStream = ptr::addr_of_mut!(STDIN_STREAM);
#[no_mangle]
pub static mut stdout: *mut StandardStream = ptr::addr_of_mut!(STDOUT_STREAM);
#[no_mangle]
pub static mut stderr: *mut StandardStream = ptr::addr_of_mut!(STDERR_STREAM);

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
}

// All pointer initialization is performed under the individual stream lock.
// No global once-state or allocator is involved in permanent-stream use.
unsafe fn initialize_buffer(stream: *mut StandardStream) {
    if unsafe { (*stream).buffer.is_null() } {
        unsafe {
            let buffer = ptr::addr_of_mut!((*stream).storage).cast::<u8>().add(UNGET);
            (*stream).buffer = buffer;
            (*stream).read_position = buffer;
            (*stream).read_end = buffer;
            (*stream).write_position = buffer;
            // musl __fdopen activates line buffering for every writable
            // terminal via TIOCGWINSZ; stderr remains unbuffered.
            if (*stream).flags & F_NOWR == 0 && (*stream).capacity != 0 {
                let mut window_size = [0u16; 4];
                (*stream).line_buffered = raw_syscall::syscall3(16,
                    (*stream).file_descriptor as i64, 0x5413,
                    window_size.as_mut_ptr() as i64) == 0;
            }
        }
    }
}

unsafe fn futex_wait(lock: &AtomicI32, value: i32) {
    unsafe { raw_syscall::syscall4(202, lock.as_ptr() as i64, 128, value as i64, 0); }
}
unsafe fn futex_wake(lock: &AtomicI32) {
    unsafe { raw_syscall::syscall3(202, lock.as_ptr() as i64, 129, 1); }
}

struct ListGuard;
impl ListGuard {
    unsafe fn acquire() -> Self {
        while LIST_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            unsafe { futex_wait(&LIST_LOCK, 1); }
        }
        Self
    }
}
impl Drop for ListGuard {
    fn drop(&mut self) {
        LIST_LOCK.store(0, Ordering::Release);
        unsafe { futex_wake(&LIST_LOCK); }
    }
}

pub(crate) struct StreamGuard(*mut StandardStream);
impl StreamGuard {
    /// Caller supplies a live FILE; the guard serializes all state access.
    pub(crate) unsafe fn acquire(stream: *mut StandardStream) -> Self {
        unsafe { flockfile(stream); }
        Self(stream)
    }
}
impl Drop for StreamGuard {
    fn drop(&mut self) { unsafe { funlockfile(self.0); } }
}

/// # Safety
/// `stream` must be a live FILE owned by this runtime.
#[no_mangle]
pub unsafe extern "C" fn ftrylockfile(stream: *mut StandardStream) -> c_int {
    unsafe {
        let tid = raw_syscall::syscall0(186) as i32;
        if (*stream).owner.load(Ordering::Relaxed) == tid {
            (*stream).lock_count += 1;
            return 0;
        }
        if (*stream).owner.compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return 1;
        }
        (*stream).lock_count = 1;
        initialize_buffer(stream);
        0
    }
}

/// # Safety
/// `stream` must be live and must not be concurrently closed.
#[no_mangle]
pub unsafe extern "C" fn flockfile(stream: *mut StandardStream) {
    unsafe {
        while ftrylockfile(stream) != 0 {
            let owner = (*stream).owner.load(Ordering::Relaxed);
            if owner != 0 { futex_wait(&(*stream).owner, owner); }
        }
    }
}

/// # Safety
/// The calling thread must own a matching FILE lock acquisition.
#[no_mangle]
pub unsafe extern "C" fn funlockfile(stream: *mut StandardStream) {
    unsafe {
        (*stream).lock_count -= 1;
        if (*stream).lock_count == 0 {
            (*stream).owner.store(0, Ordering::Release);
            futex_wake(&(*stream).owner);
        }
    }
}

pub(crate) fn is_permanent_stream(stream: *const StandardStream) -> bool {
    stream == ptr::addr_of!(STDIN_STREAM) || stream == ptr::addr_of!(STDOUT_STREAM)
        || stream == ptr::addr_of!(STDERR_STREAM)
}

const TMPFILE_RANDOM_BYTES: usize = 12;
const TMPFILE_MAX_ATTEMPTS: usize = 100;
const TMPFILE_SUFFIX_OFFSET: usize = b"/tmp/tmpfile_".len();
const EINTR: c_int = 4;
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
const O_LARGEFILE: c_int = 0o100000;

/// Retains stdio_standard.rs's kernel-entropy name generation and immediate
/// unlink policy (musl tmpfile.c/__randname.c mapping); each call owns a FILE.
/// # Safety
/// Returned FILE must be released with fclose when no longer used.
#[no_mangle]
pub unsafe extern "C" fn tmpfile() -> *mut StandardStream {

    let mut attempt = 0;
    let mut last_open_error = EIO;
    while attempt < TMPFILE_MAX_ATTEMPTS {
        let mut entropy = [0u8; TMPFILE_RANDOM_BYTES];
        let mut initialized = 0;
        while initialized < entropy.len() {
            let result = unsafe {
                raw_syscall::syscall3(
                    raw_syscall::SYS_GETRANDOM,
                    entropy.as_mut_ptr().add(initialized) as usize as i64,
                    (entropy.len() - initialized) as i64,
                    0,
                )
            };
            if result < 0 {
                let error = (-result) as c_int;
                if error == EINTR {
                    continue;
                }
                unsafe { errno::set_errno(error) };
                return ptr::null_mut();
            }
            if result == 0 {
                continue;
            }
            initialized += result as usize;
        }

        let mut path = *b"/tmp/tmpfile_XXXXXXXXXXXXXXXXXXXXXXXX\0";
        let hexadecimal = b"0123456789abcdef";
        let mut index = 0;
        while index < entropy.len() {
            path[TMPFILE_SUFFIX_OFFSET + index * 2] = hexadecimal[(entropy[index] >> 4) as usize];
            path[TMPFILE_SUFFIX_OFFSET + index * 2 + 1] = hexadecimal[(entropy[index] & 0x0f) as usize];
            index += 1;
        }

        let descriptor = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_OPEN,
                path.as_ptr() as usize as i64,
                i64::from(O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE),
                0o600,
            )
        };
        if descriptor < 0 {
            last_open_error = (-descriptor) as c_int;
            attempt += 1;
            continue;
        }
        if descriptor > i64::from(c_int::MAX) {
            let _ = unsafe {
                raw_syscall::syscall1(raw_syscall::SYS_UNLINK, path.as_ptr() as usize as i64)
            };
            let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor) };
            unsafe { errno::set_errno(EOVERFLOW) };
            return ptr::null_mut();
        }

        let unlink_status = unsafe {
            raw_syscall::syscall1(raw_syscall::SYS_UNLINK, path.as_ptr() as usize as i64)
        };
        if unlink_status < 0 {
            let unlink_error = (-unlink_status) as c_int;
            let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor) };
            unsafe { errno::set_errno(unlink_error) };
            return ptr::null_mut();
        }

        let stream = unsafe { fdopen(descriptor as c_int, c"w+".as_ptr()) };
        if stream.is_null() { unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor); } }
        return stream;
    }

    unsafe { errno::set_errno(last_open_error) };
    ptr::null_mut()
}

unsafe fn is_selected_stream(stream: *const StandardStream) -> bool { !stream.is_null() }
unsafe fn is_descriptor_stream(stream: *const StandardStream) -> bool { !stream.is_null() }
unsafe fn reject_stream() { unsafe { errno::set_errno(EINVAL); } }

// musl's mode parser admits r/w/a plus b, +, e and x modifiers.
unsafe fn open_mode(mode: *const c_char) -> Option<(c_int, u32)> {
    unsafe {
        if mode.is_null() { return None; }
        let first = *mode as u8;
        let mut flags = match first { b'r' => 0, b'w' => 0o1101, b'a' => 0o2101, _ => return None };
        let mut stream_flags = if first == b'r' { F_NOWR } else { F_NORD };
        let mut cursor = mode.add(1);
        while *cursor != 0 {
            match *cursor as u8 {
                b'+' => { flags = (flags & !3) | 2; stream_flags = 0; }
                b'e' => flags |= 0o2000000,
                b'x' => flags |= 0o200,
                _ => (),
            }
            cursor = cursor.add(1);
        }
        if first == b'a' { stream_flags |= F_APP; }
        Some((flags, stream_flags))
    }
}

/// # Safety
/// `mode` is NUL terminated; `fd` is an open descriptor transferred on success.
/// Its access mode must permit the requested stream operations. As an
/// intentional diagnostic strengthening over musl __fdopen, invalid or
/// incompatible descriptors are rejected before ownership transfer.
#[no_mangle]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut StandardStream {
    unsafe {
        let Some((flags, stream_flags)) = open_mode(mode) else {
            errno::set_errno(EINVAL); return ptr::null_mut();
        };
        let current = c_status(raw_syscall::syscall3(72, fd as i64, 3, 0));
        if current < 0 { return ptr::null_mut(); }
        if (current & 3 == 0 && stream_flags & F_NOWR == 0)
            || (current & 3 == 1 && stream_flags & F_NORD == 0) {
            errno::set_errno(EINVAL); return ptr::null_mut();
        }
        let stream = malloc(core::mem::size_of::<StandardStream>()).cast::<StandardStream>();
        if stream.is_null() { return stream; }
        ptr::write(stream, StandardStream::new(fd, stream_flags, BUFSIZ));
        if flags & 0o2000000 != 0 { raw_syscall::syscall3(72, fd as i64, 2, 1); }
        if flags & 0o2000 != 0 && current & 0o2000 == 0 {
            if c_status(raw_syscall::syscall3(72, fd as i64, 4, (current | 0o2000) as i64)) < 0 {
                free(stream.cast()); return ptr::null_mut();
            }
        }
        // Unpublished dynamic state needs no lock. Establish terminal mode
        // at fdopen time, as musl does, before callers can replace the fd.
        initialize_buffer(stream);
        let _list = ListGuard::acquire();
        (*stream).next = OPEN_STREAMS;
        if !OPEN_STREAMS.is_null() { (*OPEN_STREAMS).previous = stream; }
        OPEN_STREAMS = stream;
        stream
    }
}

/// # Safety
/// `path` and `mode` are readable NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut StandardStream {
    unsafe {
        let Some((flags, _)) = open_mode(mode) else { errno::set_errno(EINVAL); return ptr::null_mut(); };
        let fd = c_status(raw_syscall::syscall4(257, -100, path as i64, flags as i64, 0o666));
        if fd < 0 { return ptr::null_mut(); }
        let stream = fdopen(fd, mode);
        if stream.is_null() { raw_syscall::syscall1(3, fd as i64); }
        stream
    }
}

/// # Safety
/// `stream` is live; all concurrent users have stopped and caller relinquishes it.
#[no_mangle]
pub unsafe extern "C" fn fclose(stream: *mut StandardStream) -> c_int {
    unsafe {
        let permanent = is_permanent_stream(stream);
        if !permanent {
            let _list = ListGuard::acquire();
            if (*stream).previous.is_null() { OPEN_STREAMS = (*stream).next; }
            else { (*(*stream).previous).next = (*stream).next; }
            if !(*stream).next.is_null() { (*(*stream).next).previous = (*stream).previous; }
        }
        let result;
        {
            let _guard = StreamGuard::acquire(stream);
            result = fflush(stream) | c_status(raw_syscall::syscall1(3, (*stream).file_descriptor as i64));
            (*stream).file_descriptor = -1;
        }
        if !permanent { free(stream.cast()); }
        result
    }
}

/// # Safety
/// A non-null stream must be live; null flushes all open output streams.
#[no_mangle]
pub unsafe extern "C" fn fflush(stream: *mut StandardStream) -> c_int {
    unsafe {
        if stream.is_null() {
            let mut result = fflush(ptr::addr_of_mut!(STDOUT_STREAM)) | fflush(ptr::addr_of_mut!(STDERR_STREAM));
            let _list = ListGuard::acquire();
            let mut current = OPEN_STREAMS;
            while !current.is_null() {
                let _guard = StreamGuard::acquire(current);
                result |= flush_output(current);
                current = (*current).next;
            }
            return result;
        }
        let _guard = StreamGuard::acquire(stream);
        if flush_output(stream) < 0 { return EOF; }
        let unread = (*stream).read_end.offset_from((*stream).read_position);
        if unread != 0 {
            // musl attempts input synchronization but does not fail fflush on ESPIPE.
            raw_syscall::syscall3(8, (*stream).file_descriptor as i64, -(unread as i64), 1);
        }
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        0
    }
}

/// Called after ordinary-exit callbacks; _Exit and abort deliberately skip it.
pub(crate) unsafe fn flush_all_on_exit() {
    unsafe {
        // musl __stdio_exit also restores descriptor positions after input
        // lookahead so an inherited/shared open description sees the logical
        // position, rather than the end of our private read buffer.
        fflush(ptr::addr_of_mut!(STDIN_STREAM));
        fflush(ptr::addr_of_mut!(STDOUT_STREAM));
        fflush(ptr::addr_of_mut!(STDERR_STREAM));
        let _list = ListGuard::acquire();
        let mut stream = OPEN_STREAMS;
        while !stream.is_null() {
            fflush(stream);
            stream = (*stream).next;
        }
    }
}

unsafe fn prepare_read(stream: *mut StandardStream) -> bool {
    if !unsafe { is_descriptor_stream(stream) } || !unsafe { is_writable(stream) } {
        return true;
    }
    unsafe { flush_output(stream) != EOF }
}

unsafe fn prepare_write(stream: *mut StandardStream) -> bool {
    if !unsafe { is_descriptor_stream(stream) } {
        return true;
    }
    let unread = unsafe { (*stream).read_end.offset_from((*stream).read_position) };
    if unread == 0 {
        return true;
    }
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from((*stream).file_descriptor),
            -(unread as i64),
            i64::from(SEEK_CUR),
        )
    };
    if c_off_status(result) < 0 {
        unsafe { mark_error(stream) };
        return false;
    }
    unsafe {
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
    }
    true
}

unsafe fn mark_io_started(stream: *mut StandardStream) {
    if unsafe { is_descriptor_stream(stream) } {
        unsafe { (*stream).flags |= F_IO_STARTED };
    }
}

unsafe fn mark_error(stream: *mut StandardStream) {
    unsafe { (*stream).flags |= F_ERR };
}

unsafe fn is_readable(stream: *const StandardStream) -> bool {
    unsafe { (*stream).flags & F_NORD == 0 }
}

unsafe fn is_writable(stream: *const StandardStream) -> bool {
    unsafe { (*stream).flags & F_NOWR == 0 }
}

unsafe fn refill_into(
    stream: *mut StandardStream,
    destination: *mut u8,
    length: usize,
) -> usize {
    // Preserve musl's caller-plus-lookahead readv: the final requested byte
    // comes from the FILE buffer, leaving its suffix for later byte reads.
    if length == 0 {
        return 0;
    }
    if unsafe { (*stream).flags & F_EOF != 0 } {
        return 0;
    }

    let (file_descriptor, buffer, capacity) = unsafe {
        (
            (*stream).file_descriptor,
            (*stream).buffer,
            (*stream).capacity,
        )
    };
    let overlaps = (destination as usize) < (buffer as usize).saturating_add(capacity)
        && (buffer as usize) < (destination as usize).saturating_add(length);
    if capacity == 0 || overlaps {
        let count = c_ssize_status(unsafe { raw_syscall::syscall3(raw_syscall::SYS_READ,
            i64::from(file_descriptor), destination as i64, length as i64) });
        if count <= 0 {
            unsafe { if count == 0 { (*stream).flags |= F_EOF; } else { mark_error(stream); } }
            return 0;
        }
        return count as usize;
    }

    let direct_length = length - 1;
    let result = if direct_length == 0 {
        unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_READ,
                i64::from(file_descriptor),
                buffer as usize as i64,
                capacity as i64,
            )
        }
    } else {
        let mut vectors = [
            IoVec {
                base: destination.cast(),
                length: direct_length,
            },
            IoVec {
                base: buffer.cast(),
                length: capacity,
            },
        ];
        unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_READV,
                i64::from(file_descriptor),
                vectors.as_mut_ptr() as usize as i64,
                vectors.len() as i64,
            )
        }
    };
    let count = c_ssize_status(result);
    if count < 0 {
        unsafe { mark_error(stream) };
        return 0;
    }
    if count == 0 {
        unsafe { (*stream).flags |= F_EOF };
        return 0;
    }

    let count = count as usize;
    unsafe {
        if direct_length == 0 {
            (*stream).read_position = buffer.add(1);
            (*stream).read_end = buffer.add(count);
            destination.write(buffer.read());
            return 1;
        }
        if count <= direct_length {
            return count;
        }
        let retained = count - direct_length;
        (*stream).read_position = buffer.add(1);
        (*stream).read_end = buffer.add(retained);
        destination.add(direct_length).write(buffer.read());
        length
    }
}

pub(crate) unsafe fn read_byte(stream: *mut StandardStream) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return EOF;
    }
    if !unsafe { is_readable(stream) } {
        unsafe { mark_error(stream) };
        return EOF;
    }
    if !unsafe { prepare_read(stream) } {
        return EOF;
    }
    unsafe { mark_io_started(stream) };
    unsafe {
        if (*stream).read_position < (*stream).read_end {
            let byte = (*stream).read_position.read();
            (*stream).read_position = (*stream).read_position.add(1);
            return c_int::from(byte);
        }
    }

    let mut byte = 0u8;
    if unsafe { refill_into(stream, ptr::addr_of_mut!(byte), 1) } == 0 {
        EOF
    } else {
        c_int::from(byte)
    }
}

pub(crate) unsafe fn flush_output(stream: *mut StandardStream) -> c_int {
    // As in musl __stdio_write, an output error discards pending buffered
    // bytes and sets F_ERR; a later clearerr/write may start fresh.
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_writable(stream) } {
        return 0;
    }
    let pending = unsafe {
        (*stream)
            .write_position
            .offset_from((*stream).buffer) as usize
    };
    if pending == 0 {
        return 0;
    }

    let mut written = 0usize;
    while written < pending {
        let result = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_WRITE,
                i64::from((*stream).file_descriptor),
                (*stream).buffer.add(written) as usize as i64,
                (pending - written) as i64,
            )
        };
        let count = c_ssize_status(result);
        if count <= 0 {
            if count == 0 {
                unsafe { errno::set_errno(EIO) };
            }
            unsafe {
                (*stream).write_position = (*stream).buffer;
                mark_error(stream);
            }
            return EOF;
        }
        written += count as usize;
    }
    unsafe { (*stream).write_position = (*stream).buffer };
    0
}

pub(crate) unsafe fn write_byte(stream: *mut StandardStream, byte: u8) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return EOF;
    }
    if !unsafe { is_writable(stream) } {
        unsafe { mark_error(stream) };
        return EOF;
    }
    if !unsafe { prepare_write(stream) } {
        return EOF;
    }
    unsafe { mark_io_started(stream) };
    let capacity = unsafe { (*stream).capacity };
    if capacity == 0 {
        let result = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_WRITE,
                i64::from((*stream).file_descriptor),
                ptr::addr_of!(byte) as usize as i64,
                1,
            )
        };
        if c_ssize_status(result) == 1 {
            return c_int::from(byte);
        }
        unsafe { mark_error(stream) };
        return EOF;
    }

    unsafe {
        if (*stream).write_position == (*stream).buffer.add(capacity)
            && flush_output(stream) == EOF
        {
            return EOF;
        }
        (*stream).write_position.write(byte);
        (*stream).write_position = (*stream).write_position.add(1);
    }
    if unsafe { (*stream).line_buffered } && byte == b'\n' && unsafe { flush_output(stream) } < 0 { return EOF; }
    c_int::from(byte)
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn fileno(stream: *mut StandardStream) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return -1;
    }
    unsafe { (*stream).file_descriptor }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn fgetc(stream: *mut StandardStream) -> c_int {
    unsafe { read_byte(stream) }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn getc(stream: *mut StandardStream) -> c_int {
    unsafe { fgetc(stream) }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn getchar() -> c_int {
    unsafe { fgetc(ptr::addr_of_mut!(STDIN_STREAM)) }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn ungetc(character: c_int, stream: *mut StandardStream) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return EOF;
    }
    if character == EOF {
        return EOF;
    }
    if !unsafe { is_readable(stream) } {
        unsafe { mark_error(stream) };
        return EOF;
    }
    if !unsafe { prepare_read(stream) } { return EOF; }
    unsafe {
        let lower_bound = (*stream).buffer.sub(UNGET);
        if (*stream).read_position <= lower_bound {
            return EOF;
        }
        (*stream).read_position = (*stream).read_position.sub(1);
        (*stream).read_position.write(character as u8);
        (*stream).flags &= !F_EOF;
    }
    unsafe { mark_io_started(stream) };
    c_int::from(character as u8)
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn fread(
    destination: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut StandardStream,
) -> usize {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if size == 0 || count == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(count) else {
        unsafe {
            errno::set_errno(EOVERFLOW);
            mark_error(stream);
        }
        return 0;
    };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return 0;
    }
    if !unsafe { is_readable(stream) } {
        unsafe { mark_error(stream) };
        return 0;
    }
    if !unsafe { prepare_read(stream) } {
        return 0;
    }
    unsafe { mark_io_started(stream) };

    let mut received = 0usize;
    let destination = destination.cast::<u8>();
    while received < total {
        let next = unsafe { destination.add(received) };
        let buffered = unsafe {
            ((*stream).read_end as usize).saturating_sub((*stream).read_position as usize)
        };
        if buffered != 0 {
            let copied = core::cmp::min(buffered, total - received);
            unsafe {
                ptr::copy_nonoverlapping((*stream).read_position, next, copied);
                (*stream).read_position = (*stream).read_position.add(copied);
            }
            received += copied;
            continue;
        }
        let read = unsafe { refill_into(stream, next, total - received) };
        if read == 0 {
            break;
        }
        received += read;
    }
    received / size
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn fputc(character: c_int, stream: *mut StandardStream) -> c_int {
    unsafe { write_byte(stream, character as u8) }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn putc(character: c_int, stream: *mut StandardStream) -> c_int {
    unsafe { fputc(character, stream) }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn putchar(character: c_int) -> c_int {
    unsafe { fputc(character, ptr::addr_of_mut!(STDOUT_STREAM)) }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn fwrite(
    source: *const c_void,
    size: usize,
    count: usize,
    stream: *mut StandardStream,
) -> usize {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if size == 0 || count == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(count) else {
        unsafe {
            mark_error(stream);
        }
        return 0;
    };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return 0;
    }
    if !unsafe { is_writable(stream) } {
        unsafe { mark_error(stream) };
        return 0;
    }
    if !unsafe { prepare_write(stream) } {
        return 0;
    }
    unsafe { mark_io_started(stream) };

    let source = source.cast::<u8>();
    let mut written = 0usize;
    while written < total {
        if unsafe { write_byte(stream, source.add(written).read()) } == EOF {
            break;
        }
        written += 1;
    }
    written / size
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn fgets(
    destination: *mut c_char,
    count: c_int,
    stream: *mut StandardStream,
) -> *mut c_char {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return ptr::null_mut();
    }
    if destination.is_null() {
        unsafe { errno::set_errno(EINVAL) };
        return ptr::null_mut();
    }
    if count <= 1 {
        if count == 1 {
            unsafe { destination.write(0) };
            return destination;
        }
        return ptr::null_mut();
    }

    let mut cursor = destination;
    let mut remaining = count;
    let mut stopped_on_error = false;
    while remaining > 1 {
        let character = unsafe { read_byte(stream) };
        if character == EOF {
            stopped_on_error = unsafe { (*stream).flags & F_ERR != 0 };
            break;
        }
        unsafe { cursor.write(character as u8 as c_char) };
        cursor = unsafe { cursor.add(1) };
        remaining -= 1;
        if character == c_int::from(b'\n') {
            break;
        }
    }
    if cursor == destination || stopped_on_error {
        return ptr::null_mut();
    }
    unsafe { cursor.write(0) };
    destination
}

/// # Safety
/// `stream` must be a live FILE and `source` a readable NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn fputs(
    source: *const c_char,
    stream: *mut StandardStream,
) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return EOF;
    }
    if source.is_null() {
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }

    let mut cursor = source;
    loop {
        let byte = unsafe { cursor.read() as u8 };
        if byte == 0 {
            return 0;
        }
        if unsafe { write_byte(stream, byte) } == EOF {
            return EOF;
        }
        cursor = unsafe { cursor.add(1) };
    }
}

/// # Safety
/// `source` must be a readable NUL-terminated string and stdout must be open.
#[no_mangle]
pub unsafe extern "C" fn puts(source: *const c_char) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(ptr::addr_of_mut!(STDOUT_STREAM)) };
    if unsafe { fputs(source, ptr::addr_of_mut!(STDOUT_STREAM)) } == EOF {
        return EOF;
    }
    if unsafe { write_byte(ptr::addr_of_mut!(STDOUT_STREAM), b'\n') } == EOF {
        EOF
    } else {
        0
    }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn feof(stream: *mut StandardStream) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return 0;
    }
    unsafe { ((*stream).flags & F_EOF) as c_int }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn ferror(stream: *mut StandardStream) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return 0;
    }
    unsafe { ((*stream).flags & F_ERR) as c_int }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn clearerr(stream: *mut StandardStream) {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return;
    }
    unsafe { (*stream).flags &= !(F_EOF | F_ERR) };
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn fseeko(
    stream: *mut StandardStream,
    offset: i64,
    whence: c_int,
) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_descriptor_stream(stream) }
        || (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END)
    {
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }

    let unread = unsafe { (*stream).read_end.offset_from((*stream).read_position) };
    let adjusted_offset = if whence == SEEK_CUR {
        let unread = unread as i64;
        let Some(value) = offset.checked_sub(unread) else {
            unsafe { errno::set_errno(EOVERFLOW) };
            return EOF;
        };
        value
    } else {
        offset
    };
    if unsafe { flush_output(stream) } == EOF {
        return EOF;
    }
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from((*stream).file_descriptor),
            adjusted_offset,
            i64::from(whence),
        )
    };
    if c_off_status(result) < 0 {
        return EOF;
    }
    unsafe {
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).write_position = (*stream).buffer;
        (*stream).flags &= !F_EOF;
    }
    0
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn ftello(stream: *mut StandardStream) -> i64 {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_descriptor_stream(stream) } {
        unsafe { reject_stream() };
        return -1;
    }
    let raw_position = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from((*stream).file_descriptor),
            0,
            if unsafe { (*stream).flags & F_APP != 0 && (*stream).write_position != (*stream).buffer } { i64::from(SEEK_END) } else { i64::from(SEEK_CUR) },
        )
    };
    let kernel_position = c_off_status(raw_position);
    if kernel_position < 0 {
        return -1;
    }
    let unread = unsafe { (*stream).read_end.offset_from((*stream).read_position) } as i64;
    let pending = if unsafe { is_writable(stream) } {
        (unsafe { (*stream).write_position.offset_from((*stream).buffer) }) as i64
    } else {
        0
    };
    let Some(logical_position) = kernel_position
        .checked_sub(unread)
        .and_then(|position| position.checked_add(pending))
    else {
        unsafe { errno::set_errno(EOVERFLOW) };
        return -1;
    };
    logical_position
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn ftell(stream: *mut StandardStream) -> core::ffi::c_long {
    unsafe { ftello(stream) as core::ffi::c_long }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn fseek(
    stream: *mut StandardStream,
    offset: core::ffi::c_long,
    whence: c_int,
) -> c_int {
    unsafe { fseeko(stream, offset as i64, whence) }
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn rewind(stream: *mut StandardStream) {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    let _ = unsafe { fseeko(stream, 0, SEEK_SET) };
    if unsafe { is_descriptor_stream(stream) } {
        unsafe { (*stream).flags &= !(F_EOF | F_ERR) };
    }
}

/// # Safety
/// `stream` must be live. `position` must point to writable storage for one
/// installed x86 `fpos_t` object (16 bytes, aligned to 8 bytes). The first
/// eight bytes hold the opaque saved offset; callers must not interpret it.
#[no_mangle]
pub unsafe extern "C" fn fgetpos(
    stream: *mut StandardStream,
    position: *mut c_void,
) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if position.is_null() {
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }
    let offset = unsafe { ftello(stream) };
    if offset < 0 {
        return EOF;
    }
    unsafe { ptr::write_unaligned(position.cast::<i64>(), offset) };
    0
}

/// # Safety
/// `stream` must be live. `position` must point to a readable installed x86
/// `fpos_t` object (16 bytes, aligned to 8 bytes) previously populated by a
/// successful fgetpos for this stream and not modified since that call.
#[no_mangle]
pub unsafe extern "C" fn fsetpos(
    stream: *mut StandardStream,
    position: *const c_void,
) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if position.is_null() {
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }
    let offset = unsafe { ptr::read_unaligned(position.cast::<i64>()) };
    unsafe { fseeko(stream, offset, SEEK_SET) }
}


/// # Safety
/// Configure a live stream before I/O. Non-null `buffer` remains writable for
/// `size` bytes until close or the next permitted configuration.
#[no_mangle]
pub unsafe extern "C" fn setvbuf(stream: *mut StandardStream, buffer: *mut c_char, mode: c_int, size: usize) -> c_int {
    unsafe {
        let _guard = StreamGuard::acquire(stream);
        if !(0..=2).contains(&mode) { errno::set_errno(EINVAL); return -1; }
        (*stream).line_buffered = mode == 1;
        if mode == 2 { (*stream).capacity = 0; }
        else if !buffer.is_null() && size >= UNGET {
            (*stream).buffer = buffer.cast::<u8>().add(UNGET);
            (*stream).capacity = size - UNGET;
        }
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).write_position = (*stream).buffer;
        0
    }
}
