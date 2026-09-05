//! Owned native x86 byte/wide stream engine.
//!
//! Source map: pinned musl 1.2.6 commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT; see
//! `compat/upstreams.toml`): stdio_impl.h and stdin/stdout/stderr.c map to
//! StandardStream and permanent storage; __stdio_read/__toread/__uflow and
//! __stdio_write/__towrite/__overflow map to the byte/block helpers retained
//! from the existing x86 stdio_standard.rs translation. fdopen/fopen/fclose,
//! ofl/ofl_add, flockfile/ftrylockfile/funlockfile, fflush, setvbuf, and
//! fseek/ftell map to the corresponding lifecycle below. freopen.c maps to
//! reopen_descriptor/freopen, and getdelim.c/getline.c map to allocated line
//! input. Public FILE is opaque; the installed freopen64 spelling is a macro
//! for freopen, as in pinned musl.
//!
//! The registry owns only dynamic streams; allocation precedes insertion and
//! freeing follows removal. New-stream allocation and insertion never invoke
//! an allocator or application callback under the registry lock. getdelim and
//! growing memory output hold their FILE lock during realloc, matching musl;
//! fclose detaches the FILE before flushing/closing its backend. Permanent initialization requires
//! no heap allocation, including allocator
//! diagnostics before main. Registry walks hold the list lock before stream
//! locks. Like fclose in C, stream destruction requires callers to exclude
//! concurrent use. Recursive locks use Linux thread IDs and private futexes.
//!
//! `owned_stdio_backends` adds source-mapped fmemopen/open_memstream/fopencookie
//! to the same buffering, positioning, registry, locking and close lifecycle.
//! fwrite.c::__fwritex and __stdio_write supply bulk and vectored dispatch;
//! application callbacks execute without borrowed Rust backend references.
//! `owned_printf` supplies integer/byte and binary64/binary80 formatting;
//! `owned_scanf` supplies byte, numeric, scanset and allocated conversions.
//! `owned_wide_stdio` adds orientation, captured CTYPE and wide byte-buffered
//! I/O to this same FILE. `owned_stdio_process` supplies popen/pclose through
//! the shared spawn owner, also used by system. `owned_wide_format` consumes
//! the held wide and stack-string adapters. `owned_stdio_extensions` maps
//! ext.c/ext2.c and fgetln.c to the same active buffering and FILE-owned line
//! lifetime. Cancellation integration remains separate; fork preparation
//! consumes the narrow registry triplet. This is not stdio-family completion.

use core::{ffi::{c_char, c_int, c_void}, ptr, sync::atomic::{AtomicI32, Ordering}};
use super::{c_off_status, c_ssize_status, c_status, errno, raw_syscall};

#[path = "owned_stdio_backends.rs"]
mod owned_stdio_backends;
#[path = "owned_wide_stdio.rs"]
mod owned_wide_stdio;
#[path = "owned_stdio_process.rs"]
mod owned_stdio_process;
#[path = "owned_stdio_extensions.rs"]
mod owned_stdio_extensions;
use owned_stdio_backends::Backend;

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
const F_SVB: u32 = 64;
const F_APP: u32 = 128;
const F_IO_STARTED: u32 = 512;
// Private discriminator for musl stdout's one-time __stdout_write callback.
const F_STDOUT_WRITE: u32 = 1024;
const SEEK_SET: c_int = 0;
const SEEK_CUR: c_int = 1;
const SEEK_END: c_int = 2;

#[repr(C)]
struct IoVec { base: *mut c_void, length: usize }

// musl represents active input/output by non-null rend/wend, independently
// of orientation and access restrictions. Our buffer pointers stay initialized
// even when inactive, so retain precisely that distinction as explicit state.
// Successful flush/seek/purge deactivate it; a global flush visits only dynamic
// streams with pending output. Callback inspection observes the active state.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum BufferDirection { Neutral, Read, Write }

/// Opaque FILE state. Only pointers returned by this engine are valid.
/// Orientation is zero until first byte/wide admission and is reset only by
/// successful freopen. A nonzero fwide/wide-I/O admission snapshots CTYPE;
/// later setlocale/uselocale changes do not retarget this FILE's codec.
#[repr(C)]
pub struct StandardStream {
    flags: u32,
    file_descriptor: c_int,
    pipe_pid: c_int,
    orientation: i8,
    wide_locale: Option<bool>,
    direction: BufferDirection,
    // fgetln fallback allocation belongs to this FILE, not the borrowed caller;
    // successful freopen retains it and dynamic fclose frees it after detach.
    getln_buffer: *mut c_char,
    buffer: *mut u8,
    capacity: usize,
    read_position: *mut u8,
    read_end: *mut u8,
    write_position: *mut u8,
    owner: AtomicI32,
    lock_count: usize,
    // musl ftrylockfile.c: only explicit caller locks enter the current
    // task's intrusive list; internal operation guards never enter it.
    next_locked: *mut StandardStream,
    previous_locked: *mut StandardStream,
    next: *mut StandardStream,
    previous: *mut StandardStream,
    line_buffered: bool,
    backend: Backend,
    write_failed: bool,
    storage: [u8; BUFSIZ + UNGET],
}

impl StandardStream {
    const fn new(fd: c_int, flags: u32, capacity: usize) -> Self {
        Self { flags, file_descriptor: fd, pipe_pid: 0, orientation: 0, wide_locale: None,
            direction: BufferDirection::Neutral, getln_buffer: ptr::null_mut(),
            buffer: ptr::null_mut(), capacity,
            read_position: ptr::null_mut(), read_end: ptr::null_mut(),
            write_position: ptr::null_mut(), owner: AtomicI32::new(0),
            lock_count: 0, next: ptr::null_mut(), previous: ptr::null_mut(),
            next_locked: ptr::null_mut(), previous_locked: ptr::null_mut(),
            line_buffered: flags & F_STDOUT_WRITE != 0, backend: Backend::Descriptor, write_failed: false,
            storage: [0; BUFSIZ + UNGET] }
    }
}

static mut STDIN_STREAM: StandardStream = StandardStream::new(0, F_PERM | F_NOWR, BUFSIZ);
static mut STDOUT_STREAM: StandardStream = StandardStream::new(1, F_PERM | F_NORD | F_STDOUT_WRITE, BUFSIZ);
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
    fn realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
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
            if matches!((*stream).backend, Backend::Descriptor)
                && (*stream).flags & (F_NOWR | F_STDOUT_WRITE) == 0 && (*stream).capacity != 0 {
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

/// Acquire musl fork.c's __stdio_ofl_lockptr position in the process owner's
/// ordered fork transaction. No individual FILE lock is taken.
/// # Safety
/// The process owner has run user prepare callbacks and blocked application
/// signals; it holds earlier internal locks in musl order. Exactly one matching
/// parent or child hook must run before signals/user callbacks resume.
pub(super) unsafe fn pthread_fork_prepare() {
    // The transaction crosses a raw fork, so each process explicitly completes
    // its own lock transition instead of inheriting a Rust destructor lifetime.
    core::mem::forget(unsafe { ListGuard::acquire() });
}

/// Release the prepared registry lock in the original process.
/// # Safety
/// This is the original process's matching completion of pthread_fork_prepare,
/// including the failed-fork path; no other completion has run.
pub(super) unsafe fn pthread_fork_parent() {
    drop(ListGuard);
}

/// Reset only the inherited registry lock, preserving every stream and buffer.
/// # Safety
/// This runs once in the sole surviving child thread after a prepared fork,
/// before signals or user child callbacks resume. It must not run in a
/// CLONE_VM popen child or in the original process.
pub(super) unsafe fn pthread_fork_child() {
    LIST_LOCK.store(0, Ordering::Relaxed);
}

pub(crate) struct StreamGuard(*mut StandardStream, bool);
impl StreamGuard {
    /// Caller supplies a live FILE; the guard serializes all state access.
    pub(crate) unsafe fn acquire(stream: *mut StandardStream) -> Self {
        let acquired = unsafe { lock_internal(stream) };
        Self(stream, acquired)
    }
}
impl Drop for StreamGuard {
    fn drop(&mut self) { if self.1 { unsafe { unlock_internal(self.0); } } }
}

unsafe fn lock_internal(stream: *mut StandardStream) -> bool {
    unsafe {
        let tid = raw_syscall::syscall0(186) as i32;
        if (*stream).owner.load(Ordering::Relaxed) == tid { return false; }
        loop {
            if (*stream).owner.compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                initialize_buffer(stream);
                return true;
            }
            let owner = (*stream).owner.load(Ordering::Relaxed);
            if owner != 0 { futex_wait(&(*stream).owner, owner); }
        }
    }
}

unsafe fn unlock_internal(stream: *mut StandardStream) {
    unsafe {
        (*stream).owner.store(0, Ordering::Release);
        futex_wake(&(*stream).owner);
    }
}

unsafe fn register_locked_file(stream: *mut StandardStream) {
    unsafe {
        (*stream).lock_count = 1;
        (*stream).previous_locked = ptr::null_mut();
        if let Some(head) = super::pthread_cancel::current_stdio_lock_head() {
            (*stream).next_locked = head.load(Ordering::Relaxed) as *mut StandardStream;
            if !(*stream).next_locked.is_null() { (*(*stream).next_locked).previous_locked = stream; }
            head.store(stream as usize, Ordering::Relaxed);
        }
    }
}

unsafe fn unlist_locked_file(stream: *mut StandardStream) {
    unsafe {
        if (*stream).lock_count == 0 { return; }
        if !(*stream).next_locked.is_null() {
            (*(*stream).next_locked).previous_locked = (*stream).previous_locked;
        }
        if !(*stream).previous_locked.is_null() {
            (*(*stream).previous_locked).next_locked = (*stream).next_locked;
        } else if let Some(head) = super::pthread_cancel::current_stdio_lock_head() {
            head.store((*stream).next_locked as usize, Ordering::Relaxed);
        }
    }
}

// musl __do_orphaned_stdio_locks deliberately does not unlock or wake: another
// task cannot acquire a departed owner's explicit FILE lock. Retaining this
// sentinel also prevents recycled Linux TIDs from appearing to own the lock.
pub(super) unsafe fn orphan_current_stdio_locks() {
    unsafe {
        if let Some(head) = super::pthread_cancel::current_stdio_lock_head() {
            let mut stream = head.load(Ordering::Relaxed) as *mut StandardStream;
            while !stream.is_null() {
                (*stream).owner.store(0x4000_0000, Ordering::Release);
                stream = (*stream).next_locked;
            }
        }
    }
}

/// # Safety
/// `stream` must be a live FILE owned by this runtime.
#[no_mangle]
pub unsafe extern "C" fn ftrylockfile(stream: *mut StandardStream) -> c_int {
    unsafe {
        let tid = raw_syscall::syscall0(186) as i32;
        if (*stream).owner.load(Ordering::Relaxed) == tid {
            if (*stream).lock_count == isize::MAX as usize { return -1; }
            (*stream).lock_count += 1;
            return 0;
        }
        if (*stream).owner.compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return -1;
        }
        register_locked_file(stream);
        initialize_buffer(stream);
        0
    }
}

/// # Safety
/// `stream` must be live and must not be concurrently closed.
#[no_mangle]
pub unsafe extern "C" fn flockfile(stream: *mut StandardStream) {
    unsafe {
        if ftrylockfile(stream) == 0 { return; }
        lock_internal(stream);
        register_locked_file(stream);
    }
}

/// # Safety
/// The calling thread must own a matching FILE lock acquisition.
#[no_mangle]
pub unsafe extern "C" fn funlockfile(stream: *mut StandardStream) {
    unsafe {
        if (*stream).lock_count == 1 {
            unlist_locked_file(stream);
            (*stream).lock_count = 0;
            unlock_internal(stream);
        } else { (*stream).lock_count -= 1; }
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
        publish_stream(stream)
    }
}

// The caller exclusively owns initialized, unpublished dynamic storage.
// No allocator or application callback is entered while holding LIST_LOCK.
unsafe fn publish_stream(stream: *mut StandardStream) -> *mut StandardStream {
    unsafe {
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

// musl freopen keeps the original buffer and FILE identity, replacing only
// descriptor behavior and access flags. Opening an allocation-free temporary
// descriptor is sufficient for a descriptor-backed FILE. Memory/cookie FILEs
// have fd=-1, so dup3/fcntl fails and fclose retires their backend, as in musl.
// Unlike opening a temporary FILE under the old FILE lock,
// this cannot acquire the registry lock in stream->registry order. Avoiding
// that unnecessary allocation also removes musl's temporary-FILE ENOMEM case.
// The caller holds the stream lock and has attempted fflush first.
unsafe fn reopen_descriptor(path: *const c_char, mode: *const c_char, stream: *mut StandardStream) -> bool {
    unsafe {
        let Some((flags, stream_flags)) = open_mode(mode) else {
            errno::set_errno(EINVAL);
            return false;
        };
        let old_fd = (*stream).file_descriptor as i64;
        if path.is_null() {
            // Preserve musl's null-path branch: adjust the existing open
            // description's status flags without clearing FILE indicators or
            // replacing the stream's existing access restrictions.
            if flags & 0o2000000 != 0 { raw_syscall::syscall3(72, old_fd, 2, 1); }
            let status_flags = flags & !(0o100 | 0o200 | 0o2000000);
            return c_status(raw_syscall::syscall3(72, old_fd, 4, status_flags as i64)) >= 0;
        }
        let replacement = c_status(raw_syscall::syscall4(257, -100, path as i64, flags as i64, 0o666));
        if replacement < 0 { return false; }
        if replacement as i64 != old_fd {
            let duplicated = c_status(raw_syscall::syscall3(292,
                replacement as i64, old_fd, (flags & 0o2000000) as i64));
            // Raw close cannot overwrite a duplication error in errno.
            raw_syscall::syscall1(3, replacement as i64);
            if duplicated < 0 { return false; }
        }
        // If open reused an externally closed old fd, it is already the
        // replacement descriptor and must not be closed as temporary state.
        (*stream).flags = ((*stream).flags & F_PERM) | stream_flags;
        true
    }
}

/// Reopen an existing descriptor stream, retaining its FILE address and buffer.
/// Failure retires the old stream as fclose would, including its descriptor.
/// # Safety
/// `stream` must be live and not concurrently destroyed. `mode` and a non-null
/// `path` must be readable NUL-terminated strings. All stream and buffer storage
/// remains valid through the call; after failure the FILE pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn freopen(path: *const c_char, mode: *const c_char, stream: *mut StandardStream) -> *mut StandardStream {
    unsafe {
        let guard = StreamGuard::acquire(stream);
        // musl attempts the old flush even when the replacement open will
        // fail, and does not let a flush failure prevent a successful reopen.
        fflush(stream);
        let reopened = reopen_descriptor(path, mode, stream);
        if reopened { (*stream).orientation = 0; (*stream).wide_locale = None; }
        drop(guard);
        if reopened { return stream; }
        // Registry removal cannot happen under the held FILE lock: a global
        // flush may already hold the list lock while waiting for this stream.
        fclose(stream);
        ptr::null_mut()
    }
}

/// Read through a delimiter into caller-owned reallocatable storage.
/// The delimiter is included in the returned length, followed by a NUL byte.
/// # Safety
/// `stream` must be live. Non-null `line` and `capacity` must point to writable
/// pointer and size objects; either null argument is diagnosed with EINVAL.
/// A non-null `*line` must be a malloc-family allocation of
/// at least `*capacity` bytes, exclusively available for realloc and writes.
/// The output allocation and FILE buffering storage must not overlap. The
/// caller retains ownership of `*line`, including after failure, and frees it.
#[no_mangle]
pub unsafe extern "C" fn getdelim(line: *mut *mut c_char, capacity: *mut usize, delimiter: c_int, stream: *mut StandardStream) -> isize {
    unsafe {
        let _guard = StreamGuard::acquire(stream);
        if line.is_null() || capacity.is_null() {
            mark_error(stream);
            errno::set_errno(EINVAL);
            return -1;
        }
        if (*line).is_null() { *capacity = 0; }
        let mut used = 0usize;
        loop {
            let available = (*stream).read_end.offset_from((*stream).read_position) as usize;
            let mut chunk = available;
            let mut found = false;
            for index in 0..available {
                if *(*stream).read_position.add(index) == delimiter as u8 {
                    chunk = index + 1;
                    found = true;
                    break;
                }
            }
            // Refuse a length that cannot be returned as ssize_t rather than
            // wrap the allocation arithmetic. No unread byte is consumed.
            let Some(end) = used.checked_add(chunk).filter(|end| *end <= isize::MAX as usize) else {
                mark_error(stream);
                errno::set_errno(EOVERFLOW);
                return -1;
            };
            if end >= *capacity {
                let minimum = end + 2;
                let mut wanted = minimum;
                if !found && wanted < usize::MAX / 4 { wanted += wanted / 2; }
                let mut grown = realloc((*line).cast(), wanted).cast::<c_char>();
                if grown.is_null() {
                    wanted = minimum;
                    grown = realloc((*line).cast(), wanted).cast::<c_char>();
                    if grown.is_null() {
                        // Pinned getdelim consumes only the prefix which fits
                        // the original allocation, retaining its ownership.
                        let fitting = *capacity - used;
                        if fitting != 0 {
                            ptr::copy_nonoverlapping((*stream).read_position,
                                (*line).add(used).cast::<u8>(), fitting);
                            (*stream).read_position = (*stream).read_position.add(fitting);
                        }
                        mark_error(stream);
                        errno::set_errno(12);
                        return -1;
                    }
                }
                *line = grown;
                *capacity = wanted;
            }
            if chunk != 0 {
                ptr::copy_nonoverlapping((*stream).read_position,
                    (*line).add(used).cast::<u8>(), chunk);
                (*stream).read_position = (*stream).read_position.add(chunk);
                used = end;
            }
            if found { break; }
            let character = read_byte_held(stream);
            if character == EOF {
                if used == 0 || (*stream).flags & F_EOF == 0 { return -1; }
                break;
            }
            if used == isize::MAX as usize {
                (*stream).read_position = (*stream).read_position.sub(1);
                *(*stream).read_position = character as u8;
                mark_error(stream);
                errno::set_errno(EOVERFLOW);
                return -1;
            }
            // If the fallback byte needs growth, retain it in FILE pushback
            // storage before realloc can fail. This preserves the cursor on
            // the same allocation-failure paths as musl getdelim.c.
            if used + 1 >= *capacity {
                (*stream).read_position = (*stream).read_position.sub(1);
                *(*stream).read_position = character as u8;
            } else {
                *(*line).add(used) = character as c_char;
                used += 1;
                if character == delimiter { break; }
            }
        }
        *(*line).add(used) = 0;
        used as isize
    }
}

/// Read one allocated newline-delimited byte string using getdelim.
/// # Safety
/// The stream, pointer, allocation-size, ownership and non-overlap obligations
/// are exactly those of getdelim; the caller frees the resulting allocation.
#[no_mangle]
pub unsafe extern "C" fn getline(line: *mut *mut c_char, capacity: *mut usize, stream: *mut StandardStream) -> isize {
    unsafe { getdelim(line, capacity, b'\n' as c_int, stream) }
}

core::arch::global_asm!(".weak __getdelim", ".set __getdelim, getdelim");

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
            result = fflush(stream) | owned_stdio_backends::close(stream);
            (*stream).file_descriptor = -1;
        }
        if !permanent {
            unlist_locked_file(stream);
            free((*stream).getln_buffer.cast()); free(stream.cast());
        }
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
                if (*current).write_position != (*current).buffer { result |= fflush(current); }
                current = (*current).next;
            }
            return result;
        }
        let _guard = StreamGuard::acquire(stream);
        if flush_output_held(stream) < 0 { return EOF; }
        let unread = (*stream).read_end.offset_from((*stream).read_position);
        if unread != 0 {
            // musl attempts input synchronization but does not fail fflush on ESPIPE.
            owned_stdio_backends::seek(stream, -(unread as i64), 1);
        }
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).direction = BufferDirection::Neutral;
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
    unsafe {
        if is_writable(stream) && flush_output_held(stream) == EOF { return false; }
        (*stream).direction = BufferDirection::Read;
        true
    }
}

unsafe fn prepare_write(stream: *mut StandardStream) -> bool {
    if !unsafe { is_selected_stream(stream) } {
        return true;
    }
    let unread = unsafe { (*stream).read_end.offset_from((*stream).read_position) };
    if unread == 0 {
        unsafe { (*stream).direction = BufferDirection::Write; }
        return true;
    }
    let result = unsafe {
        owned_stdio_backends::seek(stream, -(unread as i64), SEEK_CUR)
    };
    if result < 0 {
        unsafe { mark_error(stream) };
        return false;
    }
    unsafe {
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).direction = BufferDirection::Write;
    }
    true
}

unsafe fn mark_io_started(stream: *mut StandardStream) {
    if unsafe { is_selected_stream(stream) } {
        unsafe {
            (*stream).flags |= F_IO_STARTED;
            if (*stream).orientation == 0 { (*stream).orientation = -1; }
        }
    }
}

unsafe fn orient_byte(stream: *mut StandardStream) {
    unsafe { if (*stream).orientation == 0 { (*stream).orientation = -1; } }
}

// Synchronous wide-parser bridge. The outer formatter/scanner owns one FILE
// guard across every callback; none of these helpers lends a Rust reference
// into the FILE to application code or lets the pointer escape.
pub(crate) unsafe fn wide_get_held(stream: *mut StandardStream) -> u32 { unsafe { owned_wide_stdio::get_held(stream) } }
pub(crate) unsafe fn wide_put_held(stream: *mut StandardStream, character: c_int) -> u32 { unsafe { owned_wide_stdio::put_held(character, stream) } }
pub(crate) unsafe fn wide_unget_held(stream: *mut StandardStream, character: u32) -> u32 { unsafe { owned_wide_stdio::ungetwc(character, stream) } }
pub(crate) unsafe fn wide_orient_held(stream: *mut StandardStream, mode: c_int) -> c_int { unsafe { owned_wide_stdio::orient(stream, mode) } }
pub(crate) unsafe fn wide_error_held(stream: *mut StandardStream) -> c_int { unsafe { ((*stream).flags & F_ERR != 0) as c_int } }
pub(crate) unsafe fn wide_format_begin_held(stream: *mut StandardStream) -> c_int {
    unsafe { let old = (*stream).flags & F_ERR; (*stream).flags &= !F_ERR; old as c_int }
}
pub(crate) unsafe fn wide_format_end_held(stream: *mut StandardStream, old: c_int) -> c_int {
    unsafe { let error = wide_error_held(stream); (*stream).flags |= old as u32; error }
}

// Source vswprintf/vswscanf use unregistered stack FILEs. These narrow helpers
// preserve that allocation-free ownership and 256-byte buffer boundary. The
// callback cannot retain the FILE or any private buffer after returning.
pub(crate) unsafe fn with_wide_output_buffer(destination: *mut c_int, capacity: usize,
    format: impl FnOnce(*mut StandardStream) -> c_int) -> c_int {
    unsafe {
        if capacity == 0 { return -1; }
        let mut stream = StandardStream::new(-1, F_NORD, 256);
        stream.backend = Backend::WideBounded { output: destination, remaining: capacity-1 };
        let stream = ptr::addr_of_mut!(stream);
        let _guard = StreamGuard::acquire(stream);
        let result = format(stream);
        write_backend_held(stream, ptr::null(), 0);
        if result >= 0 && result as usize >= capacity { -1 } else { result }
    }
}
pub(crate) unsafe fn with_wide_input_string(source: *const c_int,
    scan: impl FnOnce(*mut StandardStream) -> c_int) -> c_int {
    unsafe {
        let mut stream = StandardStream::new(-1, F_NOWR, 256);
        stream.backend = Backend::WideString { input: source };
        let stream = ptr::addr_of_mut!(stream);
        let _guard = StreamGuard::acquire(stream);
        scan(stream)
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
    if !unsafe { matches!((*stream).backend, Backend::Descriptor) } {
        return unsafe { owned_stdio_backends::read(stream, destination, length) };
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
    unsafe { read_byte_held(stream) }
}

// scanf's __toread admission happens even for an empty format. It starts no
// read syscall, but transitions away from buffered output and records wrong
// direction as F_ERR without changing errno, exactly like musl. The guard
// spans parser callbacks, %m cleanup and final delimiter restoration.
pub(crate) unsafe fn with_scanned_stream(stream: *mut StandardStream, scan: impl FnOnce() -> c_int) -> c_int {
    unsafe {
        let _guard = StreamGuard::acquire(stream);
        orient_byte(stream);
        if !is_readable(stream) { mark_error(stream); return EOF; }
        if !prepare_read(stream) { return EOF; }
        mark_io_started(stream);
        scan()
    }
}

// Only the above scoped adapter may invoke this initialized, held-lock read.
pub(crate) unsafe fn read_scanned_byte(stream: *mut StandardStream) -> c_int {
    unsafe { read_byte_held(stream) }
}

// The caller holds this stream's recursive lock and its buffer is initialized.
// Bulk/line operations reuse the held helper instead of calling gettid once
// per byte. Public entry points and external formatter clients use the guard.
unsafe fn read_byte_held(stream: *mut StandardStream) -> c_int {
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return EOF;
    }
    unsafe { orient_byte(stream); }
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

// The caller owns the stream lock, including around kernel writes.
unsafe fn flush_output_held(stream: *mut StandardStream) -> c_int {
    // As in musl __stdio_write, an output error discards pending buffered
    // bytes and sets F_ERR; a later clearerr/write may start fresh.
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

    unsafe {
        write_backend_held(stream, ptr::null(), 0);
        (*stream).write_position = (*stream).buffer;
        if (*stream).write_failed { EOF } else { 0 }
    }
}

// musl __stdio_write and backend mwrite/ms_write/cookiewrite: buffered bytes
// precede the new span, whose partial count alone is returned. Application
// callbacks receive no outstanding Rust references into stream storage.
unsafe fn write_backend_held(stream: *mut StandardStream, source: *const u8, length: usize) -> usize {
    unsafe {
        (*stream).write_failed = false;
        if !matches!((*stream).backend, Backend::Descriptor) {
            if owned_stdio_backends::ignores_writes(stream) { return length; }
            let pending = (*stream).write_position.offset_from((*stream).buffer) as usize;
            (*stream).write_position = (*stream).buffer;
            if pending != 0 && owned_stdio_backends::write(stream, (*stream).buffer, pending) < pending {
                if (*stream).write_failed { (*stream).direction = BufferDirection::Neutral; }
                return 0;
            }
            let written = owned_stdio_backends::write(stream, source, length);
            if (*stream).write_failed { (*stream).direction = BufferDirection::Neutral; }
            return written;
        }
        // __stdout_write is selected only for the original permanent stdout.
        // A query/lock does not run it. The first actual write replaces it,
        // and an explicit setvbuf configuration suppresses terminal probing.
        if (*stream).flags & F_STDOUT_WRITE != 0 {
            (*stream).flags &= !F_STDOUT_WRITE;
            if (*stream).flags & F_SVB == 0 {
                let mut window_size = [0u16; 4];
                if raw_syscall::syscall3(16, (*stream).file_descriptor as i64,
                    0x5413, window_size.as_mut_ptr() as i64) != 0 { (*stream).line_buffered = false; }
            }
        }
        let pending = (*stream).write_position.offset_from((*stream).buffer) as usize;
        let mut vectors = [IoVec { base: (*stream).buffer.cast(), length: pending },
            IoVec { base: source as *mut c_void, length }];
        let mut index = if pending == 0 { 1 } else { 0 };
        let mut remaining = pending + length;
        loop {
            let count = c_ssize_status(raw_syscall::syscall3(raw_syscall::SYS_WRITEV,
                (*stream).file_descriptor as i64, vectors.as_mut_ptr().add(index) as i64, (2-index) as i64));
            if count >= 0 && count as usize == remaining {
                (*stream).write_position = (*stream).buffer;
                return length;
            }
            if count <= 0 {
                if count == 0 { errno::set_errno(EIO); }
                (*stream).write_position = (*stream).buffer;
                (*stream).write_failed = true;
                (*stream).direction = BufferDirection::Neutral;
                mark_error(stream);
                return if index == 0 { 0 } else { length-vectors[index].length };
            }
            let mut count = count as usize;
            remaining -= count;
            if count > vectors[index].length { count -= vectors[index].length; index += 1; }
            vectors[index].base = vectors[index].base.cast::<u8>().add(count).cast();
            vectors[index].length -= count;
        }
    }
}

pub(crate) unsafe fn write_byte(stream: *mut StandardStream, byte: u8) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    unsafe { write_byte_held(stream, byte) }
}

/// Runs the source-mapped vfprintf FILE transition under one recursive lock.
/// The closure cannot retain the temporary buffer, whose pointer never leaves
/// this module. All normal returns restore buffering and the prior sticky
/// error even if parsing or descriptor output failed.
/// # Safety
/// `stream` is live; `format` accesses this stream only through held helpers
/// and does not close, reopen, or reconfigure it during the callback.
pub(crate) unsafe fn with_formatted_stream(stream: *mut StandardStream, format: impl FnOnce() -> c_int) -> c_int {
    unsafe {
        let _guard = StreamGuard::acquire(stream);
        let old_error = (*stream).flags & F_ERR;
        (*stream).flags &= !F_ERR;
        orient_byte(stream);
        if !is_writable(stream) || !prepare_write(stream) {
            (*stream).flags |= F_ERR | old_error;
            return EOF;
        }
        mark_io_started(stream); // __towrite orients even an empty printf.
        let mut temporary = [0u8; 80];
        let old_buffer = (*stream).buffer;
        let unbuffered = (*stream).capacity == 0;
        if unbuffered {
            (*stream).buffer = temporary.as_mut_ptr();
            (*stream).capacity = temporary.len();
            (*stream).write_position = (*stream).buffer;
        }
        let mut result = format();
        if unbuffered {
            // musl calls __stdio_write even for an empty formatted result;
            // unlike ordinary fflush, that validates the output descriptor.
            write_backend_held(stream, ptr::null(), 0);
            if (*stream).write_failed { result = EOF; }
            (*stream).buffer = old_buffer;
            (*stream).capacity = 0;
            (*stream).write_position = old_buffer;
            (*stream).direction = BufferDirection::Neutral;
        }
        if (*stream).flags & F_ERR != 0 { result = EOF; }
        (*stream).flags |= old_error;
        result
    }
}

/// # Safety
/// The caller holds the live stream's lock through with_formatted_stream.
pub(crate) unsafe fn write_formatted_byte(stream: *mut StandardStream, byte: u8) -> c_int {
    unsafe {
        fwrite_held((&byte as *const u8).cast(), 1, 1, stream);
        if (*stream).flags & F_ERR != 0 { EOF } else { byte as c_int }
    }
}

/// # Safety
/// The live FILE lock is held by with_formatted_stream; source is readable for
/// length bytes and does not overlap the stream's mutable buffering storage.
pub(crate) unsafe fn write_formatted_bytes(stream: *mut StandardStream, source: *const u8, length: usize) -> c_int {
    unsafe {
        // vfprintf out observes F_ERR, not a backend's non-error short count.
        fwrite_held(source.cast(), 1, length, stream);
        if (*stream).flags & F_ERR != 0 { EOF } else { 0 }
    }
}

// The caller owns the stream lock across the complete output operation.
unsafe fn write_byte_held(stream: *mut StandardStream, byte: u8) -> c_int {
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return EOF;
    }
    unsafe { orient_byte(stream); }
    if !unsafe { is_writable(stream) } {
        unsafe { mark_error(stream) };
        return EOF;
    }
    if !unsafe { prepare_write(stream) } {
        return EOF;
    }
    unsafe { mark_io_started(stream) };
    let capacity = unsafe { (*stream).capacity };
    unsafe {
        if (*stream).write_position == (*stream).buffer.add(capacity)
            || ((*stream).line_buffered && byte == b'\n')
        {
            return if write_backend_held(stream, &byte, 1) == 1 { byte as c_int } else { EOF };
        }
        (*stream).write_position.write(byte);
        (*stream).write_position = (*stream).write_position.add(1);
    }
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
    unsafe {
        if (*stream).file_descriptor < 0 { errno::set_errno(9); return -1; }
        (*stream).file_descriptor
    }
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
    unsafe { fread_held(destination, size, count, stream) }
}

// The caller exclusively owns the initialized stream through the transfer.
unsafe fn fread_held(destination: *mut c_void, size: usize, count: usize, stream: *mut StandardStream) -> usize {
    unsafe { if (*stream).orientation == 0 { (*stream).orientation = -1; } }
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
    unsafe { fwrite_held(source, size, count, stream) }
}

// The caller exclusively owns the initialized stream through the transfer.
unsafe fn fwrite_held(source: *const c_void, size: usize, count: usize, stream: *mut StandardStream) -> usize {
    unsafe { orient_byte(stream); }
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

    // musl fwrite.c::__fwritex: a span that does not fit bypasses the
    // ordinary byte loop, preserving partial caller-byte counts after any
    // pending output. Line buffering emits through the last newline.
    unsafe {
        if total == 0 { return if size == 0 { 0 } else { count }; }
        let source = source.cast::<u8>();
        let available = (*stream).buffer.add((*stream).capacity).offset_from((*stream).write_position) as usize;
        if total > available { return write_backend_held(stream, source, total) / size; }
        let mut prefix = 0;
        if (*stream).line_buffered {
            prefix = total;
            while prefix != 0 && *source.add(prefix-1) != b'\n' { prefix -= 1; }
            if prefix != 0 {
                let written = write_backend_held(stream, source, prefix);
                if written < prefix { return written / size; }
            }
        }
        ptr::copy_nonoverlapping(source.add(prefix), (*stream).write_position, total-prefix);
        (*stream).write_position = (*stream).write_position.add(total-prefix);
        count
    }
}

/// # Safety
/// `stream` is live and the caller has exclusive access, either by holding
/// flockfile or by excluding every concurrent user, including initialization.
#[no_mangle]
pub unsafe extern "C" fn fgetc_unlocked(stream: *mut StandardStream) -> c_int {
    unsafe { initialize_buffer(stream); read_byte_held(stream) }
}

/// # Safety
/// The live stream and exclusive-access obligations are those of fgetc_unlocked.
#[no_mangle]
pub unsafe extern "C" fn getc_unlocked(stream: *mut StandardStream) -> c_int {
    unsafe { fgetc_unlocked(stream) }
}

/// # Safety
/// stdin is open and the caller exclusively owns its access and initialization.
#[no_mangle]
pub unsafe extern "C" fn getchar_unlocked() -> c_int {
    unsafe { fgetc_unlocked(ptr::addr_of_mut!(STDIN_STREAM)) }
}

/// # Safety
/// The caller exclusively owns this live stream, including lazy initialization,
/// until the write completes; holding flockfile satisfies this requirement.
#[no_mangle]
pub unsafe extern "C" fn fputc_unlocked(character: c_int, stream: *mut StandardStream) -> c_int {
    unsafe { initialize_buffer(stream); write_byte_held(stream, character as u8) }
}

/// # Safety
/// The live stream and exclusive-access obligations are those of fputc_unlocked.
#[no_mangle]
pub unsafe extern "C" fn putc_unlocked(character: c_int, stream: *mut StandardStream) -> c_int {
    unsafe { fputc_unlocked(character, stream) }
}

/// # Safety
/// stdout is open and the caller exclusively owns its access and initialization.
#[no_mangle]
pub unsafe extern "C" fn putchar_unlocked(character: c_int) -> c_int {
    unsafe { fputc_unlocked(character, ptr::addr_of_mut!(STDOUT_STREAM)) }
}

/// # Safety
/// `destination` is writable for size*count bytes, disjoint from FILE storage;
/// the caller exclusively owns the live stream, including initialization.
#[no_mangle]
pub unsafe extern "C" fn fread_unlocked(destination: *mut c_void, size: usize, count: usize, stream: *mut StandardStream) -> usize {
    unsafe { initialize_buffer(stream); fread_held(destination, size, count, stream) }
}

/// # Safety
/// `source` is readable for size*count bytes; the caller exclusively owns the
/// live stream, including initialization, until the transfer completes.
#[no_mangle]
pub unsafe extern "C" fn fwrite_unlocked(source: *const c_void, size: usize, count: usize, stream: *mut StandardStream) -> usize {
    unsafe { initialize_buffer(stream); fwrite_held(source, size, count, stream) }
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
        unsafe { if (*stream).orientation == 0 { (*stream).orientation = -1; } }
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
        let character = unsafe { read_byte_held(stream) };
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

    let mut length = 0;
    while unsafe { *source.add(length) } != 0 { length += 1; }
    if unsafe { fwrite_held(source.cast(), 1, length, stream) } == length { 0 } else { EOF }
}

/// # Safety
/// `source` must be a readable NUL-terminated string and stdout must be open.
#[no_mangle]
pub unsafe extern "C" fn puts(source: *const c_char) -> c_int {
    let _guard = unsafe { StreamGuard::acquire(ptr::addr_of_mut!(STDOUT_STREAM)) };
    if unsafe { fputs(source, ptr::addr_of_mut!(STDOUT_STREAM)) } == EOF {
        return EOF;
    }
    if unsafe { write_byte_held(ptr::addr_of_mut!(STDOUT_STREAM), b'\n') } == EOF {
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
    if !unsafe { is_selected_stream(stream) }
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
    if unsafe { flush_output_held(stream) } == EOF {
        return EOF;
    }
    // Source fseek leaves writing mode before attempting the backend seek;
    // a failed input seek, conversely, preserves its buffered read state.
    unsafe {
        if (*stream).direction == BufferDirection::Write { (*stream).direction = BufferDirection::Neutral; }
    }
    let result = unsafe {
        owned_stdio_backends::seek(stream, adjusted_offset, whence)
    };
    if result < 0 {
        return EOF;
    }
    unsafe {
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).write_position = (*stream).buffer;
        (*stream).flags &= !F_EOF;
        (*stream).direction = BufferDirection::Neutral;
    }
    0
}

/// # Safety
/// Stream arguments must be live FILE pointers; string and byte ranges must
/// be valid for the size specified by this C operation.
#[no_mangle]
pub unsafe extern "C" fn ftello(stream: *mut StandardStream) -> i64 {
    let _guard = unsafe { StreamGuard::acquire(stream) };
    if !unsafe { is_selected_stream(stream) } {
        unsafe { reject_stream() };
        return -1;
    }
    let raw_position = unsafe {
        owned_stdio_backends::seek(stream, 0,
            if (*stream).flags & F_APP != 0 && (*stream).write_position != (*stream).buffer { SEEK_END } else { SEEK_CUR })
    };
    let kernel_position = raw_position;
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
    if unsafe { is_selected_stream(stream) } {
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
        if mode == 2 { (*stream).capacity = 0; }
        else if !buffer.is_null() && size >= UNGET {
            (*stream).buffer = buffer.cast::<u8>().add(UNGET);
            (*stream).capacity = size - UNGET;
        }
        (*stream).line_buffered = mode == 1 && (*stream).capacity != 0;
        (*stream).flags |= F_SVB;
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).write_position = (*stream).buffer;
        (*stream).direction = BufferDirection::Neutral;
        0
    }
}
