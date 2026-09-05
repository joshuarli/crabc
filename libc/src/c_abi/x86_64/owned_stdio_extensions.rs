//! FILE extension and compatibility entry points from musl 1.2.6 (MIT),
//! release 9fa28ece75d8a2191de7c5bb53bed224c5947417. Source mapping:
//! stdio/{ext,ext2}.c -> direct exclusive-access state operations;
//! fgetln.c -> borrowed buffered line or FILE-owned reallocating line storage;
//! gets/getw/putw/setbuf/setbuffer/setlinebuf.c -> the matching wrappers below.
//! __uflow/__overflow.c -> the held byte admission helpers, with their original
//! internal exclusive-access and exhausted-input preconditions.
//! The unlocked aliases intentionally retain the source functions' locking,
//! as musl's weak aliases do. These do not replace the already lock-free byte
//! and block entry points. __fsetlocking is musl's no-op, not an alternate lock
//! implementation. No extension owns a second registry or buffering engine.

use super::*;

/// # Safety
/// The caller exclusively accesses a live FILE, including its configuration.
#[no_mangle]
pub unsafe extern "C" fn __fbufsize(stream: *mut StandardStream) -> usize { unsafe { (*stream).capacity } }
/// # Safety
/// The caller exclusively accesses a live FILE, including its configuration.
#[no_mangle]
pub unsafe extern "C" fn __flbf(stream: *mut StandardStream) -> c_int {
    unsafe { (*stream).line_buffered as c_int }
}
/// # Safety
/// The caller exclusively accesses a live FILE.
#[no_mangle]
pub unsafe extern "C" fn __freading(stream: *mut StandardStream) -> c_int {
    unsafe { ((*stream).flags & F_NOWR != 0 || (*stream).direction == BufferDirection::Read) as c_int }
}
/// # Safety
/// The caller exclusively accesses a live FILE.
#[no_mangle]
pub unsafe extern "C" fn __fwriting(stream: *mut StandardStream) -> c_int {
    unsafe { ((*stream).flags & F_NORD != 0 || (*stream).direction == BufferDirection::Write) as c_int }
}
/// # Safety
/// The caller exclusively accesses a live FILE.
#[no_mangle]
pub unsafe extern "C" fn __freadable(stream: *mut StandardStream) -> c_int { unsafe { is_readable(stream) as c_int } }
/// # Safety
/// The caller exclusively accesses a live FILE.
#[no_mangle]
pub unsafe extern "C" fn __fwritable(stream: *mut StandardStream) -> c_int { unsafe { is_writable(stream) as c_int } }
/// # Safety
/// The caller exclusively accesses a live FILE and its buffer state.
#[no_mangle]
pub unsafe extern "C" fn __fpending(stream: *mut StandardStream) -> usize {
    unsafe { if (*stream).direction == BufferDirection::Write { (*stream).write_position.offset_from((*stream).buffer) as usize } else { 0 } }
}
/// # Safety
/// The caller exclusively accesses a live FILE and its buffer state.
#[no_mangle]
pub unsafe extern "C" fn __freadahead(stream: *mut StandardStream) -> usize {
    unsafe { if (*stream).direction == BufferDirection::Read { (*stream).read_end.offset_from((*stream).read_position) as usize } else { 0 } }
}
/// Return a borrowed view of unread bytes without advancing the stream.
/// # Safety
/// The caller exclusively accesses a live FILE. `size` points to writable
/// usize storage, disjoint from FILE buffering. A returned non-null pointer is
/// readable for the published length, is never caller-owned, and remains valid
/// only until the next operation that changes or destroys this stream/buffer.
/// If no bytes are available, return null without modifying `size`.
#[no_mangle]
pub unsafe extern "C" fn __freadptr(stream: *mut StandardStream, size: *mut usize) -> *const c_char {
    unsafe {
        if (*stream).read_position == (*stream).read_end { return ptr::null(); }
        *size = (*stream).read_end.offset_from((*stream).read_position) as usize;
        (*stream).read_position.cast()
    }
}
/// Advance a previously inspected unread buffer without refilling it.
/// # Safety
/// The caller exclusively accesses the live FILE. `count` is no larger than
/// its current unread byte count, and a valid read buffer is active. No other
/// FILE operation may intervene between obtaining the view and advancing it.
#[no_mangle]
pub unsafe extern "C" fn __freadptrinc(stream: *mut StandardStream, count: usize) {
    unsafe { (*stream).read_position = (*stream).read_position.add(count); }
}
/// Discard buffered input and output without a seek or backend callback.
/// # Safety
/// The caller exclusively accesses a live FILE and all of its borrowed views.
#[no_mangle]
pub unsafe extern "C" fn __fpurge(stream: *mut StandardStream) -> c_int {
    unsafe {
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).write_position = (*stream).buffer;
        (*stream).direction = BufferDirection::Neutral;
        0
    }
}
/// # Safety
/// The caller exclusively accesses a live FILE and its indicators.
#[no_mangle]
pub unsafe extern "C" fn __fseterr(stream: *mut StandardStream) { unsafe { mark_error(stream); } }
/// Musl accepts every request without changing the FILE locking contract.
/// # Safety
/// `stream` is a live FILE; callers must continue to obey ordinary FILE locks.
#[no_mangle]
pub unsafe extern "C" fn __fsetlocking(_stream: *mut StandardStream, _request: c_int) -> c_int { 0 }
/// # Safety
/// Open streams are live and not concurrently destroyed during this operation.
#[no_mangle]
pub unsafe extern "C" fn _flushlbf() { unsafe { fflush(ptr::null_mut()); } }

/// Read a complete line, using a borrowed FILE buffer when possible.
/// # Safety
/// `stream` is live and readable; `length` is writable usize storage disjoint
/// from FILE state. The result is readable for the published length, need not
/// be NUL-terminated, must not be freed, and is invalidated by later operations
/// on the FILE (including close). Concurrent users must not outlive the view.
#[no_mangle]
pub unsafe extern "C" fn fgetln(stream: *mut StandardStream, length: *mut usize) -> *mut c_char {
    unsafe {
        let _guard = StreamGuard::acquire(stream);
        ungetc(read_byte_held(stream), stream);
        let mut end = (*stream).read_position;
        while end != (*stream).read_end {
            let byte = *end; end = end.add(1);
            if byte == b'\n' {
                let result = (*stream).read_position;
                *length = end.offset_from(result) as usize;
                (*stream).read_position = end;
                return result.cast();
            }
        }
        // fgetln.c passes a fresh zero capacity even when its FILE-owned
        // allocation exists. getline's realloc and failure ownership remain
        // authoritative; no borrowed Rust reference survives that callback.
        let mut capacity = 0;
        let count = getline(ptr::addr_of_mut!((*stream).getln_buffer), &mut capacity, stream);
        if count > 0 { *length = count as usize; (*stream).getln_buffer } else { ptr::null_mut() }
    }
}

/// Historical unbounded line input retained for the frozen C ABI only.
/// # Safety
/// stdin is live/readable. `destination` is writable for the entire next input
/// line plus its terminating NUL; there is no bound argument and the caller
/// must establish this externally. Its storage does not overlap FILE state.
#[no_mangle]
pub unsafe extern "C" fn gets(destination: *mut c_char) -> *mut c_char {
    unsafe {
        let stream = stdin;
        let _guard = StreamGuard::acquire(stream);
        let mut count = 0;
        let last = loop {
            let byte = read_byte_held(stream);
            if byte < 0 || byte == b'\n' as c_int { break byte; }
            *destination.add(count) = byte as c_char; count += 1;
        };
        *destination.add(count) = 0;
        if last != b'\n' as c_int && ((*stream).flags & F_EOF == 0 || count == 0) { ptr::null_mut() } else { destination }
    }
}
/// Read one native-endian C int; EOF may also be a successfully read -1.
/// # Safety
/// The FILE is live/readable and is not concurrently destroyed.
#[no_mangle]
pub unsafe extern "C" fn getw(stream: *mut StandardStream) -> c_int {
    unsafe { let mut value = 0; if fread((&mut value as *mut c_int).cast(), core::mem::size_of::<c_int>(), 1, stream) == 1 { value } else { EOF } }
}
/// # Safety
/// The FILE is live/writable and is not concurrently destroyed.
#[no_mangle]
pub unsafe extern "C" fn putw(value: c_int, stream: *mut StandardStream) -> c_int {
    unsafe { fwrite((&value as *const c_int).cast(), core::mem::size_of::<c_int>(), 1, stream) as c_int - 1 }
}
/// # Safety
/// Configure the live FILE before I/O. Non-null buffer has BUFSIZ (1024)
/// writable bytes retained until close or the next permitted configuration.
#[no_mangle]
pub unsafe extern "C" fn setbuf(stream: *mut StandardStream, buffer: *mut c_char) {
    unsafe { setvbuf(stream, buffer, if buffer.is_null() { 2 } else { 0 }, BUFSIZ); }
}
/// # Safety
/// Configure the live FILE before I/O. Non-null buffer has `size` writable
/// bytes retained until close or the next permitted configuration.
#[no_mangle]
pub unsafe extern "C" fn setbuffer(stream: *mut StandardStream, buffer: *mut c_char, size: usize) {
    unsafe { setvbuf(stream, buffer, if buffer.is_null() { 2 } else { 0 }, size); }
}
/// # Safety
/// Configure a live FILE before any I/O on it.
#[no_mangle]
pub unsafe extern "C" fn setlinebuf(stream: *mut StandardStream) {
    unsafe { setvbuf(stream, ptr::null_mut(), 1, 0); }
}

/// Internal exhausted-input byte boundary from musl __uflow.c.
/// # Safety
/// The caller exclusively owns the live readable FILE, including lazy buffer
/// initialization, and there are no unread buffered bytes on entry.
#[no_mangle]
pub unsafe extern "C" fn __uflow(stream: *mut StandardStream) -> c_int {
    unsafe { initialize_buffer(stream); read_byte_held(stream) }
}
/// Internal output boundary from musl __overflow.c. The int converts to an
/// unsigned byte, including EOF; this is not an EOF-as-flush entry point.
/// # Safety
/// The caller exclusively owns the live writable FILE, including lazy buffer
/// initialization, and no overlapping borrowed view is used during output.
#[no_mangle]
pub unsafe extern "C" fn __overflow(stream: *mut StandardStream, byte: c_int) -> c_int {
    unsafe { initialize_buffer(stream); write_byte_held(stream, byte as u8) }
}

core::arch::global_asm!(
    ".weak fpurge", ".set fpurge, __fpurge",
    ".weak fflush_unlocked", ".set fflush_unlocked, fflush",
    ".weak fileno_unlocked", ".set fileno_unlocked, fileno",
    ".weak fgets_unlocked", ".set fgets_unlocked, fgets",
    ".weak fputs_unlocked", ".set fputs_unlocked, fputs",
    ".weak clearerr_unlocked", ".set clearerr_unlocked, clearerr",
    ".weak feof_unlocked", ".set feof_unlocked, feof",
    ".weak ferror_unlocked", ".set ferror_unlocked, ferror",
    ".weak _IO_feof_unlocked", ".set _IO_feof_unlocked, feof",
    ".weak _IO_ferror_unlocked", ".set _IO_ferror_unlocked, ferror",
    ".weak _IO_getc", ".set _IO_getc, getc",
    ".weak _IO_putc", ".set _IO_putc, putc",
    ".weak _IO_getc_unlocked", ".set _IO_getc_unlocked, getc_unlocked",
    ".weak _IO_putc_unlocked", ".set _IO_putc_unlocked, putc_unlocked"
);
