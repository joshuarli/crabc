//! Closed owned FILE backends, translated from musl 1.2.6 (MIT), commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417: `src/stdio/fmemopen.c`
//! mread/mwrite/mseek, `open_memstream.c` ms_write/ms_seek, and
//! `fopencookie.c` cookieread/cookiewrite/cookieseek/cookieclose.
//! See compat/upstreams.toml for the fixed source/license pin.
//!
//! Backend state is part of the opaque FILE, never a public vtable. Caller
//! fmemopen buffers and cookie userdata remain borrowed. Null-buffer fmemopen
//! storage follows the FILE in its one allocation. Growing output is a
//! separate allocation published through caller pointers and is NOT freed
//! with the FILE. Registry insertion follows all initialization. Callback
//! dispatch copies function pointers and userdata before calling C: no Rust
//! reference into FILE or backend state survives an application callback.
//! Growing output preserves musl's distinction between the current position
//! published through sizep and the high-water length used by SEEK_END; an
//! overwrite does not truncate the old tail. Expanded storage is zero-filled.
//! Non-error short memory/cookie writes do not manufacture F_ERR, including
//! ms_write's realloc failure; fflush follows upstream output-state semantics.

use super::*;

#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum Backend { Descriptor, Fixed(Fixed), Growing(Growing), Cookie(Cookie) }
#[derive(Clone, Copy)]
pub(super) struct Fixed { position: usize, length: usize, size: usize, buffer: *mut u8, mode: u8 }
#[derive(Clone, Copy)]
pub(super) struct Growing {
    output: *mut *mut c_char, size: *mut usize, position: usize,
    buffer: *mut u8, length: usize, space: usize,
}
#[derive(Clone, Copy)]
pub(super) struct Cookie { data: *mut c_void, functions: CookieIoFunctions }

/// Exact installed x86 cookie_io_functions_t ABI; absent callbacks are null.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CookieIoFunctions {
    pub read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>,
    pub seek: Option<unsafe extern "C" fn(*mut c_void, *mut i64, c_int) -> c_int>,
    pub close: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

unsafe fn allocate(extra: usize, flags: u32) -> *mut StandardStream {
    unsafe {
        let Some(size) = core::mem::size_of::<StandardStream>().checked_add(extra) else {
            errno::set_errno(12); return ptr::null_mut();
        };
        let stream = malloc(size).cast::<StandardStream>();
        if !stream.is_null() { stream.write(StandardStream::new(-1, flags & !F_APP, BUFSIZ)); }
        stream
    }
}

/// Open a fixed-size byte memory stream.
/// # Safety
/// `mode` is NUL terminated. Non-null `buffer` remains valid for `size` bytes
/// through close and is writable for a writing mode. For w+, a non-null buffer
/// must provide at least one writable byte even when size is zero: pinned
/// musl unconditionally writes the initial NUL in this mode. Caller storage
/// is never freed; null storage is owned by FILE, including its zero-size sentinel.
#[no_mangle]
pub unsafe extern "C" fn fmemopen(buffer: *mut c_void, size: usize, mode: *const c_char) -> *mut StandardStream {
    unsafe {
        let Some((_, flags)) = open_mode(mode) else { errno::set_errno(EINVAL); return ptr::null_mut(); };
        if buffer.is_null() && size > isize::MAX as usize { errno::set_errno(12); return ptr::null_mut(); }
        // Keep a writable zero-size sentinel for musl's w+ initial NUL.
        let stream = allocate(if buffer.is_null() { size.max(1) } else { 0 }, flags);
        if stream.is_null() { return stream; }
        let data = if buffer.is_null() {
            let data = stream.cast::<u8>().add(core::mem::size_of::<StandardStream>());
            ptr::write_bytes(data, 0, size); data
        } else { buffer.cast() };
        let mut state = Fixed { position: 0, length: 0, size, buffer: data, mode: *mode as u8 };
        if state.mode == b'r' { state.length = size; }
        else if state.mode == b'a' {
            while state.length < size && *data.add(state.length) != 0 { state.length += 1; }
            state.position = state.length;
        } else if flags & F_NORD == 0 { *data = 0; }
        (*stream).backend = Backend::Fixed(state);
        publish_stream(stream)
    }
}

/// Open a growing byte output stream, publishing its caller-owned allocation.
/// # Safety
/// `output` and `size` are writable, non-overlapping pointer/size objects that
/// outlive the FILE. After successful flush/close the caller may inspect the
/// published bytes. Writes may realloc and invalidate an earlier pointer.
/// The caller frees the final allocation after close; FILE never frees it.
#[no_mangle]
pub unsafe extern "C" fn open_memstream(output: *mut *mut c_char, size: *mut usize) -> *mut StandardStream {
    unsafe {
        let stream = allocate(0, F_NORD);
        if stream.is_null() { return stream; }
        let buffer = malloc(1).cast::<u8>();
        if buffer.is_null() { free(stream.cast()); return ptr::null_mut(); }
        *buffer = 0; *output = buffer.cast(); *size = 0;
        (*stream).backend = Backend::Growing(Growing { output, size, position: 0, buffer, length: 0, space: 0 });
        publish_stream(stream)
    }
}

/// Open an application-cookie byte stream.
/// # Safety
/// `mode` is NUL terminated. Userdata and callback code remain valid until
/// the close callback completes. Read/write callbacks obey their buffer/count
/// contracts and return at most the requested count. Seek writes a valid
/// resulting offset. Callbacks may use other live streams but must not close,
/// reopen, or reconfigure this FILE during its active operation. Global flush
/// follows musl's registry-before-FILE lock order; callbacks invoked by a
/// global flush must not mutate that registry or recursively flush all FILEs.
#[no_mangle]
pub unsafe extern "C" fn fopencookie(data: *mut c_void, mode: *const c_char, functions: CookieIoFunctions) -> *mut StandardStream {
    unsafe {
        let Some((_, flags)) = open_mode(mode) else { errno::set_errno(EINVAL); return ptr::null_mut(); };
        let stream = allocate(0, flags);
        if stream.is_null() { return stream; }
        (*stream).backend = Backend::Cookie(Cookie { data, functions });
        publish_stream(stream)
    }
}

pub(super) unsafe fn read(stream: *mut StandardStream, destination: *mut u8, length: usize) -> usize {
    unsafe {
        match (*stream).backend {
            Backend::Fixed(mut state) => {
                let remaining = state.length.saturating_sub(state.position);
                let count = length.min(remaining);
                if length > remaining { (*stream).flags |= F_EOF; }
                ptr::copy_nonoverlapping(state.buffer.add(state.position), destination, count);
                state.position += count;
                let retained = (remaining-count).min((*stream).capacity);
                (*stream).read_position = (*stream).buffer;
                (*stream).read_end = (*stream).buffer.add(retained);
                ptr::copy_nonoverlapping(state.buffer.add(state.position), (*stream).buffer, retained);
                state.position += retained;
                (*stream).backend = Backend::Fixed(state);
                count
            }
            Backend::Cookie(cookie) => {
                let Some(read) = cookie.functions.read else {
                    mark_error(stream); return 0;
                };
                let buffered = ((*stream).capacity != 0) as usize;
                let direct = length-buffered;
                let mut count = 0;
                if direct != 0 {
                    let status = read(cookie.data, destination.cast(), direct);
                    if status <= 0 { read_failure(stream, status); return 0; }
                    count = status as usize;
                }
                if buffered == 0 || length-count > buffered { return count; }
                (*stream).read_position = (*stream).buffer;
                let status = read(cookie.data, (*stream).buffer.cast(), (*stream).capacity);
                if status <= 0 { read_failure(stream, status); return count; }
                (*stream).read_end = (*stream).buffer.add(status as usize);
                *destination.add(count) = *(*stream).read_position;
                (*stream).read_position = (*stream).read_position.add(1);
                count+1
            }
            _ => { mark_error(stream); 0 }
        }
    }
}

unsafe fn read_failure(stream: *mut StandardStream, status: isize) {
    unsafe {
        (*stream).flags |= if status == 0 { F_EOF } else { F_ERR };
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
    }
}

// Caller has handled pending FILE bytes. Memory/cookie backends deliberately
// preserve musl's non-error short-write behavior; only negative cookie writes
// invalidate output state. No callback runs under a Rust backend reference.
pub(super) unsafe fn write(stream: *mut StandardStream, source: *const u8, length: usize) -> usize {
    unsafe {
        match (*stream).backend {
            Backend::Fixed(mut state) => {
                if state.mode == b'a' { state.position = state.length; }
                let count = length.min(state.size-state.position);
                if count != 0 { ptr::copy_nonoverlapping(source, state.buffer.add(state.position), count); }
                state.position += count;
                if state.position > state.length {
                    state.length = state.position;
                    if state.length < state.size { *state.buffer.add(state.length) = 0; }
                    else if (*stream).flags & F_NORD != 0 && state.size != 0 { *state.buffer.add(state.size-1) = 0; }
                }
                (*stream).backend = Backend::Fixed(state);
                count
            }
            Backend::Growing(mut state) => {
                let Some(end) = state.position.checked_add(length) else { errno::set_errno(12); return 0; };
                if end >= state.space {
                    let Some(minimum) = end.checked_add(1) else { errno::set_errno(12); return 0; };
                    let Some(doubled) = state.space.checked_mul(2).and_then(|n| n.checked_add(1)) else { errno::set_errno(12); return 0; };
                    let space = doubled | minimum;
                    let buffer = realloc(state.buffer.cast(), space).cast::<u8>();
                    if buffer.is_null() { return 0; }
                    *state.output = buffer.cast();
                    ptr::write_bytes(buffer.add(state.space), 0, space-state.space);
                    state.buffer = buffer; state.space = space;
                }
                if length != 0 { ptr::copy_nonoverlapping(source, state.buffer.add(state.position), length); }
                state.position = end; state.length = state.length.max(end);
                *state.size = state.position;
                (*stream).backend = Backend::Growing(state);
                length
            }
            Backend::Cookie(cookie) => {
                let Some(write) = cookie.functions.write else { return length; };
                let count = write(cookie.data, source.cast(), length);
                if count < 0 { (*stream).write_failed = true; mark_error(stream); return 0; }
                count as usize
            }
            Backend::Descriptor => unreachable!(),
        }
    }
}

pub(super) unsafe fn ignores_writes(stream: *const StandardStream) -> bool {
    unsafe { matches!((*stream).backend, Backend::Cookie(Cookie { functions: CookieIoFunctions { write: None, .. }, .. })) }
}

pub(super) unsafe fn seek(stream: *mut StandardStream, offset: i64, whence: c_int) -> i64 {
    unsafe {
        if !(0..=2).contains(&whence) { errno::set_errno(EINVAL); return -1; }
        let (position, length, maximum) = match (*stream).backend {
            Backend::Descriptor => return c_off_status(raw_syscall::syscall3(8, (*stream).file_descriptor as i64, offset, whence as i64)),
            Backend::Cookie(cookie) => {
                let Some(seek) = cookie.functions.seek else { errno::set_errno(95); return -1; };
                let mut result = offset;
                let status = seek(cookie.data, &mut result, whence);
                return if status < 0 { status as i64 } else { result };
            }
            Backend::Fixed(state) => (state.position, state.length, state.size),
            Backend::Growing(state) => (state.position, state.length, isize::MAX as usize),
        };
        let base = [0, position, length][whence as usize];
        let Some(target) = (base as i64).checked_add(offset).filter(|n| *n >= 0 && *n as usize <= maximum) else {
            errno::set_errno(EINVAL); return -1;
        };
        match &mut (*stream).backend {
            Backend::Fixed(state) => state.position = target as usize,
            Backend::Growing(state) => state.position = target as usize,
            _ => unreachable!(),
        }
        target
    }
}

pub(super) unsafe fn close(stream: *mut StandardStream) -> c_int {
    unsafe {
        match (*stream).backend {
            Backend::Descriptor => c_status(raw_syscall::syscall1(3, (*stream).file_descriptor as i64)),
            Backend::Cookie(cookie) => cookie.functions.close.map_or(0, |close| close(cookie.data)),
            _ => 0,
        }
    }
}
