//! Wide FILE operations from musl 1.2.6 (MIT), release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417: stdio/{fwide,fgetwc,
//! fputwc,fgetws,fputws,ungetwc,getwc,putwc,getwchar,putwchar}.c.
//! The opaque owner retains orientation and the C/POSIX versus C.UTF-8
//! snapshot. Shared locale codecs receive that value explicitly; a scoped
//! thread-locale guard also preserves musl's cookie-callback observations and
//! restores the caller's prior locale on every return. Byte buffering and
//! byte offsets remain in the same FILE; no parallel wide buffer or lock.
//! UTF-8 input state is local to one completed fgetwc, as in musl. ungetwc
//! pushes encoded bytes into the established eight-byte pushback reserve.

use super::*;
use super::super::locale_multibyte as codec;
use super::super::locale_objects::StreamLocaleGuard;
const WEOF: u32 = u32::MAX;

pub(super) unsafe fn orient(stream: *mut StandardStream, mode: c_int) -> c_int {
    unsafe {
        if mode != 0 {
            if (*stream).wide_locale.is_none() { (*stream).wide_locale = Some(codec::locale_ctype_is_utf8()); }
            if (*stream).orientation == 0 { (*stream).orientation = if mode > 0 { 1 } else { -1 }; }
        }
        (*stream).orientation as c_int
    }
}

// Musl's `src/stdio/fwide.c` object.
static_archive_member! { fwide_source {
    /// Query or establish a live FILE's orientation; nonzero mode captures CTYPE.
    /// # Safety
    /// The FILE is live and not concurrently closed or reopened.
    #[no_mangle]
    pub unsafe extern "C" fn fwide(stream: *mut StandardStream, mode: c_int) -> c_int {
        let _guard = unsafe { StreamGuard::acquire(stream) };
        unsafe { orient(stream, mode) }
    }
}}

pub(super) unsafe fn get_held(stream: *mut StandardStream) -> u32 {
    unsafe {
        if (*stream).orientation <= 0 { orient(stream, 1); }
        let utf8 = (*stream).wide_locale.unwrap();
        let _locale = StreamLocaleGuard::enter(utf8);
        let mut wide = 0;
        if (*stream).read_position != (*stream).read_end {
            let mut state = 0;
            let length = codec::decode_for_stream(&mut wide, (*stream).read_position.cast(),
                (*stream).read_end.offset_from((*stream).read_position) as usize, &mut state, codec::locale_ctype_is_utf8(), true);
            if length != usize::MAX {
                (*stream).read_position = (*stream).read_position.add(length.max(1));
                return wide as u32;
            }
        }
        let mut state = 0;
        let mut first = true;
        loop {
            let character = read_byte_held(stream);
            if character < 0 {
                if !first { mark_error(stream); errno::set_errno(84); }
                return WEOF;
            }
            let byte = character as u8;
            let length = codec::decode_for_stream(&mut wide, (&byte as *const u8).cast(), 1, &mut state, codec::locale_ctype_is_utf8(), false);
            if length == usize::MAX {
                if !first {
                    mark_error(stream);
                    (*stream).read_position = (*stream).read_position.sub(1);
                    *(*stream).read_position = byte;
                    (*stream).flags &= !F_EOF;
                }
                return WEOF;
            }
            first = false;
            if length != usize::MAX-1 { return wide as u32; }
        }
    }
}

pub(super) unsafe fn put_held(character: c_int, stream: *mut StandardStream) -> u32 {
    unsafe {
        if (*stream).orientation <= 0 { orient(stream, 1); }
        let _locale = StreamLocaleGuard::enter((*stream).wide_locale.unwrap());
        let result = if (character as u32) < 128 { write_byte_held(stream, character as u8) as u32 }
        else {
            let mut bytes = [0u8; 4];
            let length = codec::encode_for_locale(bytes.as_mut_ptr().cast(), character, codec::locale_ctype_is_utf8());
            if length == usize::MAX || fwrite_held(bytes.as_ptr().cast(), 1, length, stream) < length { WEOF }
            else { character as u32 }
        };
        if result == WEOF { mark_error(stream); }
        result
    }
}

// Musl's `src/stdio/fgetwc.c` object.
static_archive_member! { fgetwc_source {
    /// Read one wide character using the orientation's captured conversion locale.
    /// # Safety
    /// FILE is live, open for reading, and not concurrently destroyed.
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn fgetwc(stream: *mut StandardStream) -> u32 {
        let _guard = unsafe { StreamGuard::acquire(stream) };
        unsafe { __fgetwc_unlocked(stream) }
    }

    /// # Safety
    /// FILE is live and the caller holds its lock or otherwise excludes all access.
    /// Musl makes the public unlocked entries weak aliases of this strong body.
    #[no_mangle]
    pub unsafe extern "C" fn __fgetwc_unlocked(stream: *mut StandardStream) -> u32 {
        unsafe { initialize_buffer(stream); get_held(stream) }
    }

    core::arch::global_asm!(".weak fgetwc_unlocked", ".set fgetwc_unlocked, __fgetwc_unlocked", ".weak getwc_unlocked", ".set getwc_unlocked, __fgetwc_unlocked");
}}
// Musl's `src/stdio/getwc.c` object.
static_archive_member! { getwc_source {
    /// # Safety
    /// Same live, readable FILE contract as fgetwc.
    #[no_mangle]
    pub unsafe extern "C" fn getwc(stream: *mut StandardStream) -> u32 { unsafe { fgetwc(stream) } }
}}
// Musl's `src/stdio/getwchar.c` object.
static_archive_member! { getwchar_source {
    /// # Safety
    /// stdin remains live and readable for this operation.
    #[no_mangle]
    pub unsafe extern "C" fn getwchar() -> u32 { unsafe { fgetwc(stdin) } }

    core::arch::global_asm!(".weak getwchar_unlocked", ".set getwchar_unlocked, getwchar");
}}

// Musl's `src/stdio/fputwc.c` object.
static_archive_member! { fputwc_source {
    /// Write one wide character through the captured conversion locale.
    /// # Safety
    /// FILE is live, open for writing, and not concurrently destroyed.
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn fputwc(character: c_int, stream: *mut StandardStream) -> u32 {
        let _guard = unsafe { StreamGuard::acquire(stream) };
        unsafe { __fputwc_unlocked(character, stream) }
    }

    /// # Safety
    /// FILE is live and the caller holds its lock or otherwise excludes all access.
    /// Musl makes the public unlocked entries weak aliases of this strong body.
    #[no_mangle]
    pub unsafe extern "C" fn __fputwc_unlocked(character: c_int, stream: *mut StandardStream) -> u32 {
        unsafe { initialize_buffer(stream); put_held(character, stream) }
    }

    core::arch::global_asm!(".weak fputwc_unlocked", ".set fputwc_unlocked, __fputwc_unlocked", ".weak putwc_unlocked", ".set putwc_unlocked, __fputwc_unlocked");
}}
// Musl's `src/stdio/putwc.c` object.
static_archive_member! { putwc_source {
    /// # Safety
    /// Same live writable FILE contract as fputwc.
    #[no_mangle]
    pub unsafe extern "C" fn putwc(character: c_int, stream: *mut StandardStream) -> u32 { unsafe { fputwc(character, stream) } }
}}
// Musl's `src/stdio/putwchar.c` object.
static_archive_member! { putwchar_source {
    /// # Safety
    /// stdout remains live and writable for this operation.
    #[no_mangle]
    pub unsafe extern "C" fn putwchar(character: c_int) -> u32 { unsafe { fputwc(character, stdout) } }

    core::arch::global_asm!(".weak putwchar_unlocked", ".set putwchar_unlocked, putwchar");
}}

// Musl's `src/stdio/ungetwc.c` object.
static_archive_member! { ungetwc_source {
    /// Push a character's complete encoded byte sequence back onto a wide stream.
    /// # Safety
    /// FILE is live, readable and not concurrently destroyed. Character is WEOF
    /// or a wint_t value; unencodable values are diagnosed without insertion.
    #[no_mangle]
    pub unsafe extern "C" fn ungetwc(character: u32, stream: *mut StandardStream) -> u32 {
        unsafe {
            let _guard = StreamGuard::acquire(stream);
            if (*stream).orientation <= 0 { orient(stream, 1); }
            let _locale = StreamLocaleGuard::enter((*stream).wide_locale.unwrap());
            if !is_readable(stream) { mark_error(stream); return WEOF; }
            if !prepare_read(stream) || character == WEOF { return WEOF; }
            let mut bytes = [0u8; 4];
            let length = codec::encode_for_locale(bytes.as_mut_ptr().cast(), character as c_int, codec::locale_ctype_is_utf8());
            // musl compares addresses (`f->rpos < f->buf - UNGET + l`): after a
            // mid-stream setvbuf the unread region may lie in the previous buffer.
            if length == usize::MAX
                || ((*stream).read_position as usize) < (*stream).buffer.sub(UNGET) as usize + length { return WEOF; }
            (*stream).read_position = (*stream).read_position.sub(length);
            ptr::copy_nonoverlapping(bytes.as_ptr(), (*stream).read_position, length);
            (*stream).flags &= !F_EOF;
            character
        }
    }
}}

// Musl's `src/stdio/fgetws.c` object.
static_archive_member! { fgetws_source {
    /// Read a newline-terminated or capacity-bounded wide string.
    /// # Safety
    /// For positive count, destination has count writable wchar_t elements,
    /// disjoint from the live readable FILE and its storage.
    #[no_mangle]
    pub unsafe extern "C" fn fgetws(destination: *mut c_int, count: c_int, stream: *mut StandardStream) -> *mut c_int {
        unsafe {
            if count == 0 { return destination; }
            let _guard = StreamGuard::acquire(stream);
            let mut out = destination;
            let mut remaining = count-1;
            while remaining != 0 {
                let character = get_held(stream);
                if character == WEOF { break; }
                out.write(character as c_int); out = out.add(1);
                if character == b'\n' as u32 { break; }
                remaining -= 1;
            }
            out.write(0);
            if out == destination || (*stream).flags & F_ERR != 0 { ptr::null_mut() } else { destination }
        }
    }

    core::arch::global_asm!(".weak fgetws_unlocked", ".set fgetws_unlocked, fgetws");
}}
// Musl's `src/stdio/fputws.c` object.
static_archive_member! { fputws_source {
    /// Write a NUL-terminated wide string using source-sized byte chunks.
    /// # Safety
    /// Source remains readable through its terminator and disjoint from the live
    /// writable FILE and buffers until the call completes.
    #[no_mangle]
    pub unsafe extern "C" fn fputws(mut source: *const c_int, stream: *mut StandardStream) -> c_int {
        unsafe {
            let _guard = StreamGuard::acquire(stream);
            orient(stream, 1);
            let utf8 = (*stream).wide_locale.unwrap();
            let _locale = StreamLocaleGuard::enter(utf8);
            let mut bytes = [0u8; BUFSIZ];
            loop {
                let mut length = 0;
                let mut ended = false;
                while length < bytes.len() {
                    let character = source.read();
                    if character == 0 { ended = true; break; }
                    let mut encoded = [0u8; 4];
                    let count = codec::encode_for_locale(encoded.as_mut_ptr().cast(), character, codec::locale_ctype_is_utf8());
                    if count == usize::MAX { return -1; }
                    if count > bytes.len()-length { break; }
                    ptr::copy_nonoverlapping(encoded.as_ptr(), bytes.as_mut_ptr().add(length), count);
                    length += count; source = source.add(1);
                }
                if length != 0 && fwrite_held(bytes.as_ptr().cast(), 1, length, stream) < length { return -1; }
                if ended { return length as c_int; }
            }
        }
    }

    core::arch::global_asm!(".weak fputws_unlocked", ".set fputws_unlocked, fputws");
}}
