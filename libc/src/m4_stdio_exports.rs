// M4 stdio compatibility exports.
//
// The core FILE operations are already implemented in lib.rs and are
// intentionally lock-free for this libc's current single-process FILE model.
// These entry points provide the musl unlocked spellings as real ABI wrappers
// over those operations.  The ISO C99 scanning aliases are limited to the
// va_list forms, whose calling convention can be forwarded without rebuilding
// a variadic argument list.

// The internal glibc-compatible slow path is entered when a caller's FILE
// read buffer is empty.  fgetc owns the same refill, EOF, and errno behavior
// in this libc, so forwarding retains the observable contract.
core::arch::global_asm!(".protected __uflow");

#[no_mangle]
pub unsafe extern "C" fn __uflow(stream: *mut FILE) -> c_int {
    fgetc(stream)
}

// The current FILE implementation is process-local and its existing
// flockfile/funlockfile pair records recursive ownership in lockcount.  There
// is no thread-id lock owner to distinguish in this libc yet, so a positive
// lockcount represents a lock held by this process and remains recursively
// acquirable, matching the observable success path of musl's ftrylockfile.
#[no_mangle]
pub unsafe extern "C" fn ftrylockfile(stream: *mut FILE) -> c_int {
    if stream.is_null() {
        return -1;
    }
    if (*stream).lockcount == c_long::MAX {
        return -1;
    }
    (*stream).lockcount += 1;
    0
}

#[no_mangle]
pub unsafe extern "C" fn setlinebuf(stream: *mut FILE) {
    setvbuf(stream, core::ptr::null_mut(), _IOLBF, 0);
    // musl does not manufacture a buffer when setlinebuf follows an
    // unbuffered configuration; in that case the stream remains effectively
    // unbuffered and __flbf reports false.
    if (*stream).buf_size == 0 {
        (*stream).lbf = -1;
    }
}

// BSD/GNU fgetln returns the line including its delimiter and stores the
// length separately.  A line already available in FILE's read buffer can be
// returned in place; otherwise getline grows FILE::getln_buf, which remains
// owned by the stream and is replaced on a later call when necessary.
#[no_mangle]
pub unsafe extern "C" fn fgetln(stream: *mut FILE, length: *mut usize) -> *mut c_char {
    let mut result: *mut c_char = core::ptr::null_mut();

    // Unlike musl's pushback-aware FILE buffer, this implementation keeps
    // ungotten bytes in a separate stack.  Do not inspect rpos directly while
    // one is pending: getline must consume that logical byte first.
    if (*stream).ungotten_count == 0
        && !(*stream).rpos.is_null()
        && !(*stream).rend.is_null()
        && (*stream).rpos <= (*stream).rend
    {
        let available = (*stream).rend as usize - (*stream).rpos as usize;
        let newline = memchr((*stream).rpos, b'\n' as c_int, available);
        if !newline.is_null() {
            let end = newline.add(1);
            *length = end as usize - (*stream).rpos as usize;
            result = (*stream).rpos as *mut c_char;
            (*stream).rpos = end;
            return result;
        }
    }

    let mut capacity = 0usize;
    let read = getline(
        &raw mut (*stream).getln_buf,
        &raw mut capacity,
        stream,
    );
    if read > 0 {
        *length = read as usize;
        result = (*stream).getln_buf;
    }
    result
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fgetc_unlocked(stream: *mut FILE) -> c_int {
    fgetc(stream)
}

#[no_mangle]
pub unsafe extern "C" fn getc_unlocked(stream: *mut FILE) -> c_int {
    fgetc(stream)
}

#[no_mangle]
pub unsafe extern "C" fn getchar_unlocked() -> c_int {
    fgetc(stdin)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fputc_unlocked(c: c_int, stream: *mut FILE) -> c_int {
    fputc(c, stream)
}

#[no_mangle]
pub unsafe extern "C" fn putc_unlocked(c: c_int, stream: *mut FILE) -> c_int {
    fputc(c, stream)
}

#[no_mangle]
pub unsafe extern "C" fn putchar_unlocked(c: c_int) -> c_int {
    fputc(c, stdout)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn feof_unlocked(stream: *mut FILE) -> c_int {
    feof(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn ferror_unlocked(stream: *mut FILE) -> c_int {
    ferror(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn clearerr_unlocked(stream: *mut FILE) {
    clearerr(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fgets_unlocked(
    buf: *mut c_char,
    size: c_int,
    stream: *mut FILE,
) -> *mut c_char {
    fgets(buf, size, stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fputs_unlocked(buf: *const c_char, stream: *mut FILE) -> c_int {
    fputs(buf, stream)
}

// glibc-compatible spellings are weak musl aliases of the same operations.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _IO_feof_unlocked(stream: *mut FILE) -> c_int {
    feof(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _IO_ferror_unlocked(stream: *mut FILE) -> c_int {
    ferror(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _IO_getc(stream: *mut FILE) -> c_int {
    fgetc(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _IO_getc_unlocked(stream: *mut FILE) -> c_int {
    fgetc(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _IO_putc(c: c_int, stream: *mut FILE) -> c_int {
    fputc(c, stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _IO_putc_unlocked(c: c_int, stream: *mut FILE) -> c_int {
    fputc(c, stream)
}

// musl exposes these as weak aliases to the ordinary scanner entry points.
// The variadic entry points must keep their ABI-owned va_list intact;
// rebuilding one here would not preserve AArch64 register-save state. This is
// the same forwarding pattern used by the ordinary scanners.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_fscanf(
    stream: *mut FILE,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    vfscanf_inner(stream, fmt, &mut args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_scanf(fmt: *const c_char, args: ...) -> c_int {
    vfscanf(stdin, fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_sscanf(
    buf: *const c_char,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    vsscanf_inner(buf as *const u8, fmt, &mut args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_fwscanf(
    stream: *mut FILE,
    fmt: *const wchar_t,
    args: ...
) -> c_int {
    vfwscanf(stream, fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_wscanf(fmt: *const wchar_t, args: ...) -> c_int {
    vfwscanf(stdin, fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_swscanf(
    buf: *const wchar_t,
    fmt: *const wchar_t,
    args: ...
) -> c_int {
    vswscanf(buf, fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_vfscanf(
    stream: *mut FILE,
    fmt: *const c_char,
    args: VaList,
) -> c_int {
    vfscanf(stream, fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_vscanf(fmt: *const c_char, args: VaList) -> c_int {
    vscanf(fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_vsscanf(
    buf: *const c_char,
    fmt: *const c_char,
    args: VaList,
) -> c_int {
    vsscanf(buf, fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_vfwscanf(
    stream: *mut FILE,
    fmt: *const wchar_t,
    args: VaList,
) -> c_int {
    vfwscanf(stream, fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_vwscanf(fmt: *const wchar_t, args: VaList) -> c_int {
    vwscanf(fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __isoc99_vswscanf(
    buf: *const wchar_t,
    fmt: *const wchar_t,
    args: VaList,
) -> c_int {
    vswscanf(buf, fmt, args)
}

include!("m4_stdio_extensions_exports.rs");
