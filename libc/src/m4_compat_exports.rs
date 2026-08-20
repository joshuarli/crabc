// M4 glibc/musl compatibility spellings that have an existing behavioral
// implementation. Version and grouping parameters are ABI selectors used by
// callers of these historical names; Linux's current stat and number-parser
// behavior is the implementation behind every supported selector here.

#[no_mangle]
pub unsafe extern "C" fn __xstat(_version: c_int, path: *const c_char, buf: *mut Stat) -> c_int {
    stat(path, buf)
}

#[no_mangle]
pub unsafe extern "C" fn __lxstat(_version: c_int, path: *const c_char, buf: *mut Stat) -> c_int {
    lstat(path, buf)
}

#[no_mangle]
pub unsafe extern "C" fn __fxstat(_version: c_int, fd: c_int, buf: *mut Stat) -> c_int {
    fstat(fd, buf)
}

#[no_mangle]
pub unsafe extern "C" fn __fxstatat(
    _version: c_int,
    dirfd: c_int,
    path: *const c_char,
    buf: *mut Stat,
    flags: c_int,
) -> c_int {
    fstatat(dirfd, path, buf, flags)
}

#[no_mangle]
pub unsafe extern "C" fn __xmknod(
    _version: c_int,
    path: *const c_char,
    mode: mode_t,
    dev: c_ulong,
) -> c_int {
    mknod(path, mode, dev)
}

#[no_mangle]
pub unsafe extern "C" fn __xmknodat(
    _version: c_int,
    dirfd: c_int,
    path: *const c_char,
    mode: mode_t,
    dev: c_ulong,
) -> c_int {
    mknodat(dirfd, path, mode, dev)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __xpg_basename(path: *mut c_char) -> *mut c_char {
    basename(path)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __xpg_strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    strerror_r(errnum, buf, buflen)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtol_internal(
    text: *const c_char,
    end: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_long {
    strtol(text, end, base)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtoul_internal(
    text: *const c_char,
    end: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_ulong {
    strtoul(text, end, base)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtoll_internal(
    text: *const c_char,
    end: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_longlong {
    strtoll(text, end, base)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtoull_internal(
    text: *const c_char,
    end: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_ulonglong {
    strtoull(text, end, base)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtoimax_internal(
    text: *const c_char,
    end: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_long {
    strtol(text, end, base)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtoumax_internal(
    text: *const c_char,
    end: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_ulong {
    strtoul(text, end, base)
}
