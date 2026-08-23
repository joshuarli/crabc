// string and memory compatibility exports.
//
// These interfaces are thin only where the existing primitive already owns
// the contract.  Operations with distinct state or overflow semantics remain
// implemented here so their ABI names do not hide a behavioral gap.

#[inline]
unsafe fn cabi_ascii_lower(byte: u8) -> u8 {
    if byte >= b'A' && byte <= b'Z' { byte + (b'a' - b'A') } else { byte }
}

#[no_mangle]
pub unsafe extern "C" fn bcopy(src: *const c_void, dst: *mut c_void, n: usize) {
    memmove(dst, src, n);
}

#[no_mangle]
pub unsafe extern "C" fn bzero(dst: *mut c_void, n: usize) {
    memset(dst, 0, n);
}

#[no_mangle]
pub unsafe extern "C" fn explicit_bzero(dst: *mut c_void, n: usize) {
    let bytes = dst as *mut u8;
    for i in 0..n {
        core::ptr::write_volatile(bytes.add(i), 0);
    }
}

#[no_mangle]
pub unsafe extern "C" fn index(s: *const c_char, c: c_int) -> *mut c_char {
    strchr(s as *const u8, c) as *mut c_char
}

#[no_mangle]
pub unsafe extern "C" fn rindex(s: *const c_char, c: c_int) -> *mut c_char {
    strrchr(s as *const u8, c) as *mut c_char
}

#[no_mangle]
pub unsafe extern "C" fn memccpy(
    dst: *mut c_void,
    src: *const c_void,
    c: c_int,
    n: usize,
) -> *mut c_void {
    let dst = dst as *mut u8;
    let src = src as *const u8;
    let target = c as u8;
    for i in 0..n {
        let byte = *src.add(i);
        *dst.add(i) = byte;
        if byte == target { return dst.add(i + 1) as *mut c_void; }
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn mempcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    memcpy(dst, src, n);
    (dst as *mut u8).add(n) as *mut c_void
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn stpcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    let mut out = dst as *mut u8;
    let mut input = src as *const u8;
    loop {
        let byte = *input;
        *out = byte;
        if byte == 0 { return out as *mut c_char; }
        out = out.add(1);
        input = input.add(1);
    }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn stpncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    let out = dst as *mut u8;
    let input = src as *const u8;
    let mut i = 0;
    while i < n && *input.add(i) != 0 {
        *out.add(i) = *input.add(i);
        i += 1;
    }
    if i == n { return out.add(n) as *mut c_char; }
    let terminator = i;
    while i < n {
        *out.add(i) = 0;
        i += 1;
    }
    out.add(terminator) as *mut c_char
}

#[no_mangle]
pub unsafe extern "C" fn strcasestr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    let needle = needle as *const u8;
    if *needle == 0 { return haystack as *mut c_char; }
    let mut candidate = haystack as *const u8;
    while *candidate != 0 {
        let mut left = candidate;
        let mut right = needle;
        while *right != 0 && *left != 0 && cabi_ascii_lower(*left) == cabi_ascii_lower(*right) {
            left = left.add(1);
            right = right.add(1);
        }
        if *right == 0 { return candidate as *mut c_char; }
        candidate = candidate.add(1);
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn strndup(src: *const c_char, n: usize) -> *mut c_char {
    let len = strnlen(src as *const u8, n);
    let Some(size) = len.checked_add(1) else {
        ERRNO = ENOMEM;
        return core::ptr::null_mut();
    };
    let dst = malloc(size) as *mut c_char;
    if dst.is_null() { return core::ptr::null_mut(); }
    core::ptr::copy_nonoverlapping(src, dst, len);
    *dst.add(len) = 0;
    dst
}

#[no_mangle]
pub unsafe extern "C" fn strsep(stringp: *mut *mut c_char, delim: *const c_char) -> *mut c_char {
    if stringp.is_null() || (*stringp).is_null() { return core::ptr::null_mut(); }
    let token = *stringp;
    let mut cursor = token as *mut u8;
    loop {
        let byte = *cursor;
        if byte == 0 {
            *stringp = core::ptr::null_mut();
            return token;
        }
        if !strchr(delim as *const u8, byte as c_int).is_null() {
            *cursor = 0;
            *stringp = cursor.add(1) as *mut c_char;
            return token;
        }
        cursor = cursor.add(1);
    }
}

#[no_mangle]
pub unsafe extern "C" fn strtok_r(
    string: *mut c_char,
    delim: *const c_char,
    saveptr: *mut *mut c_char,
) -> *mut c_char {
    if saveptr.is_null() { return core::ptr::null_mut(); }
    let mut cursor = if string.is_null() { *saveptr } else { string };
    if cursor.is_null() { return core::ptr::null_mut(); }
    while *cursor != 0 && !strchr(delim as *const u8, *cursor as u8 as c_int).is_null() {
        cursor = cursor.add(1);
    }
    if *cursor == 0 {
        *saveptr = cursor;
        return core::ptr::null_mut();
    }
    let token = cursor;
    while *cursor != 0 && strchr(delim as *const u8, *cursor as u8 as c_int).is_null() {
        cursor = cursor.add(1);
    }
    if *cursor != 0 {
        *cursor = 0;
        cursor = cursor.add(1);
    }
    *saveptr = cursor;
    token
}

#[no_mangle]
pub unsafe extern "C" fn reallocarray(ptr: *mut c_void, nmemb: usize, size: usize) -> *mut c_void {
    let Some(total) = nmemb.checked_mul(size) else {
        ERRNO = ENOMEM;
        return core::ptr::null_mut();
    };
    realloc(ptr, total)
}
