// Shadow password database access.  Every successful result is backed by the
// source line read from /etc/shadow; no synthetic account is returned when
// the administrator's file is absent or unreadable.  The non-reentrant APIs
// use process-global storage, while getspnam_r copies both strings into the
// caller's buffer and reports ERANGE without publishing a partial result.

#[repr(C)]
pub struct CabiShadow {
    pub sp_namp: *mut c_char,
    pub sp_pwdp: *mut c_char,
    pub sp_lstchg: c_long,
    pub sp_min: c_long,
    pub sp_max: c_long,
    pub sp_warn: c_long,
    pub sp_inact: c_long,
    pub sp_expire: c_long,
    pub sp_flag: c_ulong,
}

const CABI_SHADOW_PATH: &[u8] = b"/etc/shadow\0";
const CABI_SHADOW_MODE: &[u8] = b"rbe\0";
// Keep the lock file separate from the shadow data stream.  Password-changing
// tools coordinate through this traditional path, and the descriptor also
// keeps the POSIX record lock alive for the lifetime of lckpwdf's ownership.
const CABI_SHADOW_LOCK_PATH: &[u8] = b"/etc/.pwd.lock\0";

// -1 means unlocked; -2 is a brief acquisition/release transition.  The
// sentinel prevents another thread in this process from observing a record
// lock (which is process-scoped on Linux) and accidentally releasing it.
static CABI_SHADOW_LOCK_FD: AtomicI32 = AtomicI32::new(-1);

static mut CABI_SHADOW_FILE: *mut FILE = core::ptr::null_mut();
static mut CABI_SHADOW_LINE: *mut c_char = core::ptr::null_mut();
static mut CABI_SHADOW_LINE_SIZE: usize = 0;
static mut CABI_SHADOW_RESULT: CabiShadow = CabiShadow {
    sp_namp: core::ptr::null_mut(),
    sp_pwdp: core::ptr::null_mut(),
    sp_lstchg: 0,
    sp_min: 0,
    sp_max: 0,
    sp_warn: 0,
    sp_inact: 0,
    sp_expire: 0,
    sp_flag: 0,
};

static mut CABI_SHADOW_LOOKUP_LINE: *mut c_char = core::ptr::null_mut();
static mut CABI_SHADOW_LOOKUP_LINE_SIZE: usize = 0;
static mut CABI_SHADOW_LOOKUP_RESULT: CabiShadow = CabiShadow {
    sp_namp: core::ptr::null_mut(),
    sp_pwdp: core::ptr::null_mut(),
    sp_lstchg: 0,
    sp_min: 0,
    sp_max: 0,
    sp_warn: 0,
    sp_inact: 0,
    sp_expire: 0,
    sp_flag: 0,
};

static mut CABI_FGETSPENT_LINE: *mut c_char = core::ptr::null_mut();
static mut CABI_FGETSPENT_LINE_SIZE: usize = 0;
static mut CABI_FGETSPENT_RESULT: CabiShadow = CabiShadow {
    sp_namp: core::ptr::null_mut(),
    sp_pwdp: core::ptr::null_mut(),
    sp_lstchg: 0,
    sp_min: 0,
    sp_max: 0,
    sp_warn: 0,
    sp_inact: 0,
    sp_expire: 0,
    sp_flag: 0,
};

#[inline]
unsafe fn shadow_empty() -> CabiShadow {
    CabiShadow {
        sp_namp: core::ptr::null_mut(),
        sp_pwdp: core::ptr::null_mut(),
        sp_lstchg: 0,
        sp_min: 0,
        sp_max: 0,
        sp_warn: 0,
        sp_inact: 0,
        sp_expire: 0,
        sp_flag: 0,
    }
}

// An empty field denotes -1 in the shadow format.  Accept an optional sign
// for the date fields because they are signed long values, but reject a
// value outside the target C long range rather than wrapping it.
unsafe fn shadow_parse_signed(field: *const c_char, value: *mut c_long) -> bool {
    if field.is_null() || value.is_null() {
        return false;
    }
    if *field == 0 {
        *value = -1;
        return true;
    }

    let mut cursor = field;
    let mut negative = false;
    if *cursor as u8 == b'+' || *cursor as u8 == b'-' {
        negative = *cursor as u8 == b'-';
        cursor = cursor.add(1);
    }
    if *cursor == 0 {
        return false;
    }

    let magnitude_limit = if negative {
        (c_long::MAX as i128) + 1
    } else {
        c_long::MAX as i128
    };
    let mut magnitude = 0i128;
    let mut digits = 0usize;
    loop {
        let byte = *cursor as u8;
        if byte == 0 {
            break;
        }
        if byte < b'0' || byte > b'9' {
            return false;
        }
        magnitude = match magnitude
            .checked_mul(10)
            .and_then(|number| number.checked_add((byte - b'0') as i128))
        {
            Some(number) if number <= magnitude_limit => number,
            _ => return false,
        };
        digits += 1;
        cursor = cursor.add(1);
    }
    if digits == 0 {
        return false;
    }
    let signed = if negative { -magnitude } else { magnitude };
    *value = signed as c_long;
    true
}

// sp_flag is unsigned, but an empty value has the same sentinel meaning as
// the signed fields.  Negative values are accepted as two's-complement
// representations for compatibility with parsers that use strtol first.
unsafe fn shadow_parse_flag(field: *const c_char, value: *mut c_ulong) -> bool {
    if field.is_null() || value.is_null() {
        return false;
    }
    if *field == 0 {
        *value = c_ulong::MAX;
        return true;
    }

    if *field as u8 == b'-' {
        let mut signed = 0 as c_long;
        if !shadow_parse_signed(field, &mut signed) {
            return false;
        }
        *value = signed as c_ulong;
        return true;
    }

    let mut cursor = field;
    if *cursor as u8 == b'+' {
        cursor = cursor.add(1);
    }
    if *cursor == 0 {
        return false;
    }
    let mut number = 0u128;
    let mut digits = 0usize;
    let limit = c_ulong::MAX as u128;
    loop {
        let byte = *cursor as u8;
        if byte == 0 {
            break;
        }
        if byte < b'0' || byte > b'9' {
            return false;
        }
        number = match number
            .checked_mul(10)
            .and_then(|number| number.checked_add((byte - b'0') as u128))
        {
            Some(number) if number <= limit => number,
            _ => return false,
        };
        digits += 1;
        cursor = cursor.add(1);
    }
    if digits == 0 {
        return false;
    }
    *value = number as c_ulong;
    true
}

// Split one line in place and populate all nine fields.  getline's returned
// length excludes its terminating NUL; a final line without a newline is
// accepted, which is useful for hand-maintained shadow files.
unsafe fn shadow_parse_line(line: *mut c_char, length: usize, shadow: *mut CabiShadow) -> bool {
    if line.is_null() || shadow.is_null() || length == 0 {
        return false;
    }
    let mut content_len = length;
    if *line.add(content_len - 1) as u8 == b'\n' {
        content_len -= 1;
        *line.add(content_len) = 0;
    }
    if content_len == 0 {
        return false;
    }

    let mut fields = [core::ptr::null_mut(); 9];
    let mut cursor = line;
    let end = line.add(content_len);
    let mut index = 0usize;
    while index < 8 {
        let mut separator = cursor;
        while separator < end && *separator as u8 != b':' {
            separator = separator.add(1);
        }
        if separator == end {
            return false;
        }
        *separator = 0;
        fields[index] = cursor;
        cursor = separator.add(1);
        index += 1;
    }
    fields[8] = cursor;

    let mut dates = [0 as c_long; 6];
    let mut date_index = 0usize;
    while date_index < dates.len() {
        if !shadow_parse_signed(fields[date_index + 2], &mut dates[date_index]) {
            return false;
        }
        date_index += 1;
    }
    let mut flag = 0 as c_ulong;
    if !shadow_parse_flag(fields[8], &mut flag) {
        return false;
    }

    (*shadow).sp_namp = fields[0];
    (*shadow).sp_pwdp = fields[1];
    (*shadow).sp_lstchg = dates[0];
    (*shadow).sp_min = dates[1];
    (*shadow).sp_max = dates[2];
    (*shadow).sp_warn = dates[3];
    (*shadow).sp_inact = dates[4];
    (*shadow).sp_expire = dates[5];
    (*shadow).sp_flag = flag;
    true
}

// Return 1 for a valid record, 0 at EOF, and -1 for an I/O error.  Invalid
// records are skipped while enumerating, matching the passwd/group helpers.
unsafe fn shadow_next(
    file: *mut FILE,
    line: *mut *mut c_char,
    line_size: *mut usize,
    shadow: *mut CabiShadow,
) -> c_int {
    loop {
        let length = getline(line, line_size, file);
        if length < 0 {
            if ferror(file) != 0 {
                if ERRNO == 0 {
                    ERRNO = EIO_VAL;
                }
                return -1;
            }
            free(*line as *mut c_void);
            *line = core::ptr::null_mut();
            *line_size = 0;
            return 0;
        }
        if shadow_parse_line(*line, length as usize, shadow) {
            return 1;
        }
    }
}

unsafe fn shadow_open() -> *mut FILE {
    fopen(
        CABI_SHADOW_PATH.as_ptr() as *const c_char,
        CABI_SHADOW_MODE.as_ptr() as *const c_char,
    )
}

unsafe fn shadow_name_matches(name: *const c_char, record: *const c_char) -> bool {
    !name.is_null() && !record.is_null() && strcmp(name as *const u8, record as *const u8) == 0
}

unsafe fn shadow_scan_name(
    name: *const c_char,
    file: *mut FILE,
    line: *mut *mut c_char,
    line_size: *mut usize,
    shadow: *mut CabiShadow,
) -> c_int {
    loop {
        let status = shadow_next(file, line, line_size, shadow);
        if status <= 0 {
            return status;
        }
        if shadow_name_matches(name, (*shadow).sp_namp) {
            return 1;
        }
    }
}

unsafe fn shadow_copy_result(
    source: *const CabiShadow,
    destination: *mut CabiShadow,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiShadow,
) -> c_int {
    *result = core::ptr::null_mut();
    if source.is_null()
        || destination.is_null()
        || (*source).sp_namp.is_null()
        || (*source).sp_pwdp.is_null()
    {
        return EIO_VAL;
    }
    let name_len = match strlen((*source).sp_namp).checked_add(1) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let password_len = match strlen((*source).sp_pwdp).checked_add(1) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let required = match name_len.checked_add(password_len) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    if buffer.is_null() || required > buffer_size {
        return ERANGE_VAL;
    }

    (*destination).sp_namp = buffer;
    core::ptr::copy_nonoverlapping(
        (*source).sp_namp as *const u8,
        buffer as *mut u8,
        name_len,
    );
    (*destination).sp_pwdp = buffer.add(name_len);
    core::ptr::copy_nonoverlapping(
        (*source).sp_pwdp as *const u8,
        (*destination).sp_pwdp as *mut u8,
        password_len,
    );
    (*destination).sp_lstchg = (*source).sp_lstchg;
    (*destination).sp_min = (*source).sp_min;
    (*destination).sp_max = (*source).sp_max;
    (*destination).sp_warn = (*source).sp_warn;
    (*destination).sp_inact = (*source).sp_inact;
    (*destination).sp_expire = (*source).sp_expire;
    (*destination).sp_flag = (*source).sp_flag;
    *result = destination;
    0
}

unsafe fn shadow_reentrant(
    name: *const c_char,
    shadow: *mut CabiShadow,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiShadow,
) -> c_int {
    if name.is_null() || shadow.is_null() || result.is_null() || (buffer.is_null() && buffer_size != 0) {
        if !result.is_null() {
            *result = core::ptr::null_mut();
        }
        ERRNO = EINVAL;
        return EINVAL;
    }
    *result = core::ptr::null_mut();
    let original_errno = ERRNO;
    let file = shadow_open();
    if file.is_null() {
        return ERRNO;
    }
    ERRNO = 0;
    let mut line = core::ptr::null_mut();
    let mut line_size = 0usize;
    let mut parsed = shadow_empty();
    let status = shadow_scan_name(name, file, &mut line, &mut line_size, &mut parsed);
    let scan_errno = ERRNO;
    let result_code = if status > 0 {
        shadow_copy_result(&parsed, shadow, buffer, buffer_size, result)
    } else if status < 0 {
        if scan_errno == 0 { EIO_VAL } else { scan_errno }
    } else {
        0
    };
    let _ = fclose(file);
    free(line as *mut c_void);
    if result_code == 0 && status >= 0 {
        ERRNO = original_errno;
    } else if result_code != 0 {
        ERRNO = result_code;
    } else if status < 0 {
        ERRNO = if scan_errno == 0 { EIO_VAL } else { scan_errno };
    }
    result_code
}

#[no_mangle]
pub unsafe extern "C" fn getspnam_r(
    name: *const c_char,
    shadow: *mut CabiShadow,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiShadow,
) -> c_int {
    shadow_reentrant(name, shadow, buffer, buffer_size, result)
}

unsafe fn shadow_global_lookup(name: *const c_char) -> *mut CabiShadow {
    if name.is_null() {
        ERRNO = EINVAL;
        return core::ptr::null_mut();
    }
    let original_errno = ERRNO;
    let file = shadow_open();
    if file.is_null() {
        return core::ptr::null_mut();
    }
    ERRNO = 0;
    let status = shadow_scan_name(
        name,
        file,
        core::ptr::addr_of_mut!(CABI_SHADOW_LOOKUP_LINE),
        core::ptr::addr_of_mut!(CABI_SHADOW_LOOKUP_LINE_SIZE),
        core::ptr::addr_of_mut!(CABI_SHADOW_LOOKUP_RESULT),
    );
    let scan_errno = ERRNO;
    let _ = fclose(file);
    if status > 0 {
        ERRNO = original_errno;
        core::ptr::addr_of_mut!(CABI_SHADOW_LOOKUP_RESULT)
    } else {
        if status < 0 {
            ERRNO = if scan_errno == 0 { EIO_VAL } else { scan_errno };
        } else {
            ERRNO = original_errno;
        }
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn getspnam(name: *const c_char) -> *mut CabiShadow {
    shadow_global_lookup(name)
}

#[no_mangle]
pub unsafe extern "C" fn setspent() {
    let file = core::ptr::addr_of_mut!(CABI_SHADOW_FILE);
    if !(*file).is_null() {
        let _ = fclose(*file);
        *file = core::ptr::null_mut();
    }
    free(CABI_SHADOW_LINE as *mut c_void);
    CABI_SHADOW_LINE = core::ptr::null_mut();
    CABI_SHADOW_LINE_SIZE = 0;
}

#[no_mangle]
pub unsafe extern "C" fn endspent() {
    setspent();
}

#[no_mangle]
pub unsafe extern "C" fn getspent() -> *mut CabiShadow {
    let file = core::ptr::addr_of_mut!(CABI_SHADOW_FILE);
    if (*file).is_null() {
        *file = shadow_open();
        if (*file).is_null() {
            return core::ptr::null_mut();
        }
    }
    let status = shadow_next(
        *file,
        core::ptr::addr_of_mut!(CABI_SHADOW_LINE),
        core::ptr::addr_of_mut!(CABI_SHADOW_LINE_SIZE),
        core::ptr::addr_of_mut!(CABI_SHADOW_RESULT),
    );
    if status > 0 {
        core::ptr::addr_of_mut!(CABI_SHADOW_RESULT)
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn fgetspent(file: *mut FILE) -> *mut CabiShadow {
    if file.is_null() {
        ERRNO = EINVAL;
        return core::ptr::null_mut();
    }
    let status = shadow_next(
        file,
        core::ptr::addr_of_mut!(CABI_FGETSPENT_LINE),
        core::ptr::addr_of_mut!(CABI_FGETSPENT_LINE_SIZE),
        core::ptr::addr_of_mut!(CABI_FGETSPENT_RESULT),
    );
    if status > 0 {
        core::ptr::addr_of_mut!(CABI_FGETSPENT_RESULT)
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn putspent(shadow: *const CabiShadow, file: *mut FILE) -> c_int {
    if shadow.is_null() || file.is_null() {
        ERRNO = EINVAL;
        return -1;
    }
    let name = if (*shadow).sp_namp.is_null() {
        b"\0".as_ptr() as *const c_char
    } else {
        (*shadow).sp_namp as *const c_char
    };
    let password = if (*shadow).sp_pwdp.is_null() {
        b"\0".as_ptr() as *const c_char
    } else {
        (*shadow).sp_pwdp as *const c_char
    };
    let number = |value: c_long| if value == -1 { 0 } else { -1 };
    let number_value = |value: c_long| if value == -1 { 0 as c_long } else { value };
    let flag_precision = if (*shadow).sp_flag == c_ulong::MAX { 0 } else { -1 };
    let flag_value = if (*shadow).sp_flag == c_ulong::MAX { 0 } else { (*shadow).sp_flag };
    let written = fprintf(
        file,
        b"%s:%s:%.*ld:%.*ld:%.*ld:%.*ld:%.*ld:%.*ld:%.*lu\n\0".as_ptr() as *const c_char,
        name,
        password,
        number((*shadow).sp_lstchg), number_value((*shadow).sp_lstchg),
        number((*shadow).sp_min), number_value((*shadow).sp_min),
        number((*shadow).sp_max), number_value((*shadow).sp_max),
        number((*shadow).sp_warn), number_value((*shadow).sp_warn),
        number((*shadow).sp_inact), number_value((*shadow).sp_inact),
        number((*shadow).sp_expire), number_value((*shadow).sp_expire),
        flag_precision, flag_value,
    );
    if written < 0 { -1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn lckpwdf() -> c_int {
    if CABI_SHADOW_LOCK_FD
        .compare_exchange(-1, -2, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        ERRNO = EBUSY;
        return -1;
    }

    let fd = open(
        CABI_SHADOW_LOCK_PATH.as_ptr() as *const c_char,
        O_WRONLY | O_CREAT | O_CLOEXEC,
        0o600,
    );
    if fd < 0 {
        CABI_SHADOW_LOCK_FD.store(-1, Ordering::Release);
        return -1;
    }

    // A non-blocking record lock is deliberate: callers receive the kernel's
    // contention error instead of risking an unbounded wait in a password
    // management path.  The lock covers the complete file (length zero).
    if cabi_lockf(fd, CABI_F_TLOCK, 0) < 0 {
        let _ = close(fd);
        CABI_SHADOW_LOCK_FD.store(-1, Ordering::Release);
        return -1;
    }

    CABI_SHADOW_LOCK_FD.store(fd, Ordering::Release);
    0
}

#[no_mangle]
pub unsafe extern "C" fn ulckpwdf() -> c_int {
    let fd = CABI_SHADOW_LOCK_FD.load(Ordering::Acquire);
    if fd < 0
        || CABI_SHADOW_LOCK_FD
            .compare_exchange(fd, -2, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        ERRNO = EINVAL;
        return -1;
    }

    let unlock_result = cabi_lockf(fd, CABI_F_ULOCK, 0);
    let unlock_errno = ERRNO;
    let close_result = close(fd);
    let close_errno = ERRNO;
    CABI_SHADOW_LOCK_FD.store(-1, Ordering::Release);

    if unlock_result < 0 {
        ERRNO = unlock_errno;
        -1
    } else if close_result < 0 {
        ERRNO = close_errno;
        -1
    } else {
        0
    }
}
