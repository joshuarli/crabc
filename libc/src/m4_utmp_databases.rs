// M4 utmp/utmpx databases.
//
// musl's public utmp ABI is one fixed-width utmpx record, so the traditional
// names below deliberately use the same Rust representation.  The database
// is a process-global cursor over the selected file, matching the historical
// API.  Reads and writes use raw syscalls rather than FILE: a record is an
// on-disk binary object and must never be split or transformed by text I/O.

const M4_UTMP_PATH_MAX: usize = 4096;
const M4_UTMP_FD_NONE: c_int = -1;
const M4_UTMP_EOF: c_int = 0;
const M4_UTMP_RECORD_OK: c_int = 1;
const M4_UTMP_RECORD_ERROR: c_int = -1;

const M4_UTMP_EMPTY: i16 = 0;
const M4_UTMP_RUN_LVL: i16 = 1;
const M4_UTMP_BOOT_TIME: i16 = 2;
const M4_UTMP_NEW_TIME: i16 = 3;
const M4_UTMP_OLD_TIME: i16 = 4;
const M4_UTMP_INIT_PROCESS: i16 = 5;
const M4_UTMP_LOGIN_PROCESS: i16 = 6;
const M4_UTMP_USER_PROCESS: i16 = 7;
const M4_UTMP_DEAD_PROCESS: i16 = 8;

const M4_UTMP_EINVAL: c_int = 22;
const M4_UTMP_EBADF: c_int = 9;
const M4_UTMP_EIO: c_int = 5;
const M4_UTMP_ENAMETOOLONG: c_int = 36;

static M4_UTMP_DEFAULT_PATH: &[u8] = b"/dev/null/utmp\0";
static mut M4_UTMP_PATH: [c_char; M4_UTMP_PATH_MAX] = [0; M4_UTMP_PATH_MAX];
static mut M4_UTMP_HAS_PATH: bool = false;
static mut M4_UTMP_FD: c_int = M4_UTMP_FD_NONE;
static mut M4_UTMP_WRITABLE: bool = false;

#[repr(C)]
pub struct M4UtmpExit {
    pub __e_termination: i16,
    pub __e_exit: i16,
}

#[repr(C)]
pub struct M4Utmpx {
    pub ut_type: i16,
    pub __ut_pad1: i16,
    pub ut_pid: c_int,
    pub ut_line: [c_char; 32],
    pub ut_id: [c_char; 4],
    pub ut_user: [c_char; 32],
    pub ut_host: [c_char; 256],
    pub ut_exit: M4UtmpExit,
    pub ut_session: i32,
    pub __ut_pad2: i32,
    pub ut_tv: timeval,
    pub ut_addr_v6: [u32; 4],
    pub __unused: [c_char; 20],
}

static mut M4_UTMP_RECORD: M4Utmpx = M4Utmpx {
    ut_type: 0,
    __ut_pad1: 0,
    ut_pid: 0,
    ut_line: [0; 32],
    ut_id: [0; 4],
    ut_user: [0; 32],
    ut_host: [0; 256],
    ut_exit: M4UtmpExit {
        __e_termination: 0,
        __e_exit: 0,
    },
    ut_session: 0,
    __ut_pad2: 0,
    ut_tv: timeval { tv_sec: 0, tv_usec: 0 },
    ut_addr_v6: [0; 4],
    __unused: [0; 20],
};

static mut M4_UTMP_PENDING: M4Utmpx = M4Utmpx {
    ut_type: 0,
    __ut_pad1: 0,
    ut_pid: 0,
    ut_line: [0; 32],
    ut_id: [0; 4],
    ut_user: [0; 32],
    ut_host: [0; 256],
    ut_exit: M4UtmpExit {
        __e_termination: 0,
        __e_exit: 0,
    },
    ut_session: 0,
    __ut_pad2: 0,
    ut_tv: timeval { tv_sec: 0, tv_usec: 0 },
    ut_addr_v6: [0; 4],
    __unused: [0; 20],
};

#[inline]
unsafe fn m4_utmp_path() -> *const c_char {
    if M4_UTMP_HAS_PATH {
        core::ptr::addr_of!(M4_UTMP_PATH).cast::<c_char>()
    } else {
        M4_UTMP_DEFAULT_PATH.as_ptr().cast::<c_char>()
    }
}

#[inline]
unsafe fn m4_utmp_close() {
    if M4_UTMP_FD != M4_UTMP_FD_NONE {
        let result = sys_close(M4_UTMP_FD as i64);
        if result < 0 && result >= -4095 {
            ERRNO = (-result) as c_int;
        }
        M4_UTMP_FD = M4_UTMP_FD_NONE;
    }
    M4_UTMP_WRITABLE = false;
}

#[inline]
unsafe fn m4_utmp_open(writable: bool) -> bool {
    if M4_UTMP_FD != M4_UTMP_FD_NONE {
        if !writable || M4_UTMP_WRITABLE {
            return true;
        }
        m4_utmp_close();
    }

    let flags = if writable {
        O_RDWR | O_CREAT | O_CLOEXEC
    } else {
        O_RDONLY | O_CLOEXEC
    };
    let result = sys_open(m4_utmp_path() as *const u8, flags as i64, 0o666);
    if result < 0 {
        syscall_result(result);
        return false;
    }
    M4_UTMP_FD = result as c_int;
    M4_UTMP_WRITABLE = writable;
    true
}

// Read one complete binary record.  A clean EOF is distinct from a short
// record: the latter is a corrupt database and reports EIO to the caller.
#[inline]
unsafe fn m4_utmp_read_record(fd: c_int, record: *mut M4Utmpx) -> c_int {
    if fd < 0 || record.is_null() {
        ERRNO = if fd < 0 { M4_UTMP_EBADF } else { M4_UTMP_EINVAL };
        return M4_UTMP_RECORD_ERROR;
    }
    let size = core::mem::size_of::<M4Utmpx>();
    let mut consumed = 0usize;
    while consumed < size {
        let result = sys_read(
            fd as i64,
            (record as *mut u8).add(consumed),
            size - consumed,
        );
        if result < 0 {
            syscall_result(result);
            return M4_UTMP_RECORD_ERROR;
        }
        if result == 0 {
            if consumed == 0 {
                return M4_UTMP_EOF;
            }
            ERRNO = M4_UTMP_EIO;
            return M4_UTMP_RECORD_ERROR;
        }
        consumed += result as usize;
    }
    M4_UTMP_RECORD_OK
}

#[inline]
unsafe fn m4_utmp_write_record(fd: c_int, record: *const M4Utmpx) -> bool {
    if fd < 0 {
        ERRNO = M4_UTMP_EBADF;
        return false;
    }
    if record.is_null() {
        ERRNO = M4_UTMP_EINVAL;
        return false;
    }
    let size = core::mem::size_of::<M4Utmpx>();
    let mut written = 0usize;
    while written < size {
        let result = sys_write(
            fd as i64,
            (record as *const u8).add(written),
            size - written,
        );
        if result < 0 {
            syscall_result(result);
            return false;
        }
        if result == 0 {
            ERRNO = M4_UTMP_EIO;
            return false;
        }
        written += result as usize;
    }
    true
}

#[inline]
unsafe fn m4_utmp_equal_id(left: *const M4Utmpx, right: *const M4Utmpx) -> bool {
    let mut i = 0usize;
    while i < 4 {
        if (*left).ut_id[i] != (*right).ut_id[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[inline]
unsafe fn m4_utmp_equal_line(left: *const M4Utmpx, right: *const M4Utmpx) -> bool {
    let mut i = 0usize;
    while i < 32 {
        if (*left).ut_line[i] != (*right).ut_line[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[inline]
unsafe fn m4_utmp_id_match(record: *const M4Utmpx, query: *const M4Utmpx) -> bool {
    match (*query).ut_type {
        M4_UTMP_RUN_LVL | M4_UTMP_BOOT_TIME | M4_UTMP_NEW_TIME | M4_UTMP_OLD_TIME => {
            (*record).ut_type == (*query).ut_type
        }
        _ => m4_utmp_equal_id(record, query),
    }
}

#[inline]
unsafe fn m4_utmp_line_match(record: *const M4Utmpx, query: *const M4Utmpx) -> bool {
    ((*record).ut_type == M4_UTMP_USER_PROCESS
        || (*record).ut_type == M4_UTMP_LOGIN_PROCESS)
        && m4_utmp_equal_line(record, query)
}

#[no_mangle]
pub unsafe extern "C" fn endutxent() {
    m4_utmp_close();
}

#[no_mangle]
pub unsafe extern "C" fn setutxent() {
    if M4_UTMP_FD != M4_UTMP_FD_NONE {
        let result = sys_lseek(M4_UTMP_FD as i64, 0, SEEK_SET as i64);
        if result < 0 {
            syscall_result(result);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn getutxent() -> *mut M4Utmpx {
    if !m4_utmp_open(false) {
        return core::ptr::null_mut();
    }
    match m4_utmp_read_record(M4_UTMP_FD, core::ptr::addr_of_mut!(M4_UTMP_RECORD)) {
        M4_UTMP_RECORD_OK => core::ptr::addr_of_mut!(M4_UTMP_RECORD),
        _ => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn getutxid(query: *const M4Utmpx) -> *mut M4Utmpx {
    if query.is_null() {
        ERRNO = M4_UTMP_EINVAL;
        return core::ptr::null_mut();
    }
    // A query may legally be the pointer returned by getutxent.  Preserve it
    // before the next read overwrites the process-global result object.
    core::ptr::copy_nonoverlapping(
        query as *const u8,
        core::ptr::addr_of_mut!(M4_UTMP_PENDING) as *mut u8,
        core::mem::size_of::<M4Utmpx>(),
    );
    if !m4_utmp_open(false) {
        return core::ptr::null_mut();
    }
    loop {
        match m4_utmp_read_record(M4_UTMP_FD, core::ptr::addr_of_mut!(M4_UTMP_RECORD)) {
            M4_UTMP_RECORD_OK => {
                if m4_utmp_id_match(
                    core::ptr::addr_of!(M4_UTMP_RECORD),
                    core::ptr::addr_of!(M4_UTMP_PENDING),
                ) {
                    return core::ptr::addr_of_mut!(M4_UTMP_RECORD);
                }
            }
            _ => return core::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn getutxline(query: *const M4Utmpx) -> *mut M4Utmpx {
    if query.is_null() {
        ERRNO = M4_UTMP_EINVAL;
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(
        query as *const u8,
        core::ptr::addr_of_mut!(M4_UTMP_PENDING) as *mut u8,
        core::mem::size_of::<M4Utmpx>(),
    );
    if !m4_utmp_open(false) {
        return core::ptr::null_mut();
    }
    loop {
        match m4_utmp_read_record(M4_UTMP_FD, core::ptr::addr_of_mut!(M4_UTMP_RECORD)) {
            M4_UTMP_RECORD_OK => {
                if m4_utmp_line_match(
                    core::ptr::addr_of!(M4_UTMP_RECORD),
                    core::ptr::addr_of!(M4_UTMP_PENDING),
                ) {
                    return core::ptr::addr_of_mut!(M4_UTMP_RECORD);
                }
            }
            _ => return core::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pututxline(record: *const M4Utmpx) -> *mut M4Utmpx {
    if record.is_null() {
        ERRNO = M4_UTMP_EINVAL;
        return core::ptr::null_mut();
    }
    // The caller is allowed to pass the pointer returned by getutxent.  Copy
    // before scanning, because the scan uses the same process-global result.
    core::ptr::copy_nonoverlapping(
        record as *const u8,
        core::ptr::addr_of_mut!(M4_UTMP_PENDING) as *mut u8,
        core::mem::size_of::<M4Utmpx>(),
    );
    if !m4_utmp_open(true) {
        return core::ptr::null_mut();
    }
    let start = sys_lseek(M4_UTMP_FD as i64, 0, SEEK_SET as i64);
    if start < 0 {
        syscall_result(start);
        return core::ptr::null_mut();
    }
    let mut replacement = -1i64;
    loop {
        let position = sys_lseek(M4_UTMP_FD as i64, 0, SEEK_CUR as i64);
        if position < 0 {
            syscall_result(position);
            return core::ptr::null_mut();
        }
        match m4_utmp_read_record(M4_UTMP_FD, core::ptr::addr_of_mut!(M4_UTMP_RECORD)) {
            M4_UTMP_RECORD_OK => {
                if m4_utmp_equal_id(
                    core::ptr::addr_of!(M4_UTMP_RECORD),
                    core::ptr::addr_of!(M4_UTMP_PENDING),
                ) {
                    replacement = position;
                    break;
                }
            }
            M4_UTMP_EOF => break,
            _ => return core::ptr::null_mut(),
        }
    }
    if replacement >= 0 {
        let result = sys_lseek(M4_UTMP_FD as i64, replacement, SEEK_SET as i64);
        if result < 0 {
            syscall_result(result);
            return core::ptr::null_mut();
        }
    } else {
        let result = sys_lseek(M4_UTMP_FD as i64, 0, SEEK_END as i64);
        if result < 0 {
            syscall_result(result);
            return core::ptr::null_mut();
        }
    }
    if !m4_utmp_write_record(
        M4_UTMP_FD,
        core::ptr::addr_of!(M4_UTMP_PENDING),
    ) {
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(
        core::ptr::addr_of!(M4_UTMP_PENDING) as *const u8,
        core::ptr::addr_of_mut!(M4_UTMP_RECORD) as *mut u8,
        core::mem::size_of::<M4Utmpx>(),
    );
    core::ptr::addr_of_mut!(M4_UTMP_RECORD)
}

#[no_mangle]
pub unsafe extern "C" fn updwtmpx(path: *const c_char, record: *const M4Utmpx) {
    if path.is_null() || record.is_null() {
        ERRNO = M4_UTMP_EINVAL;
        return;
    }
    core::ptr::copy_nonoverlapping(
        record as *const u8,
        core::ptr::addr_of_mut!(M4_UTMP_PENDING) as *mut u8,
        core::mem::size_of::<M4Utmpx>(),
    );
    let fd = sys_open(
        path as *const u8,
        (O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC) as i64,
        0o666,
    );
    if fd < 0 {
        syscall_result(fd);
        return;
    }
    let _ = m4_utmp_write_record(fd as c_int, core::ptr::addr_of!(M4_UTMP_PENDING));
    let result = sys_close(fd);
    if result < 0 && result >= -4095 {
        ERRNO = (-result) as c_int;
    }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn utmpxname(path: *const c_char) -> c_int {
    if path.is_null() {
        ERRNO = M4_UTMP_EINVAL;
        return -1;
    }
    let mut length = 0usize;
    while length < M4_UTMP_PATH_MAX {
        if *path.add(length) == 0 {
            break;
        }
        length += 1;
    }
    if length == M4_UTMP_PATH_MAX {
        ERRNO = M4_UTMP_ENAMETOOLONG;
        return -1;
    }
    let mut i = 0usize;
    while i <= length {
        M4_UTMP_PATH[i] = *path.add(i);
        i += 1;
    }
    M4_UTMP_HAS_PATH = true;
    m4_utmp_close();
    0
}

// Traditional utmp is an ABI alias of utmpx in musl.  Keep distinct exported
// symbols so callers that request the historical names resolve directly even
// when no linker weak-alias processing is available.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn endutent() {
    endutxent();
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn setutent() {
    setutxent();
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn getutent() -> *mut M4Utmpx {
    getutxent()
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn getutid(query: *const M4Utmpx) -> *mut M4Utmpx {
    getutxid(query)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn getutline(query: *const M4Utmpx) -> *mut M4Utmpx {
    getutxline(query)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn pututline(record: *const M4Utmpx) -> *mut M4Utmpx {
    pututxline(record)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn updwtmp(path: *const c_char, record: *const M4Utmpx) {
    updwtmpx(path, record);
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn utmpname(path: *const c_char) -> c_int {
    utmpxname(path)
}
