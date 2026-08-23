// legacy error-reporting and signal-information exports.
//
// These functions follow musl's src/legacy/err.c contract: warnings are
// prefixed by __progname, include the current errno only for the non-x forms,
// and the err forms terminate with the supplied status.  The local perror
// implementation predates this slice and prints a numeric errno, so the
// shared warning path emits strerror(errno) directly to preserve musl's
// observable text.

#[inline]
unsafe fn cabi_error_prefix() {
    let _ = fprintf(
        stderr,
        b"%s: \0".as_ptr() as *const c_char,
        __progname,
    );
}

unsafe fn cabi_vwarn_impl(fmt: *const c_char, args: VaList) {
    cabi_error_prefix();
    if !fmt.is_null() {
        let _ = vfprintf(stderr, fmt, args);
        let _ = fputs(b": \0".as_ptr() as *const c_char, stderr);
    }
    let _ = fputs(strerror(ERRNO), stderr);
    let _ = fputc(b'\n' as c_int, stderr);
    // musl keeps stderr unbuffered.  Flush this checkout's buffered FILE so
    // a warning is complete before a caller forks or exits through another
    // path.
    let _ = fflush(stderr);
}

unsafe fn cabi_vwarnx_impl(fmt: *const c_char, args: VaList) {
    cabi_error_prefix();
    if !fmt.is_null() {
        let _ = vfprintf(stderr, fmt, args);
    }
    let _ = fputc(b'\n' as c_int, stderr);
    let _ = fflush(stderr);
}

#[no_mangle]
pub unsafe extern "C" fn vwarn(fmt: *const c_char, args: VaList) {
    cabi_vwarn_impl(fmt, args);
}

#[no_mangle]
pub unsafe extern "C" fn vwarnx(fmt: *const c_char, args: VaList) {
    cabi_vwarnx_impl(fmt, args);
}

#[no_mangle]
pub unsafe extern "C" fn warn(fmt: *const c_char, args: ...) {
    vwarn(fmt, args);
}

#[no_mangle]
pub unsafe extern "C" fn warnx(fmt: *const c_char, args: ...) {
    vwarnx(fmt, args);
}

#[no_mangle]
pub unsafe extern "C" fn verr(status: c_int, fmt: *const c_char, args: VaList) -> ! {
    vwarn(fmt, args);
    exit(status)
}

#[no_mangle]
pub unsafe extern "C" fn verrx(status: c_int, fmt: *const c_char, args: VaList) -> ! {
    vwarnx(fmt, args);
    exit(status)
}

#[no_mangle]
pub unsafe extern "C" fn err(status: c_int, fmt: *const c_char, args: ...) -> ! {
    verr(status, fmt, args)
}

#[no_mangle]
pub unsafe extern "C" fn errx(status: c_int, fmt: *const c_char, args: ...) -> ! {
    verrx(status, fmt, args)
}

#[no_mangle]
pub unsafe extern "C" fn psiginfo(si: *const siginfo_t, msg: *const c_char) {
    // musl reports the signal number carried by siginfo through psignal;
    // psignal already supplies the signal-name and errno-preserving output.
    psignal((*si).si_signo, msg);
}

// syslog slice.
//
// The wire format and connection policy here follow musl's src/misc/syslog.c:
// messages are bounded to one 1024-byte datagram, use the UTC `%b %e %T`
// timestamp, and are sent to the connected AF_UNIX datagram endpoint at
// `/dev/log`. The fixed-size ident is intentional: musl copies at most 31
// bytes during openlog, so the caller's storage is not retained by the
// logger. This implementation is process-global, as is the musl interface.

const CABI_SYSLOG_MASK_DEFAULT: c_int = 0xff;
const CABI_SYSLOG_FACMASK: c_int = 0x3f8;
const CABI_SYSLOG_PRIORITY_MASK: c_int = 0x3ff;
const CABI_SYSLOG_LOG_PID: c_int = 0x01;
const CABI_SYSLOG_LOG_CONS: c_int = 0x02;
const CABI_SYSLOG_LOG_NDELAY: c_int = 0x08;
const CABI_SYSLOG_LOG_PERROR: c_int = 0x20;
const CABI_SYSLOG_SOCK_CLOEXEC: c_int = 0o2000000;
const CABI_SYSLOG_O_NOCTTY: c_int = 0x100;
const CABI_SYSLOG_BUF_SIZE: usize = 1024;
const CABI_SYSLOG_IDENT_SIZE: usize = 32;
const CABI_SYSLOG_ECONNREFUSED: c_int = 111;
const CABI_SYSLOG_ECONNRESET: c_int = 104;
const CABI_SYSLOG_ENOTCONN: c_int = 107;
const CABI_SYSLOG_EPIPE: c_int = 32;

static CABI_SYSLOG_LOCK: AtomicI32 = AtomicI32::new(0);
static mut CABI_SYSLOG_IDENT: [c_char; CABI_SYSLOG_IDENT_SIZE] = [0; CABI_SYSLOG_IDENT_SIZE];
static mut CABI_SYSLOG_OPT: c_int = 0;
static mut CABI_SYSLOG_FACILITY: c_int = 1 << 3; // LOG_USER
static mut CABI_SYSLOG_MASK: c_int = CABI_SYSLOG_MASK_DEFAULT;
static mut CABI_SYSLOG_FD: c_int = -1;

#[repr(C)]
struct CabiSyslogAddr {
    sun_family: u16,
    // `/dev/log` is eight bytes; the ninth byte is its terminating NUL. The
    // short sockaddr is the address length musl passes to connect(2).
    sun_path: [u8; 9],
}

#[inline]
unsafe fn cabi_syslog_lock() {
    while CABI_SYSLOG_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
unsafe fn cabi_syslog_unlock() {
    CABI_SYSLOG_LOCK.store(0, Ordering::Release);
}

#[inline]
unsafe fn cabi_syslog_addr() -> CabiSyslogAddr {
    CabiSyslogAddr {
        sun_family: AF_UNIX as u16,
        sun_path: *b"/dev/log\0",
    }
}

unsafe fn cabi_syslog_open_connection() {
    let fd = socket(AF_UNIX, SOCK_DGRAM | CABI_SYSLOG_SOCK_CLOEXEC, 0);
    CABI_SYSLOG_FD = fd;
    if fd >= 0 {
        let addr = cabi_syslog_addr();
        // Keep the descriptor after a failed connect. musl retries a lost
        // connection from _vsyslog, while a non-lost error is reported only
        // through LOG_CONS, matching syslog's void-returning contract.
        let _ = connect(
            fd,
            &addr as *const CabiSyslogAddr as *const sockaddr,
            core::mem::size_of::<CabiSyslogAddr>() as c_uint,
        );
    }
}

#[inline]
fn cabi_syslog_lost_connection(error: c_int) -> bool {
    error == CABI_SYSLOG_ECONNREFUSED
        || error == CABI_SYSLOG_ECONNRESET
        || error == CABI_SYSLOG_ENOTCONN
        || error == CABI_SYSLOG_EPIPE
    // ECONNREFUSED, ECONNRESET, ENOTCONN, EPIPE
}

unsafe fn cabi_syslog_console(buf: *const u8, length: usize, header_length: usize) {
    let fd = open(
        b"/dev/console\0".as_ptr() as *const c_char,
        O_WRONLY | CABI_SYSLOG_O_NOCTTY | O_CLOEXEC,
        0,
    );
    if fd >= 0 {
        // The console receives the human-readable part, without the syslog
        // priority and timestamp prefix.
        let _ = dprintf(
            fd,
            b"%.*s\0".as_ptr() as *const c_char,
            length.saturating_sub(header_length) as c_int,
            buf.add(header_length) as *const c_char,
        );
        let _ = close(fd);
    }
}

unsafe fn cabi_syslog_vsyslog_impl(
    priority: c_int,
    message: *const c_char,
    args: VaList,
) {
    let errno_save = ERRNO;
    if CABI_SYSLOG_FD < 0 {
        cabi_syslog_open_connection();
    }

    // cabi_syslog_open_connection may have changed errno. The formatter must
    // observe the caller's errno, and a successful send must preserve it.
    ERRNO = errno_save;

    let mut now: TimeT = 0;
    let _ = time(&mut now);
    let mut tm_value: tm = core::mem::zeroed();
    let _ = gmtime_r(&now, &mut tm_value);
    let mut timebuf = [0 as c_char; 16];
    let _ = strftime(
        timebuf.as_mut_ptr(),
        timebuf.len(),
        b"%b %e %T\0".as_ptr() as *const c_char,
        &tm_value,
    );

    let pid = if CABI_SYSLOG_OPT & CABI_SYSLOG_LOG_PID != 0 {
        getpid()
    } else {
        0
    };
    let mut buf = [0u8; CABI_SYSLOG_BUF_SIZE];
    let mut header_length: c_int = 0;
    let opening_bracket = b"[\0".as_ptr().add(if pid != 0 { 0 } else { 1 });
    let closing_bracket = b"]\0".as_ptr().add(if pid != 0 { 0 } else { 1 });
    let ident_ptr = core::ptr::addr_of!(CABI_SYSLOG_IDENT) as *const c_char;
    let header = snprintf(
        buf.as_mut_ptr() as *mut c_char,
        buf.len(),
        b"<%d>%s %n%s%s%.0d%s: \0".as_ptr() as *const c_char,
        priority,
        timebuf.as_ptr(),
        &mut header_length,
        ident_ptr,
        opening_bracket,
        pid,
        closing_bracket,
    );
    if header < 0 || header as usize >= buf.len() {
        return;
    }

    // snprintf/vsnprintf are not supposed to alter errno, but restoring it
    // explicitly is part of musl's syslog behavior around connection setup.
    ERRNO = errno_save;
    let header_length = header_length.max(0) as usize;
    let available = buf.len() - header as usize;
    let message_length = vsnprintf(
        buf.as_mut_ptr().add(header as usize) as *mut c_char,
        available,
        message,
        args,
    );
    if message_length < 0 {
        return;
    }
    let mut length = if message_length as usize >= available {
        CABI_SYSLOG_BUF_SIZE - 1
    } else {
        header as usize + message_length as usize
    };
    if length == 0 || buf[length - 1] != b'\n' {
        if length < CABI_SYSLOG_BUF_SIZE {
            buf[length] = b'\n';
            length += 1;
        }
    }

    let fd = CABI_SYSLOG_FD;
    let sent = send(fd, buf.as_ptr() as *const c_void, length, 0);
    if sent < 0 {
        let mut send_failed = true;
        if cabi_syslog_lost_connection(ERRNO) {
            let addr = cabi_syslog_addr();
            if connect(
                fd,
                &addr as *const CabiSyslogAddr as *const sockaddr,
                core::mem::size_of::<CabiSyslogAddr>() as c_uint,
            ) == 0
                && send(fd, buf.as_ptr() as *const c_void, length, 0) >= 0
            {
                send_failed = false;
            }
        }
        if send_failed && CABI_SYSLOG_OPT & CABI_SYSLOG_LOG_CONS != 0 {
            cabi_syslog_console(buf.as_ptr(), length, header_length);
        }
    }
    if CABI_SYSLOG_OPT & CABI_SYSLOG_LOG_PERROR != 0 {
        let _ = dprintf(
            2,
            b"%.*s\0".as_ptr() as *const c_char,
            length.saturating_sub(header_length) as c_int,
            buf.as_ptr().add(header_length) as *const c_char,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn setlogmask(maskpri: c_int) -> c_int {
    cabi_syslog_lock();
    let old = CABI_SYSLOG_MASK;
    if maskpri != 0 {
        CABI_SYSLOG_MASK = maskpri;
    }
    cabi_syslog_unlock();
    old
}

#[no_mangle]
pub unsafe extern "C" fn closelog() {
    cabi_syslog_lock();
    // musl closes the current descriptor even when it is -1; use the public
    // close entry point so a caller observing errno sees the same EBADF path.
    let _ = close(CABI_SYSLOG_FD);
    CABI_SYSLOG_FD = -1;
    cabi_syslog_unlock();
}

#[no_mangle]
pub unsafe extern "C" fn openlog(ident: *const c_char, logopt: c_int, facility: c_int) {
    cabi_syslog_lock();
    if !ident.is_null() {
        let length = strnlen(ident as *const u8, CABI_SYSLOG_IDENT_SIZE - 1);
        let ident_ptr = core::ptr::addr_of_mut!(CABI_SYSLOG_IDENT) as *mut c_char;
        core::ptr::copy_nonoverlapping(ident, ident_ptr, length);
        CABI_SYSLOG_IDENT[length] = 0;
    } else {
        CABI_SYSLOG_IDENT[0] = 0;
    }
    CABI_SYSLOG_OPT = logopt;
    CABI_SYSLOG_FACILITY = facility;
    if logopt & CABI_SYSLOG_LOG_NDELAY != 0 && CABI_SYSLOG_FD < 0 {
        cabi_syslog_open_connection();
    }
    cabi_syslog_unlock();
}

#[inline(always)]
unsafe fn cabi_syslog_dispatch(
    priority: c_int,
    message: *const c_char,
    args: VaList,
) {
    cabi_syslog_lock();
    if (priority & !CABI_SYSLOG_PRIORITY_MASK) != 0
        || CABI_SYSLOG_MASK & (1 << (priority & 7)) == 0
    {
        cabi_syslog_unlock();
        return;
    }
    let mut priority = priority;
    if priority & CABI_SYSLOG_FACMASK == 0 {
        priority |= CABI_SYSLOG_FACILITY;
    }
    cabi_syslog_vsyslog_impl(priority, message, args);
    cabi_syslog_unlock();
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn vsyslog(
    priority: c_int,
    message: *const c_char,
    args: VaList,
) {
    cabi_syslog_dispatch(priority, message, args);
}

#[no_mangle]
pub unsafe extern "C" fn syslog(priority: c_int, message: *const c_char, args: ...) {
    cabi_syslog_dispatch(priority, message, args);
}
