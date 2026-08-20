// M4 legacy error-reporting and signal-information exports.
//
// These functions follow musl's src/legacy/err.c contract: warnings are
// prefixed by __progname, include the current errno only for the non-x forms,
// and the err forms terminate with the supplied status.  The local perror
// implementation predates this slice and prints a numeric errno, so the
// shared warning path emits strerror(errno) directly to preserve musl's
// observable text.

#[inline]
unsafe fn m4_error_prefix() {
    let _ = fprintf(
        stderr,
        b"%s: \0".as_ptr() as *const c_char,
        __progname,
    );
}

unsafe fn m4_vwarn_impl(fmt: *const c_char, args: VaList) {
    m4_error_prefix();
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

unsafe fn m4_vwarnx_impl(fmt: *const c_char, args: VaList) {
    m4_error_prefix();
    if !fmt.is_null() {
        let _ = vfprintf(stderr, fmt, args);
    }
    let _ = fputc(b'\n' as c_int, stderr);
    let _ = fflush(stderr);
}

#[no_mangle]
pub unsafe extern "C" fn vwarn(fmt: *const c_char, args: VaList) {
    m4_vwarn_impl(fmt, args);
}

#[no_mangle]
pub unsafe extern "C" fn vwarnx(fmt: *const c_char, args: VaList) {
    m4_vwarnx_impl(fmt, args);
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

// M4 syslog slice.
//
// The wire format and connection policy here follow musl's src/misc/syslog.c:
// messages are bounded to one 1024-byte datagram, use the UTC `%b %e %T`
// timestamp, and are sent to the connected AF_UNIX datagram endpoint at
// `/dev/log`. The fixed-size ident is intentional: musl copies at most 31
// bytes during openlog, so the caller's storage is not retained by the
// logger. This implementation is process-global, as is the musl interface.

const M4_SYSLOG_MASK_DEFAULT: c_int = 0xff;
const M4_SYSLOG_FACMASK: c_int = 0x3f8;
const M4_SYSLOG_PRIORITY_MASK: c_int = 0x3ff;
const M4_SYSLOG_LOG_PID: c_int = 0x01;
const M4_SYSLOG_LOG_CONS: c_int = 0x02;
const M4_SYSLOG_LOG_NDELAY: c_int = 0x08;
const M4_SYSLOG_LOG_PERROR: c_int = 0x20;
const M4_SYSLOG_SOCK_CLOEXEC: c_int = 0o2000000;
const M4_SYSLOG_O_NOCTTY: c_int = 0x100;
const M4_SYSLOG_BUF_SIZE: usize = 1024;
const M4_SYSLOG_IDENT_SIZE: usize = 32;
const M4_SYSLOG_ECONNREFUSED: c_int = 111;
const M4_SYSLOG_ECONNRESET: c_int = 104;
const M4_SYSLOG_ENOTCONN: c_int = 107;
const M4_SYSLOG_EPIPE: c_int = 32;

static M4_SYSLOG_LOCK: AtomicI32 = AtomicI32::new(0);
static mut M4_SYSLOG_IDENT: [c_char; M4_SYSLOG_IDENT_SIZE] = [0; M4_SYSLOG_IDENT_SIZE];
static mut M4_SYSLOG_OPT: c_int = 0;
static mut M4_SYSLOG_FACILITY: c_int = 1 << 3; // LOG_USER
static mut M4_SYSLOG_MASK: c_int = M4_SYSLOG_MASK_DEFAULT;
static mut M4_SYSLOG_FD: c_int = -1;

#[repr(C)]
struct M4SyslogAddr {
    sun_family: u16,
    // `/dev/log` is eight bytes; the ninth byte is its terminating NUL. The
    // short sockaddr is the address length musl passes to connect(2).
    sun_path: [u8; 9],
}

#[inline]
unsafe fn m4_syslog_lock() {
    while M4_SYSLOG_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
unsafe fn m4_syslog_unlock() {
    M4_SYSLOG_LOCK.store(0, Ordering::Release);
}

#[inline]
unsafe fn m4_syslog_addr() -> M4SyslogAddr {
    M4SyslogAddr {
        sun_family: AF_UNIX as u16,
        sun_path: *b"/dev/log\0",
    }
}

unsafe fn m4_syslog_open_connection() {
    let fd = socket(AF_UNIX, SOCK_DGRAM | M4_SYSLOG_SOCK_CLOEXEC, 0);
    M4_SYSLOG_FD = fd;
    if fd >= 0 {
        let addr = m4_syslog_addr();
        // Keep the descriptor after a failed connect. musl retries a lost
        // connection from _vsyslog, while a non-lost error is reported only
        // through LOG_CONS, matching syslog's void-returning contract.
        let _ = connect(
            fd,
            &addr as *const M4SyslogAddr as *const sockaddr,
            core::mem::size_of::<M4SyslogAddr>() as c_uint,
        );
    }
}

#[inline]
fn m4_syslog_lost_connection(error: c_int) -> bool {
    error == M4_SYSLOG_ECONNREFUSED
        || error == M4_SYSLOG_ECONNRESET
        || error == M4_SYSLOG_ENOTCONN
        || error == M4_SYSLOG_EPIPE
    // ECONNREFUSED, ECONNRESET, ENOTCONN, EPIPE
}

unsafe fn m4_syslog_console(buf: *const u8, length: usize, header_length: usize) {
    let fd = open(
        b"/dev/console\0".as_ptr() as *const c_char,
        O_WRONLY | M4_SYSLOG_O_NOCTTY | O_CLOEXEC,
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

unsafe fn m4_syslog_vsyslog_impl(
    priority: c_int,
    message: *const c_char,
    args: VaList,
) {
    let errno_save = ERRNO;
    if M4_SYSLOG_FD < 0 {
        m4_syslog_open_connection();
    }

    // m4_syslog_open_connection may have changed errno. The formatter must
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

    let pid = if M4_SYSLOG_OPT & M4_SYSLOG_LOG_PID != 0 {
        getpid()
    } else {
        0
    };
    let mut buf = [0u8; M4_SYSLOG_BUF_SIZE];
    let mut header_length: c_int = 0;
    let opening_bracket = b"[\0".as_ptr().add(if pid != 0 { 0 } else { 1 });
    let closing_bracket = b"]\0".as_ptr().add(if pid != 0 { 0 } else { 1 });
    let ident_ptr = core::ptr::addr_of!(M4_SYSLOG_IDENT) as *const c_char;
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
        M4_SYSLOG_BUF_SIZE - 1
    } else {
        header as usize + message_length as usize
    };
    if length == 0 || buf[length - 1] != b'\n' {
        if length < M4_SYSLOG_BUF_SIZE {
            buf[length] = b'\n';
            length += 1;
        }
    }

    let fd = M4_SYSLOG_FD;
    let sent = send(fd, buf.as_ptr() as *const c_void, length, 0);
    if sent < 0 {
        let mut send_failed = true;
        if m4_syslog_lost_connection(ERRNO) {
            let addr = m4_syslog_addr();
            if connect(
                fd,
                &addr as *const M4SyslogAddr as *const sockaddr,
                core::mem::size_of::<M4SyslogAddr>() as c_uint,
            ) == 0
                && send(fd, buf.as_ptr() as *const c_void, length, 0) >= 0
            {
                send_failed = false;
            }
        }
        if send_failed && M4_SYSLOG_OPT & M4_SYSLOG_LOG_CONS != 0 {
            m4_syslog_console(buf.as_ptr(), length, header_length);
        }
    }
    if M4_SYSLOG_OPT & M4_SYSLOG_LOG_PERROR != 0 {
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
    m4_syslog_lock();
    let old = M4_SYSLOG_MASK;
    if maskpri != 0 {
        M4_SYSLOG_MASK = maskpri;
    }
    m4_syslog_unlock();
    old
}

#[no_mangle]
pub unsafe extern "C" fn closelog() {
    m4_syslog_lock();
    // musl closes the current descriptor even when it is -1; use the public
    // close entry point so a caller observing errno sees the same EBADF path.
    let _ = close(M4_SYSLOG_FD);
    M4_SYSLOG_FD = -1;
    m4_syslog_unlock();
}

#[no_mangle]
pub unsafe extern "C" fn openlog(ident: *const c_char, logopt: c_int, facility: c_int) {
    m4_syslog_lock();
    if !ident.is_null() {
        let length = strnlen(ident as *const u8, M4_SYSLOG_IDENT_SIZE - 1);
        let ident_ptr = core::ptr::addr_of_mut!(M4_SYSLOG_IDENT) as *mut c_char;
        core::ptr::copy_nonoverlapping(ident, ident_ptr, length);
        M4_SYSLOG_IDENT[length] = 0;
    } else {
        M4_SYSLOG_IDENT[0] = 0;
    }
    M4_SYSLOG_OPT = logopt;
    M4_SYSLOG_FACILITY = facility;
    if logopt & M4_SYSLOG_LOG_NDELAY != 0 && M4_SYSLOG_FD < 0 {
        m4_syslog_open_connection();
    }
    m4_syslog_unlock();
}

#[inline(always)]
unsafe fn m4_syslog_dispatch(
    priority: c_int,
    message: *const c_char,
    args: VaList,
) {
    m4_syslog_lock();
    if (priority & !M4_SYSLOG_PRIORITY_MASK) != 0
        || M4_SYSLOG_MASK & (1 << (priority & 7)) == 0
    {
        m4_syslog_unlock();
        return;
    }
    let mut priority = priority;
    if priority & M4_SYSLOG_FACMASK == 0 {
        priority |= M4_SYSLOG_FACILITY;
    }
    m4_syslog_vsyslog_impl(priority, message, args);
    m4_syslog_unlock();
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn vsyslog(
    priority: c_int,
    message: *const c_char,
    args: VaList,
) {
    m4_syslog_dispatch(priority, message, args);
}

#[no_mangle]
pub unsafe extern "C" fn syslog(priority: c_int, message: *const c_char, args: ...) {
    m4_syslog_dispatch(priority, message, args);
}
