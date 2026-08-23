// Linux terminal and termios entry points.
//
// The public header's termios layout is the musl layout on x86_64, AArch64,
// and RISC-V64: four u32 flag words, one cc_t line byte, 32 control bytes,
// and two u32 speed words.  The ioctl operations below use the Linux tty
// ABI directly and publish negative syscall errors through errno.

#[repr(C)]
pub struct cabi_termios {
    c_iflag: c_uint,
    c_oflag: c_uint,
    c_cflag: c_uint,
    c_lflag: c_uint,
    c_line: u8,
    c_cc: [u8; 32],
    __ispeed: c_uint,
    __ospeed: c_uint,
}

const CABI_TCGETS: u32 = 0x5401;
const CABI_TCSETS: u32 = 0x5402;
const CABI_TCSETSW: u32 = 0x5403;
const CABI_TCSETSF: u32 = 0x5404;
const CABI_TCSBRK: u32 = 0x5409;
const CABI_TIOCGWINSZ: u32 = 0x5413;
const CABI_TIOCSWINSZ: u32 = 0x5414;
const CABI_TCXONC: u32 = 0x540a;
const CABI_TCFLSH: u32 = 0x540b;
const CABI_TIOCGPGRP: u32 = 0x540f;
const CABI_TIOCSPGRP: u32 = 0x5410;
const CABI_TIOCGSID: u32 = 0x5429;
const CABI_TIOCSCTTY: u32 = 0x540e;
const CABI_TIOCSPTLCK: u32 = 0x4004_5431;
const CABI_TIOCGPTN: u32 = 0x8004_5430;

const CABI_PTY_O_RDWR: i32 = 2;
const CABI_PTY_O_NOCTTY: i32 = 0x100;
const CABI_PTY_O_CLOEXEC: i32 = 0x80000;

const CABI_CBAUD: c_uint = 0o10017;
const CABI_CIBAUD: c_uint = 0o2003600000;
const CABI_TERM_F_GETFD: c_int = 1;

unsafe fn cabi_ioctl(fd: c_int, request: u32, argument: *mut u8) -> c_int {
    syscall_result(sys_ioctl(fd, request, argument)) as c_int
}

unsafe fn cabi_ioctl_value(fd: c_int, request: u32, value: c_int) -> c_int {
    cabi_ioctl(fd, request, value as isize as *mut u8)
}

#[no_mangle]
pub unsafe extern "C" fn tcgetattr(fd: c_int, tio: *mut cabi_termios) -> c_int {
    cabi_ioctl(fd, CABI_TCGETS, tio as *mut u8)
}

#[no_mangle]
pub unsafe extern "C" fn tcsetattr(
    fd: c_int,
    action: c_int,
    tio: *const cabi_termios,
) -> c_int {
    if action < 0 || action > 2 {
        ERRNO = EINVAL;
        return -1;
    }
    cabi_ioctl(
        fd,
        CABI_TCSETS + action as u32,
        tio as *const cabi_termios as *mut u8,
    )
}

#[no_mangle]
pub unsafe extern "C" fn tcflush(fd: c_int, queue: c_int) -> c_int {
    cabi_ioctl_value(fd, CABI_TCFLSH, queue)
}

#[no_mangle]
pub unsafe extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    cabi_ioctl_value(fd, CABI_TCXONC, action)
}

#[no_mangle]
pub unsafe extern "C" fn tcdrain(fd: c_int) -> c_int {
    // TCSBRK with a nonzero argument waits for output to drain without
    // generating a break, matching musl's tcdrain implementation.
    cabi_ioctl_value(fd, CABI_TCSBRK, 1)
}

#[repr(C)]
pub struct cabi_winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[no_mangle]
pub unsafe extern "C" fn tcgetwinsize(fd: c_int, wsz: *mut cabi_winsize) -> c_int {
    cabi_ioctl(fd, CABI_TIOCGWINSZ, wsz as *mut u8)
}

#[no_mangle]
pub unsafe extern "C" fn tcsetwinsize(fd: c_int, wsz: *const cabi_winsize) -> c_int {
    cabi_ioctl(fd, CABI_TIOCSWINSZ, wsz as *mut cabi_winsize as *mut u8)
}

#[no_mangle]
pub unsafe extern "C" fn tcsendbreak(fd: c_int, _duration: c_int) -> c_int {
    // POSIX leaves nonzero duration implementation-defined. Linux's TCSBRK
    // ioctl with zero sends the break and has the same behavior for all
    // durations in musl.
    cabi_ioctl_value(fd, CABI_TCSBRK, 0)
}

#[no_mangle]
pub unsafe extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let mut pgrp: c_int = 0;
    if cabi_ioctl(fd, CABI_TIOCGPGRP, &mut pgrp as *mut c_int as *mut u8) < 0 {
        return -1;
    }
    pgrp
}

#[no_mangle]
pub unsafe extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    let mut pgrp = pgrp;
    cabi_ioctl(fd, CABI_TIOCSPGRP, &mut pgrp as *mut c_int as *mut u8)
}

#[no_mangle]
pub unsafe extern "C" fn tcgetsid(fd: c_int) -> c_int {
    let mut sid: c_int = 0;
    if cabi_ioctl(fd, CABI_TIOCGSID, &mut sid as *mut c_int as *mut u8) < 0 {
        return -1;
    }
    sid
}

#[no_mangle]
pub unsafe extern "C" fn cfgetospeed(tio: *const cabi_termios) -> c_uint {
    (*tio).c_cflag & CABI_CBAUD
}

#[no_mangle]
pub unsafe extern "C" fn cfgetispeed(tio: *const cabi_termios) -> c_uint {
    ((*tio).c_cflag & CABI_CIBAUD) / (CABI_CIBAUD / CABI_CBAUD)
}

#[no_mangle]
pub unsafe extern "C" fn cfsetospeed(tio: *mut cabi_termios, speed: c_uint) -> c_int {
    if speed & !CABI_CBAUD != 0 {
        ERRNO = EINVAL;
        return -1;
    }
    (*tio).c_cflag = ((*tio).c_cflag & !CABI_CBAUD) | speed;
    0
}

#[no_mangle]
pub unsafe extern "C" fn cfsetispeed(tio: *mut cabi_termios, speed: c_uint) -> c_int {
    if speed & !CABI_CBAUD != 0 {
        ERRNO = EINVAL;
        return -1;
    }
    (*tio).c_cflag = ((*tio).c_cflag & !CABI_CIBAUD)
        | speed * (CABI_CIBAUD / CABI_CBAUD);
    0
}

#[no_mangle]
pub unsafe extern "C" fn cfsetspeed(tio: *mut cabi_termios, speed: c_uint) -> c_int {
    let result = cfsetospeed(tio, speed);
    if result == 0 {
        // Linux represents an input speed of zero as "same as output".
        // This is the musl cfsetspeed contract, while preserving the
        // independently-set input rate supported by cfsetispeed.
        cfsetispeed(tio, 0);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn isastream(fd: c_int) -> c_int {
    // Linux has no STREAMS subsystem. musl still validates the descriptor so
    // callers receive EBADF for an invalid fd, as required by isastream(3).
    let result = syscall_result(sys_fcntl(fd, CABI_TERM_F_GETFD, 0));
    if result < 0 { -1 } else { 0 }
}

// Linux's devpts filesystem creates and owns the slave node when /dev/ptmx
// is opened.  The remaining PTY setup is still performed through the kernel
// ioctls rather than returning success for an arbitrary descriptor.
unsafe fn cabi_pty_number(fd: c_int, number: *mut c_int) -> c_int {
    let r = sys_ioctl(fd, CABI_TIOCGPTN, number as *mut u8);
    if r < 0 { (-r) as c_int } else { 0 }
}

unsafe fn cabi_pty_name_from_number(number: c_int, buf: *mut c_char, len: usize) -> c_int {
    // A Linux PTY number is a non-negative int.  The fixed buffer is large
    // enough for "/dev/pts/" plus every decimal int and its terminator.
    if number < 0 {
        return EIO_VAL;
    }
    let prefix = b"/dev/pts/";
    let mut name = [0u8; 32];
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), name.as_mut_ptr(), prefix.len());
    let mut digits = [0u8; 10];
    let mut value = number as u32;
    let mut digit_count = 0usize;
    loop {
        digits[digit_count] = b'0' + (value % 10) as u8;
        digit_count += 1;
        value /= 10;
        if value == 0 { break; }
    }
    let mut i = 0usize;
    while i < digit_count {
        name[prefix.len() + i] = digits[digit_count - i - 1];
        i += 1;
    }
    let name_len = prefix.len() + digit_count;

    // musl treats a null destination as a zero-length destination and
    // returns ERANGE after obtaining the kernel PTY number.
    if buf.is_null() || len <= name_len {
        return ERANGE_VAL;
    }
    core::ptr::copy_nonoverlapping(name.as_ptr(), buf as *mut u8, name_len);
    *buf.add(name_len) = 0;
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_openpt(flags: c_int) -> c_int {
    let r = sys_open(b"/dev/ptmx\0".as_ptr(), flags as i64, 0);
    if r < 0 {
        let mut error = (-r) as c_int;
        // Linux reports an exhausted PTY pool as ENOSPC; POSIX exposes this
        // resource-exhaustion case from posix_openpt as EAGAIN.
        if error == ENOSPC_VAL { error = EAGAIN; }
        ERRNO = error;
        return -1;
    }
    r as c_int
}

#[no_mangle]
pub unsafe extern "C" fn grantpt(fd: c_int) -> c_int {
    // devpts performs the grant operation during ptmx allocation.  Validate
    // that fd is in fact a PTY master so invalid/non-PTY descriptors do not
    // receive manufactured success.
    let mut number = 0;
    let error = cabi_pty_number(fd, &mut number);
    if error != 0 {
        ERRNO = error;
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn unlockpt(fd: c_int) -> c_int {
    let mut unlock: c_int = 0;
    let r = sys_ioctl(fd, CABI_TIOCSPTLCK, &mut unlock as *mut c_int as *mut u8);
    if r < 0 {
        ERRNO = (-r) as c_int;
        return -1;
    }
    0
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn ptsname_r(fd: c_int, buf: *mut c_char, len: usize) -> c_int {
    let mut number = 0;
    let error = cabi_pty_number(fd, &mut number);
    if error != 0 {
        return error;
    }
    cabi_pty_name_from_number(number, buf, len)
}

#[no_mangle]
pub unsafe extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    static mut NAME: [c_char; 32] = [0; 32];
    let name = core::ptr::addr_of_mut!(NAME).cast::<c_char>();
    let error = ptsname_r(fd, name, 32);
    if error != 0 {
        ERRNO = error;
        return core::ptr::null_mut();
    }
    name
}

unsafe fn cabi_openpty_error(master: c_int, slave: c_int, error: c_int) -> c_int {
    if slave >= 0 { sys_close(slave as i64); }
    if master >= 0 { sys_close(master as i64); }
    ERRNO = error;
    -1
}

#[no_mangle]
pub unsafe extern "C" fn openpty(
    master: *mut c_int,
    slave: *mut c_int,
    name: *mut c_char,
    tio: *const cabi_termios,
    ws: *const cabi_winsize,
) -> c_int {
    if master.is_null() || slave.is_null() {
        ERRNO = EINVAL;
        return -1;
    }

    let m = posix_openpt(CABI_PTY_O_RDWR | CABI_PTY_O_NOCTTY);
    if m < 0 { return -1; }
    if grantpt(m) < 0 {
        return cabi_openpty_error(m, -1, ERRNO);
    }
    if unlockpt(m) < 0 {
        return cabi_openpty_error(m, -1, ERRNO);
    }

    let mut slave_name = [0u8; 32];
    let name_error = ptsname_r(m, slave_name.as_mut_ptr() as *mut c_char, slave_name.len());
    if name_error != 0 {
        return cabi_openpty_error(m, -1, name_error);
    }
    let s = {
        let r = sys_open(slave_name.as_ptr(), (CABI_PTY_O_RDWR | CABI_PTY_O_NOCTTY) as i64, 0);
        if r < 0 {
            return cabi_openpty_error(m, -1, (-r) as c_int);
        }
        r as c_int
    };

    if !name.is_null() {
        // openpty has no destination-size argument; as with musl, callers
        // provide storage for the conventional /dev/pts/<number> spelling.
        let name_len = strlen(slave_name.as_ptr() as *const c_char) + 1;
        core::ptr::copy_nonoverlapping(slave_name.as_ptr(), name as *mut u8, name_len);
    }
    if !tio.is_null() && tcsetattr(s, 0, tio) < 0 {
        return cabi_openpty_error(m, s, ERRNO);
    }
    if !ws.is_null() && tcsetwinsize(s, ws) < 0 {
        return cabi_openpty_error(m, s, ERRNO);
    }
    *master = m;
    *slave = s;
    0
}

#[no_mangle]
pub unsafe extern "C" fn login_tty(fd: c_int) -> c_int {
    let r = sys_setsid();
    if r < 0 {
        ERRNO = (-r) as c_int;
        return -1;
    }
    let r = sys_ioctl(fd, CABI_TIOCSCTTY, core::ptr::null_mut());
    if r < 0 {
        ERRNO = (-r) as c_int;
        return -1;
    }
    let mut target = 0;
    while target < 3 {
        let r = sys_dup2(fd, target);
        if r < 0 {
            ERRNO = (-r) as c_int;
            return -1;
        }
        target += 1;
    }
    if fd > 2 { sys_close(fd as i64); }
    0
}

#[no_mangle]
pub unsafe extern "C" fn forkpty(
    master: *mut c_int,
    name: *mut c_char,
    tio: *const cabi_termios,
    ws: *const cabi_winsize,
) -> c_int {
    if master.is_null() {
        ERRNO = EINVAL;
        return -1;
    }
    let mut m = -1;
    let mut s = -1;
    if openpty(&mut m, &mut s, name, tio, ws) < 0 {
        return -1;
    }

    // The close-on-exec pipe lets the parent distinguish a child that
    // successfully completed login_tty (EOF) from one that failed setup
    // (the child writes its errno before exiting 127).
    let mut status_pipe = [0; 2];
    let pipe_result = sys_pipe2(status_pipe.as_mut_ptr(), CABI_PTY_O_CLOEXEC);
    if pipe_result < 0 {
        return cabi_openpty_error(m, s, (-pipe_result) as c_int);
    }

    let pid = fork();
    if pid < 0 {
        sys_close(status_pipe[0] as i64);
        sys_close(status_pipe[1] as i64);
        return cabi_openpty_error(m, s, ERRNO);
    }
    if pid == 0 {
        sys_close(m as i64);
        sys_close(status_pipe[0] as i64);
        if login_tty(s) < 0 {
            let error = ERRNO;
            let _ = sys_write(status_pipe[1] as i64, &error as *const c_int as *const u8, core::mem::size_of::<c_int>());
            _exit(127);
        }
        sys_close(status_pipe[1] as i64);
        return 0;
    }

    sys_close(s as i64);
    sys_close(status_pipe[1] as i64);
    let mut error = 0;
    let mut received = 0usize;
    while received < core::mem::size_of::<c_int>() {
        let r = sys_read(
            status_pipe[0] as i64,
            (&mut error as *mut c_int as *mut u8).add(received),
            core::mem::size_of::<c_int>() - received,
        );
        if r < 0 {
            let e = (-r) as c_int;
            if e == EINTR { continue; }
            sys_close(status_pipe[0] as i64);
            let mut ignored = 0;
            let _ = waitpid(pid, &mut ignored, 0);
            return cabi_openpty_error(m, -1, e);
        }
        if r == 0 { break; }
        received += r as usize;
    }
    sys_close(status_pipe[0] as i64);
    if received != 0 {
        let mut ignored = 0;
        let _ = waitpid(pid, &mut ignored, 0);
        return cabi_openpty_error(m, -1, if received == core::mem::size_of::<c_int>() { error } else { EIO_VAL });
    }
    *master = m;
    pid
}

#[no_mangle]
pub unsafe extern "C" fn cfmakeraw(tio: *mut cabi_termios) {
    (*tio).c_iflag &= !(0o0000001 | 0o0000002 | 0o0000010 | 0o0000040
        | 0o0000100 | 0o0000200 | 0o0000400 | 0o0002000);
    (*tio).c_oflag &= !0o0000001;
    (*tio).c_lflag &= !(0o0000010 | 0o0000100 | 0o0000002 | 0o0000001
        | 0o0100000);
    (*tio).c_cflag &= !(0o0000060 | 0o0000400);
    (*tio).c_cflag |= 0o0000060;
    (*tio).c_cc[6] = 1;
    (*tio).c_cc[5] = 0;
}
