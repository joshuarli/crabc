// M4 POSIX/XSI signal helpers.
//
// The main signal implementation uses the Linux kernel's one-word mask for
// syscalls (`SigSetT`), while the public C ABI reserves 128 bytes for
// `sigset_t`.  musl's GNU set operations intentionally operate on the one
// word needed for its 65-signal ABI (`_NSIG / 8 / sizeof(long)`); the legacy
// mask-changing helpers use the same existing one-word signal entry points.

const M4_NSIG: usize = 65;
const M4_SIGSET_WORDS: usize = M4_NSIG / 8 / core::mem::size_of::<c_ulong>();

#[inline]
unsafe fn m4_sigset_words(set: *const SigSetT) -> *const c_ulong {
    set as *const c_ulong
}

#[inline]
unsafe fn m4_sigset_words_mut(set: *mut SigSetT) -> *mut c_ulong {
    set as *mut c_ulong
}

#[no_mangle]
pub unsafe extern "C" fn sigandset(
    dest: *mut SigSetT,
    left: *const SigSetT,
    right: *const SigSetT,
) -> c_int {
    let d = m4_sigset_words_mut(dest);
    let l = m4_sigset_words(left);
    let r = m4_sigset_words(right);
    let mut i = 0usize;
    while i < M4_SIGSET_WORDS {
        *d.add(i) = *l.add(i) & *r.add(i);
        i += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigorset(
    dest: *mut SigSetT,
    left: *const SigSetT,
    right: *const SigSetT,
) -> c_int {
    let d = m4_sigset_words_mut(dest);
    let l = m4_sigset_words(left);
    let r = m4_sigset_words(right);
    let mut i = 0usize;
    while i < M4_SIGSET_WORDS {
        *d.add(i) = *l.add(i) | *r.add(i);
        i += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigisemptyset(set: *const SigSetT) -> c_int {
    let words = m4_sigset_words(set);
    let mut i = 0usize;
    while i < M4_SIGSET_WORDS {
        if *words.add(i) != 0 {
            return 0;
        }
        i += 1;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn sighold(sig: c_int) -> c_int {
    let mut mask: SigSetT = 0;
    if sigaddset(&mut mask, sig) < 0 {
        return -1;
    }
    sigprocmask(SIG_BLOCK, &mask, core::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn sigrelse(sig: c_int) -> c_int {
    let mut mask: SigSetT = 0;
    if sigaddset(&mut mask, sig) < 0 {
        return -1;
    }
    sigprocmask(SIG_UNBLOCK, &mask, core::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn sigpause(sig: c_int) -> c_int {
    let mut mask: SigSetT = 0;
    // XSI sigpause atomically waits with the current mask minus `sig`.
    if sigprocmask(0, core::ptr::null(), &mut mask) < 0 {
        return -1;
    }
    if sigdelset(&mut mask, sig) < 0 {
        return -1;
    }
    sigsuspend(&mask)
}

#[no_mangle]
pub unsafe extern "C" fn siginterrupt(sig: c_int, flag: c_int) -> c_int {
    let mut action: sigaction = core::mem::zeroed();
    if sigaction(sig, core::ptr::null(), &mut action) < 0 {
        return -1;
    }
    if flag != 0 {
        action.sa_flags &= !(SA_RESTART as c_int);
    } else {
        action.sa_flags |= SA_RESTART as c_int;
    }
    sigaction(sig, &action, core::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn sigignore(sig: c_int) -> c_int {
    let action = sigaction {
        sa_handler: SIG_IGN,
        sa_flags: 0,
        __sa_flags_padding: 0,
        sa_restorer: 0,
        sa_mask: [0; PUBLIC_SIGSET_WORDS],
    };
    sigaction(sig, &action, core::ptr::null_mut())
}

const M4_SIG_HOLD: usize = 2;

#[no_mangle]
pub unsafe extern "C" fn sigset(sig: c_int, handler: usize) -> usize {
    let mut mask: SigSetT = 0;
    let mut old_mask: SigSetT = 0;
    if sigemptyset(&mut mask) < 0 || sigaddset(&mut mask, sig) < 0 {
        return SIG_ERR;
    }

    let mut old_action: sigaction = core::mem::zeroed();
    if handler == M4_SIG_HOLD {
        if sigaction(sig, core::ptr::null(), &mut old_action) < 0 {
            return SIG_ERR;
        }
        if sigprocmask(SIG_BLOCK, &mask, &mut old_mask) < 0 {
            return SIG_ERR;
        }
    } else {
        let action = sigaction {
            sa_handler: handler,
            sa_flags: 0,
            __sa_flags_padding: 0,
            sa_restorer: 0,
            sa_mask: [0; PUBLIC_SIGSET_WORDS],
        };
        if sigaction(sig, &action, &mut old_action) < 0 {
            return SIG_ERR;
        }
        if sigprocmask(SIG_UNBLOCK, &mask, &mut old_mask) < 0 {
            return SIG_ERR;
        }
    }

    if sigismember(&old_mask, sig) != 0 {
        M4_SIG_HOLD
    } else {
        old_action.sa_handler
    }
}

// Linux rt_sigqueueinfo is not used by the existing signal wrappers, so keep
// its architecture-specific number local to this vertical slice.
#[cfg(target_arch = "x86_64")]
const M4_SYS_RT_SIGQUEUEINFO: i64 = 129;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_RT_SIGQUEUEINFO: i64 = 138;

#[repr(C)]
pub union M4Sigval {
    pub sival_int: c_int,
    pub sival_ptr: *mut c_void,
}

#[inline]
unsafe fn m4_rt_sigqueueinfo(pid: c_int, sig: c_int, info: *const u8) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_RT_SIGQUEUEINFO,
        pid as i64,
        sig as i64,
        info as i64,
    )
}

#[inline]
unsafe fn m4_siginfo_write_i32(info: &mut [u8; 128], offset: usize, value: c_int) {
    core::ptr::write_unaligned(info.as_mut_ptr().add(offset) as *mut c_int, value);
}

#[no_mangle]
pub unsafe extern "C" fn sigqueue(pid: c_int, sig: c_int, value: M4Sigval) -> c_int {
    let mut info = [0u8; 128];
    // Linux's siginfo_t common/rt fields are: signo at 0, code at 8,
    // sender pid/uid at 12/16, and sigval at 20.
    m4_siginfo_write_i32(&mut info, 0, sig);
    m4_siginfo_write_i32(&mut info, 8, -1); // SI_QUEUE
    m4_siginfo_write_i32(&mut info, 12, getpid());
    core::ptr::write_unaligned(
        info.as_mut_ptr().add(16) as *mut c_uint,
        getuid(),
    );
    core::ptr::copy_nonoverlapping(
        &value as *const M4Sigval as *const u8,
        info.as_mut_ptr().add(20),
        core::mem::size_of::<M4Sigval>(),
    );
    syscall_result(m4_rt_sigqueueinfo(pid, sig, info.as_ptr())) as c_int
}

static M4_SIGNAL_NAMES: [&[u8]; 65] = [
    b"Unknown signal\0",
    b"Hangup\0",
    b"Interrupt\0",
    b"Quit\0",
    b"Illegal instruction\0",
    b"Trace/breakpoint trap\0",
    b"Aborted\0",
    b"Bus error\0",
    b"Arithmetic exception\0",
    b"Killed\0",
    b"User defined signal 1\0",
    b"Segmentation fault\0",
    b"User defined signal 2\0",
    b"Broken pipe\0",
    b"Alarm clock\0",
    b"Terminated\0",
    b"Stack fault\0",
    b"Child process status\0",
    b"Continued\0",
    b"Stopped (signal)\0",
    b"Stopped\0",
    b"Stopped (tty input)\0",
    b"Stopped (tty output)\0",
    b"Urgent I/O condition\0",
    b"CPU time limit exceeded\0",
    b"File size limit exceeded\0",
    b"Virtual timer expired\0",
    b"Profiling timer expired\0",
    b"Window changed\0",
    b"I/O possible\0",
    b"Power failure\0",
    b"Bad system call\0",
    b"RT32\0",
    b"RT33\0",
    b"RT34\0",
    b"RT35\0",
    b"RT36\0",
    b"RT37\0",
    b"RT38\0",
    b"RT39\0",
    b"RT40\0",
    b"RT41\0",
    b"RT42\0",
    b"RT43\0",
    b"RT44\0",
    b"RT45\0",
    b"RT46\0",
    b"RT47\0",
    b"RT48\0",
    b"RT49\0",
    b"RT50\0",
    b"RT51\0",
    b"RT52\0",
    b"RT53\0",
    b"RT54\0",
    b"RT55\0",
    b"RT56\0",
    b"RT57\0",
    b"RT58\0",
    b"RT59\0",
    b"RT60\0",
    b"RT61\0",
    b"RT62\0",
    b"RT63\0",
    b"RT64\0",
];

#[no_mangle]
pub unsafe extern "C" fn strsignal(signum: c_int) -> *mut c_char {
    let index = if signum > 0 && signum < M4_SIGNAL_NAMES.len() as c_int {
        signum as usize
    } else {
        0
    };
    M4_SIGNAL_NAMES[index].as_ptr() as *mut c_char
}

#[no_mangle]
pub unsafe extern "C" fn psignal(sig: c_int, msg: *const c_char) {
    let fd = (*stderr).fd;
    if !msg.is_null() {
        write_str(fd, msg as *const u8, strlen(msg));
        write_str(fd, b": ".as_ptr(), 2);
    }
    let description = strsignal(sig);
    write_str(fd, description as *const u8, strlen(description));
    write_str(fd, b"\n".as_ptr(), 1);
}
