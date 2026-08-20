// POSIX message queues backed by Linux's mq_* syscalls.
//
// Linux exposes mq_open(2), mq_unlink(2), mq_timedsend(2),
// mq_timedreceive(2), mq_notify(2), and mq_getsetattr(2).  The non-timed
// POSIX entry points are libc conveniences over the corresponding timed
// syscalls with a null timeout.  Keep the kernel's negative-errno result
// private and use syscall_result at the C ABI boundary.

#[cfg(target_arch = "x86_64")]
const M4_SYS_MQ_OPEN: i64 = 240;
#[cfg(target_arch = "x86_64")]
const M4_SYS_MQ_UNLINK: i64 = 241;
#[cfg(target_arch = "x86_64")]
const M4_SYS_MQ_TIMEDSEND: i64 = 242;
#[cfg(target_arch = "x86_64")]
const M4_SYS_MQ_TIMEDRECEIVE: i64 = 243;
#[cfg(target_arch = "x86_64")]
const M4_SYS_MQ_NOTIFY: i64 = 244;
#[cfg(target_arch = "x86_64")]
const M4_SYS_MQ_GETSETATTR: i64 = 245;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MQ_OPEN: i64 = 180;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MQ_UNLINK: i64 = 181;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MQ_TIMEDSEND: i64 = 182;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MQ_TIMEDRECEIVE: i64 = 183;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MQ_NOTIFY: i64 = 184;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MQ_GETSETATTR: i64 = 185;

// struct mq_attr is four long values followed by four reserved long values
// on all supported 64-bit Linux ABIs.  The kernel only consumes the first
// four values and preserves the reserved tail when copying the structure.
#[repr(C)]
pub struct M4MqAttr {
    pub mq_flags: c_long,
    pub mq_maxmsg: c_long,
    pub mq_msgsize: c_long,
    pub mq_curmsgs: c_long,
    pub __reserved: [c_long; 4],
}

#[inline]
unsafe fn m4_mq_open(
    name: *const c_char,
    oflag: c_int,
    mode: mode_t,
    attr: *const M4MqAttr,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_MQ_OPEN,
        name as i64,
        oflag as i64,
        mode as i64,
        attr as i64,
    )
}

// POSIX queue names have one leading slash, but the Linux mq syscalls expect
// the namespace component without it.  Passing the public spelling directly
// reaches the kernel's filesystem-style path check and spuriously returns
// EACCES.  Validate the POSIX form before making that translation.
unsafe fn m4_mq_kernel_name(name: *const c_char) -> *const c_char {
    if name.is_null() {
        return name;
    }
    if *name as u8 != b'/' || *name.add(1) == 0 {
        ERRNO = EINVAL;
        return core::ptr::null();
    }
    let mut byte = name.add(1);
    while *byte != 0 {
        if *byte as u8 == b'/' {
            ERRNO = EINVAL;
            return core::ptr::null();
        }
        byte = byte.add(1);
    }
    name.add(1)
}

#[inline]
unsafe fn m4_mq_unlink(name: *const c_char) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_MQ_UNLINK, name as i64)
}

#[inline]
unsafe fn m4_mq_timedsend(
    mqdes: c_int,
    msg_ptr: *const c_char,
    msg_len: SizeT,
    msg_prio: c_uint,
    abs_timeout: *const timespec,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        M4_SYS_MQ_TIMEDSEND,
        mqdes as i64,
        msg_ptr as i64,
        msg_len as i64,
        msg_prio as i64,
        abs_timeout as i64,
    )
}

#[inline]
unsafe fn m4_mq_timedreceive(
    mqdes: c_int,
    msg_ptr: *mut c_char,
    msg_len: SizeT,
    msg_prio: *mut c_uint,
    abs_timeout: *const timespec,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        M4_SYS_MQ_TIMEDRECEIVE,
        mqdes as i64,
        msg_ptr as i64,
        msg_len as i64,
        msg_prio as i64,
        abs_timeout as i64,
    )
}

#[inline]
unsafe fn m4_mq_notify(mqdes: c_int, notification: *const c_void) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_MQ_NOTIFY, mqdes as i64, notification as i64)
}

#[inline]
unsafe fn m4_mq_getsetattr(
    mqdes: c_int,
    new_attr: *const M4MqAttr,
    old_attr: *mut M4MqAttr,
) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_MQ_GETSETATTR,
        mqdes as i64,
        new_attr as i64,
        old_attr as i64,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mq_open(
    name: *const c_char,
    oflag: c_int,
    mut args: ...,
) -> c_int {
    // POSIX mq_open has mode and attr varargs only when O_CREAT is present.
    // Do not consume absent arguments: callers that omit O_CREAT use the
    // ordinary two-argument ABI and the remaining registers are unspecified.
    let (mode, attr) = if oflag & O_CREAT != 0 {
        (
            args.next_arg::<mode_t>(),
            args.next_arg::<*const M4MqAttr>(),
        )
    } else {
        (0, core::ptr::null())
    };
    let kernel_name = m4_mq_kernel_name(name);
    if !name.is_null() && kernel_name.is_null() {
        return -1;
    }
    syscall_result(m4_mq_open(kernel_name, oflag, mode, attr)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mq_close(mqdes: c_int) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall1(SYS_CLOSE, mqdes as i64)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    let kernel_name = m4_mq_kernel_name(name);
    if !name.is_null() && kernel_name.is_null() {
        return -1;
    }
    syscall_result(m4_mq_unlink(kernel_name)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mq_send(
    mqdes: c_int,
    msg_ptr: *const c_char,
    msg_len: SizeT,
    msg_prio: c_uint,
) -> c_int {
    syscall_result(m4_mq_timedsend(
        mqdes,
        msg_ptr,
        msg_len,
        msg_prio,
        core::ptr::null(),
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mq_timedsend(
    mqdes: c_int,
    msg_ptr: *const c_char,
    msg_len: SizeT,
    msg_prio: c_uint,
    abs_timeout: *const timespec,
) -> c_int {
    syscall_result(m4_mq_timedsend(
        mqdes,
        msg_ptr,
        msg_len,
        msg_prio,
        abs_timeout,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mq_receive(
    mqdes: c_int,
    msg_ptr: *mut c_char,
    msg_len: SizeT,
    msg_prio: *mut c_uint,
) -> SSizeT {
    syscall_result(m4_mq_timedreceive(
        mqdes,
        msg_ptr,
        msg_len,
        msg_prio,
        core::ptr::null(),
    )) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn mq_timedreceive(
    mqdes: c_int,
    msg_ptr: *mut c_char,
    msg_len: SizeT,
    msg_prio: *mut c_uint,
    abs_timeout: *const timespec,
) -> SSizeT {
    syscall_result(m4_mq_timedreceive(
        mqdes,
        msg_ptr,
        msg_len,
        msg_prio,
        abs_timeout,
    )) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn mq_getattr(mqdes: c_int, attr: *mut M4MqAttr) -> c_int {
    syscall_result(m4_mq_getsetattr(
        mqdes,
        core::ptr::null(),
        attr,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mq_setattr(
    mqdes: c_int,
    new_attr: *const M4MqAttr,
    old_attr: *mut M4MqAttr,
) -> c_int {
    syscall_result(m4_mq_getsetattr(mqdes, new_attr, old_attr)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mq_notify(mqdes: c_int, notification: *const c_void) -> c_int {
    syscall_result(m4_mq_notify(mqdes, notification)) as c_int
}
