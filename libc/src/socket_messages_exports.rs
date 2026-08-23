// socket-message exports.
//
// Linux's 64-bit socket syscalls use a kernel msghdr whose iovlen and
// controllen fields are native longs.  musl's public ABI keeps those fields
// as 32-bit values and places an explicit padding word after each one.  The
// layouts therefore agree only when the padding words are present and zero.
// Keep the ABI adapter here rather than passing an uninitialised public
// msghdr directly to the kernel.


const CABI_SYS_ACCEPT4: i64 = 242;


const CABI_SYS_GETPEERNAME: i64 = 205;


const CABI_SYS_GETSOCKOPT: i64 = 209;


const CABI_SYS_SENDMSG: i64 = 211;


const CABI_SYS_RECVMSG: i64 = 212;


const CABI_SYS_RECVMMSG: i64 = 243;


const CABI_SYS_IOCTL: i64 = 29;

// Linux's IOV_MAX, and the bound used by musl's 64-bit sendmmsg path.
const CABI_IOV_MAX: c_uint = 1024;
const CABI_CMSG_ALIGN: usize = 8;
const CABI_CMSG_HDR_SIZE: usize = 16;
// CMSG_SPACE(255 * sizeof(int)) + one header, rounded to a usize word.
const CABI_SEND_CONTROL_WORDS: usize = 132;

#[repr(C)]
struct CabiMsghdr {
    msg_name: *mut c_void,
    msg_namelen: c_uint,
    msg_iov: *mut c_void,
    msg_iovlen: c_int,
    // musl's little-endian 64-bit ABI padding after msg_iovlen.
    msg_iovlen_pad: c_int,
    msg_control: *mut c_void,
    msg_controllen: c_uint,
    // musl's little-endian 64-bit ABI padding after msg_controllen.
    msg_controllen_pad: c_int,
    msg_flags: c_int,
}

#[repr(C)]
struct CabiMmsghdr {
    msg_hdr: CabiMsghdr,
    msg_len: c_uint,
}

#[inline]
fn cabi_cmsg_align(length: usize) -> usize {
    length.wrapping_add(CABI_CMSG_ALIGN - 1) & !(CABI_CMSG_ALIGN - 1)
}

// Zero the high word of every cmsghdr length in a copied send buffer.  A
// malformed header is left for the kernel to reject; stopping here avoids
// reading past the caller's declared control buffer.
unsafe fn cabi_zero_cmsg_padding(control: *mut u8, length: usize) {
    let mut offset = 0usize;
    while offset + CABI_CMSG_HDR_SIZE <= length {
        core::ptr::write_unaligned(
            control.add(offset + core::mem::size_of::<c_uint>()) as *mut c_uint,
            0,
        );
        let cmsg_len = core::ptr::read_unaligned(control.add(offset) as *const c_uint) as usize;
        if cmsg_len < CABI_CMSG_HDR_SIZE {
            break;
        }
        let next = cabi_cmsg_align(cmsg_len);
        if next == 0 || next > length - offset {
            break;
        }
        offset += next;
    }
}

// Prepare one outgoing msghdr in a kernel-compatible temporary.  The
// temporary control buffer is deliberately bounded to musl's SCM_RIGHTS
// maximum (255 descriptors), which is also the bound used by musl itself.
unsafe fn cabi_sendmsg_raw(fd: c_int, msg: *const c_void, flags: c_int) -> i64 {
    if msg.is_null() {
        return aarch64::syscall::syscall3(CABI_SYS_SENDMSG, fd as i64, 0, flags as i64);
    }

    let mut header: CabiMsghdr;
    let mut control_words = [0usize; CABI_SEND_CONTROL_WORDS];

    header = core::ptr::read_unaligned(msg as *const CabiMsghdr);
    header.msg_iovlen_pad = 0;
    header.msg_controllen_pad = 0;
    if header.msg_controllen != 0 {
        let length = header.msg_controllen as usize;
        let capacity = control_words.len() * core::mem::size_of::<usize>();
        if length > capacity {
            return -(ENOMEM as i64);
        }
        let control = control_words.as_mut_ptr() as *mut u8;
        core::ptr::copy_nonoverlapping(
            header.msg_control as *const u8,
            control,
            length,
        );
        cabi_zero_cmsg_padding(control, length);
        header.msg_control = control as *mut c_void;
    }

    aarch64::syscall::syscall3(
        CABI_SYS_SENDMSG,
        fd as i64,
        &header as *const CabiMsghdr as i64,
        flags as i64,
    )
}

unsafe fn cabi_recvmsg_raw(fd: c_int, msg: *mut c_void, flags: c_int) -> i64 {
    if msg.is_null() {
        return aarch64::syscall::syscall3(CABI_SYS_RECVMSG, fd as i64, 0, flags as i64);
    }

    let mut header = core::ptr::read_unaligned(msg as *const CabiMsghdr);
    header.msg_iovlen_pad = 0;
    header.msg_controllen_pad = 0;
    let result = aarch64::syscall::syscall3(
        CABI_SYS_RECVMSG,
        fd as i64,
        &mut header as *mut CabiMsghdr as i64,
        flags as i64,
    );
    // musl preserves kernel-updated namelen, controllen, and msg_flags even
    // when the syscall reports an error, so copy the temporary back on both
    // paths.
    core::ptr::write_unaligned(msg as *mut CabiMsghdr, header);
    result
}

#[no_mangle]
pub unsafe extern "C" fn accept4(
    fd: c_int,
    addr: *mut c_void,
    len: *mut c_uint,
    flags: c_int,
) -> c_int {
    syscall_result(aarch64::syscall::syscall4(
        CABI_SYS_ACCEPT4,
        fd as i64,
        addr as i64,
        len as i64,
        flags as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getpeername(
    fd: c_int,
    addr: *mut c_void,
    len: *mut c_uint,
) -> c_int {
    syscall_result(aarch64::syscall::syscall3(
        CABI_SYS_GETPEERNAME,
        fd as i64,
        addr as i64,
        len as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut c_uint,
) -> c_int {
    syscall_result(aarch64::syscall::syscall5(
        CABI_SYS_GETSOCKOPT,
        fd as i64,
        level as i64,
        optname as i64,
        optval as i64,
        optlen as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sendmsg(
    fd: c_int,
    msg: *const c_void,
    flags: c_int,
) -> SSizeT {
    syscall_result(cabi_sendmsg_raw(fd, msg, flags)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn recvmsg(
    fd: c_int,
    msg: *mut c_void,
    flags: c_int,
) -> SSizeT {
    syscall_result(cabi_recvmsg_raw(fd, msg, flags)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn sendmmsg(
    fd: c_int,
    msgvec: *mut c_void,
    vlen: c_uint,
    flags: c_uint,
) -> c_int {
    let count = if vlen > CABI_IOV_MAX { CABI_IOV_MAX } else { vlen };
    let messages = msgvec as *mut CabiMmsghdr;
    let mut sent = 0u32;
    while sent < count {
        let message = messages.add(sent as usize);
        let result = cabi_sendmsg_raw(
            fd,
            &(*message).msg_hdr as *const CabiMsghdr as *const c_void,
            flags as c_int,
        );
        if result < 0 {
            // sendmmsg reports the number already sent, but sendmsg's errno
            // contract still applies to the failed element.
            let _ = syscall_result(result);
            if sent == 0 {
                return -1;
            }
            return sent as c_int;
        }
        (*message).msg_len = result as c_uint;
        sent += 1;
    }
    sent as c_int
}

#[no_mangle]
pub unsafe extern "C" fn recvmmsg(
    fd: c_int,
    msgvec: *mut c_void,
    vlen: c_uint,
    flags: c_uint,
    timeout: *mut c_void,
) -> c_int {
    let count = if vlen > CABI_IOV_MAX { CABI_IOV_MAX } else { vlen };
    let messages = msgvec as *mut CabiMmsghdr;
    // The kernel writes native-size fields.  Clear the public ABI padding
    // before entering it so each header has the same layout as a native one.
    let mut index = 0u32;
    while index < count {
        let header = &mut (*messages.add(index as usize)).msg_hdr;
        header.msg_iovlen_pad = 0;
        header.msg_controllen_pad = 0;
        index += 1;
    }
    syscall_result(aarch64::syscall::syscall5(
        CABI_SYS_RECVMMSG,
        fd as i64,
        messages as i64,
        count as i64,
        flags as i64,
        timeout as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sockatmark(fd: c_int) -> c_int {
    let mut at_mark = 0 as c_int;
    let result = aarch64::syscall::syscall3(
        CABI_SYS_IOCTL,
        fd as i64,
        0x8905,
        &mut at_mark as *mut c_int as i64,
    );
    if syscall_result(result) < 0 {
        -1
    } else {
        at_mark
    }
}
