// direct file-I/O and pipe-vector exports.
//
// Linux's vector and pipe syscalls are not present in the base syscall
// substrate yet, so this slice keeps their architecture syscall numbers and
// raw argument shaping local.  Public functions below are the C ABI boundary:
// Linux's negative errno convention is converted with syscall_result, while
// the POSIX advisory/allocation functions return an error number directly and
// therefore deliberately do not modify errno.
// process_vm_readv/writev use the same two-word iovec layout as the public
// sys/uio.h type, with unsigned-long vector counts as required by Linux.

const CABI_EINTR: c_int = 4;

#[repr(C)]
pub struct CabiIoVec {
    iov_base: *mut c_void,
    iov_len: SizeT,
}

#[cfg(target_arch = "x86_64")]
const CABI_SYS_READV: i64 = 19;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_WRITEV: i64 = 20;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_FADVISE64: i64 = 221;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_SENDFILE: i64 = 40;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_SPLICE: i64 = 275;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_TEE: i64 = 276;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_VMSPLICE: i64 = 278;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_FALLOCATE: i64 = 285;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_PREADV: i64 = 295;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_PWRITEV: i64 = 296;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_PREADV2: i64 = 327;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_PWRITEV2: i64 = 328;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_COPY_FILE_RANGE: i64 = 326;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_PROCESS_VM_READV: i64 = 310;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_PROCESS_VM_WRITEV: i64 = 311;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_READV: i64 = 65;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_WRITEV: i64 = 66;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_PREADV: i64 = 69;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_PWRITEV: i64 = 70;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_PREADV2: i64 = 286;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_PWRITEV2: i64 = 287;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_SENDFILE: i64 = 71;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_VMSPLICE: i64 = 75;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_SPLICE: i64 = 76;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_TEE: i64 = 77;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_FALLOCATE: i64 = 47;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_FADVISE64: i64 = 223;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_COPY_FILE_RANGE: i64 = 285;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_PROCESS_VM_READV: i64 = 270;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_PROCESS_VM_WRITEV: i64 = 271;

#[inline]
fn cabi_offset_parts(offset: c_long) -> (i64, i64) {
    let bits = offset as u64;
    ((bits as u32) as i64, (bits >> 32) as i64)
}

#[inline]
unsafe fn cabi_readv(fd: c_int, iov: *const CabiIoVec, iovcnt: c_int) -> i64 {
    <Arch as Syscalls>::syscall3(CABI_SYS_READV, fd as i64, iov as i64, iovcnt as i64)
}

#[inline]
unsafe fn cabi_writev(fd: c_int, iov: *const CabiIoVec, iovcnt: c_int) -> i64 {
    <Arch as Syscalls>::syscall3(CABI_SYS_WRITEV, fd as i64, iov as i64, iovcnt as i64)
}

#[inline]
unsafe fn cabi_preadv(fd: c_int, iov: *const CabiIoVec, iovcnt: c_int, offset: c_long) -> i64 {
    let (lo, hi) = cabi_offset_parts(offset);
    <Arch as Syscalls>::syscall5(
        CABI_SYS_PREADV,
        fd as i64,
        iov as i64,
        iovcnt as i64,
        lo,
        hi,
    )
}

#[inline]
unsafe fn cabi_pwritev(fd: c_int, iov: *const CabiIoVec, iovcnt: c_int, offset: c_long) -> i64 {
    let (lo, hi) = cabi_offset_parts(offset);
    <Arch as Syscalls>::syscall5(
        CABI_SYS_PWRITEV,
        fd as i64,
        iov as i64,
        iovcnt as i64,
        lo,
        hi,
    )
}

#[inline]
unsafe fn cabi_preadv2(
    fd: c_int,
    iov: *const CabiIoVec,
    iovcnt: c_int,
    offset: c_long,
    flags: c_int,
) -> i64 {
    if flags == 0 {
        if offset == -1 {
            return cabi_readv(fd, iov, iovcnt);
        }
        return cabi_preadv(fd, iov, iovcnt, offset);
    }
    let (lo, hi) = cabi_offset_parts(offset);
    <Arch as Syscalls>::syscall6(
        CABI_SYS_PREADV2,
        fd as i64,
        iov as i64,
        iovcnt as i64,
        lo,
        hi,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_pwritev2(
    fd: c_int,
    iov: *const CabiIoVec,
    iovcnt: c_int,
    offset: c_long,
    flags: c_int,
) -> i64 {
    if flags == 0 {
        if offset == -1 {
            return cabi_writev(fd, iov, iovcnt);
        }
        return cabi_pwritev(fd, iov, iovcnt, offset);
    }
    let (lo, hi) = cabi_offset_parts(offset);
    <Arch as Syscalls>::syscall6(
        CABI_SYS_PWRITEV2,
        fd as i64,
        iov as i64,
        iovcnt as i64,
        lo,
        hi,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_copy_file_range(
    fd_in: c_int,
    off_in: *mut c_long,
    fd_out: c_int,
    off_out: *mut c_long,
    len: SizeT,
    flags: c_uint,
) -> i64 {
    <Arch as Syscalls>::syscall6(
        CABI_SYS_COPY_FILE_RANGE,
        fd_in as i64,
        off_in as i64,
        fd_out as i64,
        off_out as i64,
        len as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_process_vm_readv(
    pid: c_int,
    local_iov: *const CabiIoVec,
    local_iovcnt: SizeT,
    remote_iov: *const CabiIoVec,
    remote_iovcnt: SizeT,
    flags: SizeT,
) -> i64 {
    <Arch as Syscalls>::syscall6(
        CABI_SYS_PROCESS_VM_READV,
        pid as i64,
        local_iov as i64,
        local_iovcnt as i64,
        remote_iov as i64,
        remote_iovcnt as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_process_vm_writev(
    pid: c_int,
    local_iov: *const CabiIoVec,
    local_iovcnt: SizeT,
    remote_iov: *const CabiIoVec,
    remote_iovcnt: SizeT,
    flags: SizeT,
) -> i64 {
    <Arch as Syscalls>::syscall6(
        CABI_SYS_PROCESS_VM_WRITEV,
        pid as i64,
        local_iov as i64,
        local_iovcnt as i64,
        remote_iov as i64,
        remote_iovcnt as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_sendfile(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut c_long,
    count: SizeT,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        CABI_SYS_SENDFILE,
        out_fd as i64,
        in_fd as i64,
        offset as i64,
        count as i64,
    )
}

#[inline]
unsafe fn cabi_splice(
    fd_in: c_int,
    off_in: *mut c_long,
    fd_out: c_int,
    off_out: *mut c_long,
    len: SizeT,
    flags: c_uint,
) -> i64 {
    <Arch as Syscalls>::syscall6(
        CABI_SYS_SPLICE,
        fd_in as i64,
        off_in as i64,
        fd_out as i64,
        off_out as i64,
        len as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_tee(fd_in: c_int, fd_out: c_int, len: SizeT, flags: c_uint) -> i64 {
    <Arch as Syscalls>::syscall4(
        CABI_SYS_TEE,
        fd_in as i64,
        fd_out as i64,
        len as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_vmsplice(
    fd: c_int,
    iov: *const CabiIoVec,
    nr_segs: SizeT,
    flags: c_uint,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        CABI_SYS_VMSPLICE,
        fd as i64,
        iov as i64,
        nr_segs as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_fallocate(fd: c_int, mode: c_int, offset: c_long, len: c_long) -> i64 {
    <Arch as Syscalls>::syscall4(
        CABI_SYS_FALLOCATE,
        fd as i64,
        mode as i64,
        offset as i64,
        len as i64,
    )
}

#[inline]
unsafe fn cabi_fadvise(fd: c_int, offset: c_long, len: c_long, advice: c_int) -> i64 {
    <Arch as Syscalls>::syscall4(
        CABI_SYS_FADVISE64,
        fd as i64,
        offset as i64,
        len as i64,
        advice as i64,
    )
}

#[inline]
fn cabi_posix_error(result: i64) -> c_int {
    if result < 0 && result >= -4095 {
        (-result) as c_int
    } else {
        result as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn readv(
    fd: c_int,
    iov: *const CabiIoVec,
    iovcnt: c_int,
) -> SSizeT {
    syscall_result(cabi_readv(fd, iov, iovcnt)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn writev(
    fd: c_int,
    iov: *const CabiIoVec,
    iovcnt: c_int,
) -> SSizeT {
    syscall_result(cabi_writev(fd, iov, iovcnt)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn preadv(
    fd: c_int,
    iov: *const CabiIoVec,
    iovcnt: c_int,
    offset: c_long,
) -> SSizeT {
    syscall_result(cabi_preadv(fd, iov, iovcnt, offset)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn pwritev(
    fd: c_int,
    iov: *const CabiIoVec,
    iovcnt: c_int,
    offset: c_long,
) -> SSizeT {
    syscall_result(cabi_pwritev(fd, iov, iovcnt, offset)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn preadv2(
    fd: c_int,
    iov: *const CabiIoVec,
    iovcnt: c_int,
    offset: c_long,
    flags: c_int,
) -> SSizeT {
    syscall_result(cabi_preadv2(fd, iov, iovcnt, offset, flags)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn pwritev2(
    fd: c_int,
    iov: *const CabiIoVec,
    iovcnt: c_int,
    offset: c_long,
    flags: c_int,
) -> SSizeT {
    syscall_result(cabi_pwritev2(fd, iov, iovcnt, offset, flags)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn copy_file_range(
    fd_in: c_int,
    off_in: *mut c_long,
    fd_out: c_int,
    off_out: *mut c_long,
    len: SizeT,
    flags: c_uint,
) -> SSizeT {
    syscall_result(cabi_copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn process_vm_readv(
    pid: c_int,
    local_iov: *const CabiIoVec,
    local_iovcnt: SizeT,
    remote_iov: *const CabiIoVec,
    remote_iovcnt: SizeT,
    flags: SizeT,
) -> SSizeT {
    syscall_result(cabi_process_vm_readv(
        pid,
        local_iov,
        local_iovcnt,
        remote_iov,
        remote_iovcnt,
        flags,
    )) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn process_vm_writev(
    pid: c_int,
    local_iov: *const CabiIoVec,
    local_iovcnt: SizeT,
    remote_iov: *const CabiIoVec,
    remote_iovcnt: SizeT,
    flags: SizeT,
) -> SSizeT {
    syscall_result(cabi_process_vm_writev(
        pid,
        local_iov,
        local_iovcnt,
        remote_iov,
        remote_iovcnt,
        flags,
    )) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn sendfile(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut c_long,
    count: SizeT,
) -> SSizeT {
    syscall_result(cabi_sendfile(out_fd, in_fd, offset, count)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn splice(
    fd_in: c_int,
    off_in: *mut c_long,
    fd_out: c_int,
    off_out: *mut c_long,
    len: SizeT,
    flags: c_uint,
) -> SSizeT {
    syscall_result(cabi_splice(fd_in, off_in, fd_out, off_out, len, flags)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn tee(
    fd_in: c_int,
    fd_out: c_int,
    len: SizeT,
    flags: c_uint,
) -> SSizeT {
    syscall_result(cabi_tee(fd_in, fd_out, len, flags)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn vmsplice(
    fd: c_int,
    iov: *const CabiIoVec,
    nr_segs: SizeT,
    flags: c_uint,
) -> SSizeT {
    syscall_result(cabi_vmsplice(fd, iov, nr_segs, flags)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn fallocate(
    fd: c_int,
    mode: c_int,
    offset: c_long,
    len: c_long,
) -> c_int {
    syscall_result(cabi_fallocate(fd, mode, offset, len)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn posix_fallocate(
    fd: c_int,
    offset: c_long,
    len: c_long,
) -> c_int {
    cabi_posix_error(cabi_fallocate(fd, 0, offset, len))
}

#[no_mangle]
pub unsafe extern "C" fn posix_fadvise(
    fd: c_int,
    offset: c_long,
    len: c_long,
    advice: c_int,
) -> c_int {
    cabi_posix_error(cabi_fadvise(fd, offset, len, advice))
}

#[no_mangle]
pub unsafe extern "C" fn posix_close(fd: c_int, _flags: c_int) -> c_int {
    // musl's close-equivalent treats Linux EINTR as success: Linux has
    // already released the descriptor when close reports that interruption.
    let result = sys_close(fd as i64);
    if result == -(CABI_EINTR as i64) {
        0
    } else {
        syscall_result(result) as c_int
    }
}
