// M4 Linux administrative and kernel-interface exports.
//
// These are deliberately thin syscall adapters.  The kernel owns the
// namespace, process-personality, synchronization, and statx semantics;
// syscall_result only translates Linux's negative errno convention at the
// public C ABI boundary.
// prlimit uses Linux's prlimit64 entry point on both supported 64-bit ABIs;
// its rlimit64 layout is identical to the public 64-bit struct rlimit here.
// The reboot libc entry point likewise supplies Linux's two magic values;
// umount is the flagless umount2 operation because Linux exposes no separate
// modern umount syscall on these ABIs.

#[cfg(target_arch = "x86_64")]
const M4_SYS_PRCTL: i64 = 157;
#[cfg(target_arch = "x86_64")]
const M4_SYS_PERSONALITY: i64 = 135;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SETNS: i64 = 308;
#[cfg(target_arch = "x86_64")]
const M4_SYS_UNSHARE: i64 = 272;
#[cfg(target_arch = "x86_64")]
const M4_SYS_MEMBARRIER: i64 = 324;
#[cfg(target_arch = "x86_64")]
const M4_SYS_MEMFD_CREATE: i64 = 319;
#[cfg(target_arch = "x86_64")]
const M4_SYS_READAHEAD: i64 = 187;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SYNC_FILE_RANGE: i64 = 277;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SYNCFS: i64 = 306;
#[cfg(target_arch = "x86_64")]
const M4_SYS_STATX: i64 = 332;
#[cfg(target_arch = "x86_64")]
const M4_SYS_PRLIMIT64: i64 = 302;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SYSLOG: i64 = 103;
#[cfg(target_arch = "x86_64")]
const M4_SYS_VHANGUP: i64 = 153;
#[cfg(target_arch = "x86_64")]
const M4_SYS_PIVOT_ROOT: i64 = 155;
#[cfg(target_arch = "x86_64")]
const M4_SYS_ACCT: i64 = 163;
#[cfg(target_arch = "x86_64")]
const M4_SYS_MOUNT: i64 = 165;
#[cfg(target_arch = "x86_64")]
const M4_SYS_UMOUNT2: i64 = 166;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SWAPON: i64 = 167;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SWAPOFF: i64 = 168;
#[cfg(target_arch = "x86_64")]
const M4_SYS_REBOOT: i64 = 169;
#[cfg(target_arch = "x86_64")]
const M4_SYS_INIT_MODULE: i64 = 175;
#[cfg(target_arch = "x86_64")]
const M4_SYS_DELETE_MODULE: i64 = 176;
#[cfg(target_arch = "x86_64")]
const M4_SYS_QUOTACTL: i64 = 179;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_PRCTL: i64 = 167;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_PERSONALITY: i64 = 92;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SETNS: i64 = 268;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_UNSHARE: i64 = 97;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MEMBARRIER: i64 = 283;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MEMFD_CREATE: i64 = 279;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_READAHEAD: i64 = 213;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SYNC_FILE_RANGE: i64 = 84;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SYNCFS: i64 = 267;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_STATX: i64 = 291;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_PRLIMIT64: i64 = 261;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_UMOUNT2: i64 = 39;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_MOUNT: i64 = 40;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_PIVOT_ROOT: i64 = 41;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_VHANGUP: i64 = 58;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_QUOTACTL: i64 = 60;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_ACCT: i64 = 89;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_INIT_MODULE: i64 = 105;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_DELETE_MODULE: i64 = 106;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SYSLOG: i64 = 116;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_REBOOT: i64 = 142;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SWAPON: i64 = 224;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SWAPOFF: i64 = 225;

const M4_LINUX_REBOOT_MAGIC1: i64 = 0xfee1dead;
const M4_LINUX_REBOOT_MAGIC2: i64 = 672274793;

// prctl options whose argument count is observable at this ABI boundary.
// Linux ignores the unused trailing syscall registers, so known one-argument
// and zero-argument operations can avoid reading absent C varargs.  Unknown
// operations retain the four-argument ABI used by musl's prctl wrapper.
const M4_PR_GET_DUMPABLE: c_int = 3;
const M4_PR_GET_NAME: c_int = 16;
const M4_PR_SET_NAME: c_int = 15;
const M4_PR_SET_NO_NEW_PRIVS: c_int = 38;
const M4_PR_GET_NO_NEW_PRIVS: c_int = 39;

#[inline]
unsafe fn m4_prctl(option: c_int, args: &mut VaList) -> i64 {
    let argc = match option {
        M4_PR_GET_DUMPABLE | M4_PR_GET_NO_NEW_PRIVS => 0,
        M4_PR_GET_NAME | M4_PR_SET_NAME | M4_PR_SET_NO_NEW_PRIVS => 1,
        _ => 4,
    };
    let mut values = [0u64; 4];
    let mut index = 0;
    while index < argc {
        // musl's prctl implementation reads unsigned-long varargs before
        // forwarding them.  Pointers and integer arguments have the same
        // register representation on the supported 64-bit ABIs.
        values[index] = args.next_arg::<c_ulong>();
        index += 1;
    }
    <Arch as Syscalls>::syscall5(
        M4_SYS_PRCTL,
        option as i64,
        values[0] as i64,
        values[1] as i64,
        values[2] as i64,
        values[3] as i64,
    )
}

#[inline]
unsafe fn m4_personality(persona: c_ulong) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_PERSONALITY, persona as i64)
}

#[inline]
unsafe fn m4_setns(fd: c_int, nstype: c_int) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_SETNS, fd as i64, nstype as i64)
}

#[inline]
unsafe fn m4_unshare(flags: c_int) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_UNSHARE, flags as i64)
}

#[inline]
unsafe fn m4_membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_MEMBARRIER,
        cmd as i64,
        flags as i64,
        cpu_id as i64,
    )
}

#[inline]
unsafe fn m4_memfd_create(name: *const c_char, flags: c_uint) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_MEMFD_CREATE, name as i64, flags as i64)
}

#[inline]
unsafe fn m4_readahead(fd: c_int, offset: i64, count: SizeT) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_READAHEAD,
        fd as i64,
        offset,
        count as i64,
    )
}

#[inline]
unsafe fn m4_sync_file_range(fd: c_int, offset: i64, nbytes: i64, flags: c_uint) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_SYNC_FILE_RANGE,
        fd as i64,
        offset,
        nbytes,
        flags as i64,
    )
}

#[inline]
unsafe fn m4_syncfs(fd: c_int) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_SYNCFS, fd as i64)
}

#[inline]
unsafe fn m4_statx(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mask: c_uint,
    buffer: *mut c_void,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        M4_SYS_STATX,
        dirfd as i64,
        path as i64,
        flags as i64,
        mask as i64,
        buffer as i64,
    )
}

#[inline]
unsafe fn m4_prlimit(
    pid: c_int,
    resource: c_int,
    new_limit: *const Rlimit,
    old_limit: *mut Rlimit,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_PRLIMIT64,
        pid as i64,
        resource as i64,
        new_limit as i64,
        old_limit as i64,
    )
}

#[inline]
unsafe fn m4_acct(path: *const c_char) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_ACCT, path as i64)
}

#[inline]
unsafe fn m4_delete_module(name: *const c_char, flags: c_uint) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_DELETE_MODULE, name as i64, flags as i64)
}

#[inline]
unsafe fn m4_init_module(
    module_image: *mut c_void,
    len: SizeT,
    param_values: *const c_char,
) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_INIT_MODULE,
        module_image as i64,
        len as i64,
        param_values as i64,
    )
}

#[inline]
unsafe fn m4_klogctl(syslog_type: c_int, buffer: *mut c_char, len: c_int) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_SYSLOG,
        syslog_type as i64,
        buffer as i64,
        len as i64,
    )
}

#[inline]
unsafe fn m4_mount(
    source: *const c_char,
    target: *const c_char,
    filesystem_type: *const c_char,
    mount_flags: c_ulong,
    data: *const c_void,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        M4_SYS_MOUNT,
        source as i64,
        target as i64,
        filesystem_type as i64,
        mount_flags as i64,
        data as i64,
    )
}

#[inline]
unsafe fn m4_umount2(target: *const c_char, flags: c_int) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_UMOUNT2, target as i64, flags as i64)
}

#[inline]
unsafe fn m4_pivot_root(new_root: *const c_char, put_old: *const c_char) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_PIVOT_ROOT, new_root as i64, put_old as i64)
}

#[inline]
unsafe fn m4_quotactl(
    command: c_int,
    special: *const c_char,
    id: c_int,
    data: *mut c_void,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_QUOTACTL,
        command as i64,
        special as i64,
        id as i64,
        data as i64,
    )
}

#[inline]
unsafe fn m4_reboot(how: c_int) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_REBOOT,
        M4_LINUX_REBOOT_MAGIC1,
        M4_LINUX_REBOOT_MAGIC2,
        how as i64,
        0,
    )
}

#[inline]
unsafe fn m4_swapoff(path: *const c_char) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_SWAPOFF, path as i64)
}

#[inline]
unsafe fn m4_swapon(path: *const c_char, flags: c_int) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_SWAPON, path as i64, flags as i64)
}

#[inline]
unsafe fn m4_vhangup() -> i64 {
    <Arch as Syscalls>::syscall0(M4_SYS_VHANGUP)
}

#[no_mangle]
pub unsafe extern "C" fn prctl(option: c_int, mut args: ...) -> c_int {
    syscall_result(m4_prctl(option, &mut args)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn personality(persona: c_ulong) -> c_int {
    syscall_result(m4_personality(persona)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setns(fd: c_int, nstype: c_int) -> c_int {
    syscall_result(m4_setns(fd, nstype)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn unshare(flags: c_int) -> c_int {
    syscall_result(m4_unshare(flags)) as c_int
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> c_int {
    syscall_result(m4_membarrier(cmd, flags, cpu_id)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn memfd_create(name: *const c_char, flags: c_uint) -> c_int {
    syscall_result(m4_memfd_create(name, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn readahead(fd: c_int, offset: i64, count: SizeT) -> SSizeT {
    syscall_result(m4_readahead(fd, offset, count)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn sync_file_range(
    fd: c_int,
    offset: i64,
    nbytes: i64,
    flags: c_uint,
) -> c_int {
    syscall_result(m4_sync_file_range(fd, offset, nbytes, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn syncfs(fd: c_int) -> c_int {
    syscall_result(m4_syncfs(fd)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn statx(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mask: c_uint,
    buffer: *mut c_void,
) -> c_int {
    syscall_result(m4_statx(dirfd, path, flags, mask, buffer)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn prlimit(
    pid: c_int,
    resource: c_int,
    new_limit: *const Rlimit,
    old_limit: *mut Rlimit,
) -> c_int {
    syscall_result(m4_prlimit(pid, resource, new_limit, old_limit)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn acct(path: *const c_char) -> c_int {
    syscall_result(m4_acct(path)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn delete_module(name: *const c_char, flags: c_uint) -> c_int {
    syscall_result(m4_delete_module(name, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn init_module(
    module_image: *mut c_void,
    len: SizeT,
    param_values: *const c_char,
) -> c_int {
    syscall_result(m4_init_module(module_image, len, param_values)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn klogctl(
    syslog_type: c_int,
    buffer: *mut c_char,
    len: c_int,
) -> c_int {
    syscall_result(m4_klogctl(syslog_type, buffer, len)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mount(
    source: *const c_char,
    target: *const c_char,
    filesystem_type: *const c_char,
    mount_flags: c_ulong,
    data: *const c_void,
) -> c_int {
    syscall_result(m4_mount(source, target, filesystem_type, mount_flags, data)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn umount(target: *const c_char) -> c_int {
    syscall_result(m4_umount2(target, 0)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    syscall_result(m4_umount2(target, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    syscall_result(m4_pivot_root(new_root, put_old)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn quotactl(
    command: c_int,
    special: *const c_char,
    id: c_int,
    data: *mut c_void,
) -> c_int {
    syscall_result(m4_quotactl(command, special, id, data)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn reboot(how: c_int) -> c_int {
    syscall_result(m4_reboot(how)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    syscall_result(m4_swapoff(path)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn swapon(path: *const c_char, flags: c_int) -> c_int {
    syscall_result(m4_swapon(path, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn vhangup() -> c_int {
    syscall_result(m4_vhangup()) as c_int
}
