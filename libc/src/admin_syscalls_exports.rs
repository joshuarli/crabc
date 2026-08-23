// Linux administrative and kernel-interface exports.
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


const CABI_SYS_PRCTL: i64 = 167;
const CABI_SYS_PERSONALITY: i64 = 92;
const CABI_SYS_SETNS: i64 = 268;
const CABI_SYS_UNSHARE: i64 = 97;
const CABI_SYS_MEMBARRIER: i64 = 283;
const CABI_SYS_MEMFD_CREATE: i64 = 279;
const CABI_SYS_READAHEAD: i64 = 213;
const CABI_SYS_SYNC_FILE_RANGE: i64 = 84;
const CABI_SYS_SYNCFS: i64 = 267;
const CABI_SYS_STATX: i64 = 291;
const CABI_SYS_PRLIMIT64: i64 = 261;
const CABI_SYS_UMOUNT2: i64 = 39;
const CABI_SYS_MOUNT: i64 = 40;
const CABI_SYS_PIVOT_ROOT: i64 = 41;
const CABI_SYS_VHANGUP: i64 = 58;
const CABI_SYS_QUOTACTL: i64 = 60;
const CABI_SYS_ACCT: i64 = 89;
const CABI_SYS_INIT_MODULE: i64 = 105;
const CABI_SYS_DELETE_MODULE: i64 = 106;
const CABI_SYS_SYSLOG: i64 = 116;
const CABI_SYS_REBOOT: i64 = 142;
const CABI_SYS_SWAPON: i64 = 224;
const CABI_SYS_SWAPOFF: i64 = 225;

const CABI_LINUX_REBOOT_MAGIC1: i64 = 0xfee1dead;
const CABI_LINUX_REBOOT_MAGIC2: i64 = 672274793;

// prctl options whose argument count is observable at this ABI boundary.
// Linux ignores the unused trailing syscall registers, so known one-argument
// and zero-argument operations can avoid reading absent C varargs.  Unknown
// operations retain the four-argument ABI used by musl's prctl wrapper.
const CABI_PR_GET_DUMPABLE: c_int = 3;
const CABI_PR_GET_NAME: c_int = 16;
const CABI_PR_SET_NAME: c_int = 15;
const CABI_PR_SET_NO_NEW_PRIVS: c_int = 38;
const CABI_PR_GET_NO_NEW_PRIVS: c_int = 39;

#[inline]
unsafe fn cabi_prctl(option: c_int, args: &mut VaList) -> i64 {
    let argc = match option {
        CABI_PR_GET_DUMPABLE | CABI_PR_GET_NO_NEW_PRIVS => 0,
        CABI_PR_GET_NAME | CABI_PR_SET_NAME | CABI_PR_SET_NO_NEW_PRIVS => 1,
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
    aarch64::syscall::syscall5(
        CABI_SYS_PRCTL,
        option as i64,
        values[0] as i64,
        values[1] as i64,
        values[2] as i64,
        values[3] as i64,
    )
}

#[inline]
unsafe fn cabi_personality(persona: c_ulong) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_PERSONALITY, persona as i64)
}

#[inline]
unsafe fn cabi_setns(fd: c_int, nstype: c_int) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_SETNS, fd as i64, nstype as i64)
}

#[inline]
unsafe fn cabi_unshare(flags: c_int) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_UNSHARE, flags as i64)
}

#[inline]
unsafe fn cabi_membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_MEMBARRIER,
        cmd as i64,
        flags as i64,
        cpu_id as i64,
    )
}

#[inline]
unsafe fn cabi_memfd_create(name: *const c_char, flags: c_uint) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_MEMFD_CREATE, name as i64, flags as i64)
}

#[inline]
unsafe fn cabi_readahead(fd: c_int, offset: i64, count: SizeT) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_READAHEAD,
        fd as i64,
        offset,
        count as i64,
    )
}

#[inline]
unsafe fn cabi_sync_file_range(fd: c_int, offset: i64, nbytes: i64, flags: c_uint) -> i64 {
    aarch64::syscall::syscall4(
        CABI_SYS_SYNC_FILE_RANGE,
        fd as i64,
        offset,
        nbytes,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_syncfs(fd: c_int) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_SYNCFS, fd as i64)
}

#[inline]
unsafe fn cabi_statx(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mask: c_uint,
    buffer: *mut c_void,
) -> i64 {
    aarch64::syscall::syscall5(
        CABI_SYS_STATX,
        dirfd as i64,
        path as i64,
        flags as i64,
        mask as i64,
        buffer as i64,
    )
}

#[inline]
unsafe fn cabi_prlimit(
    pid: c_int,
    resource: c_int,
    new_limit: *const Rlimit,
    old_limit: *mut Rlimit,
) -> i64 {
    aarch64::syscall::syscall4(
        CABI_SYS_PRLIMIT64,
        pid as i64,
        resource as i64,
        new_limit as i64,
        old_limit as i64,
    )
}

#[inline]
unsafe fn cabi_acct(path: *const c_char) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_ACCT, path as i64)
}

#[inline]
unsafe fn cabi_delete_module(name: *const c_char, flags: c_uint) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_DELETE_MODULE, name as i64, flags as i64)
}

#[inline]
unsafe fn cabi_init_module(
    module_image: *mut c_void,
    len: SizeT,
    param_values: *const c_char,
) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_INIT_MODULE,
        module_image as i64,
        len as i64,
        param_values as i64,
    )
}

#[inline]
unsafe fn cabi_klogctl(syslog_type: c_int, buffer: *mut c_char, len: c_int) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_SYSLOG,
        syslog_type as i64,
        buffer as i64,
        len as i64,
    )
}

#[inline]
unsafe fn cabi_mount(
    source: *const c_char,
    target: *const c_char,
    filesystem_type: *const c_char,
    mount_flags: c_ulong,
    data: *const c_void,
) -> i64 {
    match crabc_core::mount::mount_raw(
        source.cast(),
        target.cast(),
        filesystem_type.cast(),
        mount_flags as u64,
        data.cast(),
    ) {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn cabi_umount2(target: *const c_char, flags: c_int) -> i64 {
    match crabc_core::mount::umount2_raw(target.cast(), flags) {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn cabi_pivot_root(new_root: *const c_char, put_old: *const c_char) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_PIVOT_ROOT, new_root as i64, put_old as i64)
}

#[inline]
unsafe fn cabi_quotactl(
    command: c_int,
    special: *const c_char,
    id: c_int,
    data: *mut c_void,
) -> i64 {
    aarch64::syscall::syscall4(
        CABI_SYS_QUOTACTL,
        command as i64,
        special as i64,
        id as i64,
        data as i64,
    )
}

#[inline]
unsafe fn cabi_reboot(how: c_int) -> i64 {
    aarch64::syscall::syscall4(
        CABI_SYS_REBOOT,
        CABI_LINUX_REBOOT_MAGIC1,
        CABI_LINUX_REBOOT_MAGIC2,
        how as i64,
        0,
    )
}

#[inline]
unsafe fn cabi_swapoff(path: *const c_char) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_SWAPOFF, path as i64)
}

#[inline]
unsafe fn cabi_swapon(path: *const c_char, flags: c_int) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_SWAPON, path as i64, flags as i64)
}

#[inline]
unsafe fn cabi_vhangup() -> i64 {
    aarch64::syscall::syscall0(CABI_SYS_VHANGUP)
}

#[no_mangle]
pub unsafe extern "C" fn prctl(option: c_int, mut args: ...) -> c_int {
    syscall_result(cabi_prctl(option, &mut args)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn personality(persona: c_ulong) -> c_int {
    syscall_result(cabi_personality(persona)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setns(fd: c_int, nstype: c_int) -> c_int {
    syscall_result(cabi_setns(fd, nstype)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn unshare(flags: c_int) -> c_int {
    syscall_result(cabi_unshare(flags)) as c_int
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> c_int {
    syscall_result(cabi_membarrier(cmd, flags, cpu_id)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn memfd_create(name: *const c_char, flags: c_uint) -> c_int {
    syscall_result(cabi_memfd_create(name, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn readahead(fd: c_int, offset: i64, count: SizeT) -> SSizeT {
    syscall_result(cabi_readahead(fd, offset, count)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn sync_file_range(
    fd: c_int,
    offset: i64,
    nbytes: i64,
    flags: c_uint,
) -> c_int {
    syscall_result(cabi_sync_file_range(fd, offset, nbytes, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn syncfs(fd: c_int) -> c_int {
    syscall_result(cabi_syncfs(fd)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn statx(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mask: c_uint,
    buffer: *mut c_void,
) -> c_int {
    syscall_result(cabi_statx(dirfd, path, flags, mask, buffer)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn prlimit(
    pid: c_int,
    resource: c_int,
    new_limit: *const Rlimit,
    old_limit: *mut Rlimit,
) -> c_int {
    syscall_result(cabi_prlimit(pid, resource, new_limit, old_limit)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn acct(path: *const c_char) -> c_int {
    syscall_result(cabi_acct(path)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn delete_module(name: *const c_char, flags: c_uint) -> c_int {
    syscall_result(cabi_delete_module(name, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn init_module(
    module_image: *mut c_void,
    len: SizeT,
    param_values: *const c_char,
) -> c_int {
    syscall_result(cabi_init_module(module_image, len, param_values)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn klogctl(
    syslog_type: c_int,
    buffer: *mut c_char,
    len: c_int,
) -> c_int {
    syscall_result(cabi_klogctl(syslog_type, buffer, len)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mount(
    source: *const c_char,
    target: *const c_char,
    filesystem_type: *const c_char,
    mount_flags: c_ulong,
    data: *const c_void,
) -> c_int {
    syscall_result(cabi_mount(source, target, filesystem_type, mount_flags, data)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn umount(target: *const c_char) -> c_int {
    syscall_result(cabi_umount2(target, 0)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    syscall_result(cabi_umount2(target, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    syscall_result(cabi_pivot_root(new_root, put_old)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn quotactl(
    command: c_int,
    special: *const c_char,
    id: c_int,
    data: *mut c_void,
) -> c_int {
    syscall_result(cabi_quotactl(command, special, id, data)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn reboot(how: c_int) -> c_int {
    syscall_result(cabi_reboot(how)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    syscall_result(cabi_swapoff(path)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn swapon(path: *const c_char, flags: c_int) -> c_int {
    syscall_result(cabi_swapon(path, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn vhangup() -> c_int {
    syscall_result(cabi_vhangup()) as c_int
}
