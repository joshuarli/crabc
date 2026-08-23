// system-information exports.
//
// The values in this slice come from Linux rather than a process-local
// approximation: sysinfo(2) supplies memory/load data, sched_getaffinity(2)
// supplies the processor count, and AT_PAGESZ supplies the page size used to
// convert memory bytes to pages.  The public sysinfo layout intentionally
// retains musl's 256-byte compatibility tail; Linux only fills the prefix.

#[repr(C)]
pub struct CabiSysinfo {
    pub uptime: c_ulong,
    pub loads: [c_ulong; 3],
    pub totalram: c_ulong,
    pub freeram: c_ulong,
    pub sharedram: c_ulong,
    pub bufferram: c_ulong,
    pub totalswap: c_ulong,
    pub freeswap: c_ulong,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: c_ulong,
    pub freehigh: c_ulong,
    pub mem_unit: c_uint,
    pub __reserved: [u8; 256],
}




const CABI_INFO_SYS_SYSINFO: i64 = 179;
const CABI_INFO_SYS_SCHED_GETAFFINITY: i64 = 123;

const CABI_INFO_AT_PAGESZ: c_ulong = 6;
const CABI_INFO_LOAD_SCALE: f64 = 65536.0;
const CABI_INFO_CPUSET_BYTES: usize = 128;
const CABI_INFO_CLOCK_PROCESS_CPUTIME_ID: c_int = 2;
const CABI_INFO_ESRCH: c_int = 3;
const CABI_INFO_ENOSYS: c_int = 38;

#[inline]
unsafe fn cabi_info_sysinfo_raw(info: *mut CabiSysinfo) -> i64 {
    match crabc_core::system::sysinfo_raw(info.cast()) {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn cabi_info_page_size() -> u64 {
    // AT_PAGESZ is supplied by the Linux kernel in the initial auxiliary
    // vector.  Unlike a target-specific literal this remains correct for
    // AArch64 kernels configured with 16 KiB or 64 KiB pages.
    getauxval(CABI_INFO_AT_PAGESZ) as u64
}

#[inline]
unsafe fn cabi_info_page_count(info: &CabiSysinfo, available: bool) -> c_long {
    let page_size = cabi_info_page_size();
    if page_size == 0 {
        ERRNO = CABI_INFO_ENOSYS;
        return -1;
    }

    let unit = if info.mem_unit == 0 {
        1u64
    } else {
        info.mem_unit as u64
    };
    let amount = if available {
        (info.freeram as u64).saturating_add(info.bufferram as u64)
    } else {
        info.totalram as u64
    };
    let bytes = amount.saturating_mul(unit);
    let pages = bytes / page_size;
    if pages > i64::MAX as u64 {
        i64::MAX
    } else {
        pages as c_long
    }
}

#[inline]
unsafe fn cabi_info_nprocs() -> c_int {
    // musl uses a 128-byte mask, initialized with CPU 0 set.  Linux writes
    // the mask bytes represented by the kernel's CPU set; keeping the rest
    // zero lets this work with both smaller and larger kernel CPU masks.
    let mut mask = [0u8; CABI_INFO_CPUSET_BYTES];
    mask[0] = 1;
    let _ = aarch64::syscall::syscall3(
        CABI_INFO_SYS_SCHED_GETAFFINITY,
        0,
        CABI_INFO_CPUSET_BYTES as i64,
        mask.as_mut_ptr() as i64,
    );

    let mut count = 0u32;
    let mut i = 0usize;
    while i < mask.len() {
        count += mask[i].count_ones();
        i += 1;
    }
    count as c_int
}

// musl exposes sysinfo as a weak alias of its raw Linux adapter.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn sysinfo(info: *mut CabiSysinfo) -> c_int {
    syscall_result(cabi_info_sysinfo_raw(info)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getloadavg(loads: *mut f64, n: c_int) -> c_int {
    if n <= 0 {
        return if n < 0 { -1 } else { 0 };
    }

    let mut info: CabiSysinfo = core::mem::zeroed();
    if syscall_result(cabi_info_sysinfo_raw(&mut info)) < 0 {
        return -1;
    }

    let count = if n > 3 { 3 } else { n as usize };
    let mut i = 0usize;
    while i < count {
        *loads.add(i) = info.loads[i] as f64 / CABI_INFO_LOAD_SCALE;
        i += 1;
    }
    count as c_int
}

#[no_mangle]
pub unsafe extern "C" fn get_nprocs_conf() -> c_int {
    cabi_info_nprocs()
}

#[no_mangle]
pub unsafe extern "C" fn get_nprocs() -> c_int {
    cabi_info_nprocs()
}

#[no_mangle]
pub unsafe extern "C" fn get_phys_pages() -> c_long {
    let mut info: CabiSysinfo = core::mem::zeroed();
    if syscall_result(cabi_info_sysinfo_raw(&mut info)) < 0 {
        return -1;
    }
    cabi_info_page_count(&info, false)
}

#[no_mangle]
pub unsafe extern "C" fn get_avphys_pages() -> c_long {
    let mut info: CabiSysinfo = core::mem::zeroed();
    if syscall_result(cabi_info_sysinfo_raw(&mut info)) < 0 {
        return -1;
    }
    cabi_info_page_count(&info, true)
}

#[no_mangle]
pub unsafe extern "C" fn clock_getcpuclockid(pid: c_int, clock: *mut c_int) -> c_int {
    // Linux encodes a process CPU clock as (~pid << 3) | 2.  The wrapping
    // unsigned arithmetic also gives the current-process clock for pid 0,
    // matching musl's (-pid-1)*8U + 2 expression.
    let id = (0u32
        .wrapping_sub(pid as u32)
        .wrapping_sub(1)
        .wrapping_shl(3)
        | CABI_INFO_CLOCK_PROCESS_CPUTIME_ID as u32) as c_int;
    let mut resolution: timespec = core::mem::zeroed();
    let result = sys_clock_getres(id, &mut resolution);
    if result == -(EINVAL as i64) {
        return CABI_INFO_ESRCH;
    }
    if result < 0 {
        return (-result) as c_int;
    }

    *clock = id;
    0
}
