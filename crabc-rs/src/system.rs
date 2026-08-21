//! Linux system identity and status information.

use core::ffi::CStr;

/// Kernel and hardware naming data returned by [`uname`].
#[derive(Clone, Copy)]
pub struct Uname(crabc_core::system::UtsName);

impl Uname {
    #[inline]
    fn field(bytes: &[u8; 65]) -> &CStr {
        // Linux's `new_utsname` fields are NUL-terminated fixed arrays.
        unsafe { CStr::from_ptr(bytes.as_ptr().cast()) }
    }

    /// Operating-system name.
    #[inline]
    pub fn sysname(&self) -> &CStr { Self::field(&self.0.sysname) }
    /// Network node name.
    #[inline]
    pub fn nodename(&self) -> &CStr { Self::field(&self.0.nodename) }
    /// Kernel release.
    #[inline]
    pub fn release(&self) -> &CStr { Self::field(&self.0.release) }
    /// Kernel version.
    #[inline]
    pub fn version(&self) -> &CStr { Self::field(&self.0.version) }
    /// Kernel machine name.
    #[inline]
    pub fn machine(&self) -> &CStr { Self::field(&self.0.machine) }
    /// Linux NIS domain name.
    #[inline]
    pub fn domainname(&self) -> &CStr { Self::field(&self.0.domainname) }
}

impl core::fmt::Debug for Uname {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Uname")
            .field("sysname", &self.sysname())
            .field("nodename", &self.nodename())
            .field("release", &self.release())
            .field("version", &self.version())
            .field("machine", &self.machine())
            .field("domainname", &self.domainname())
            .finish()
    }
}

/// Linux `sysinfo` data, expressed in the kernel's native units.
#[non_exhaustive]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Sysinfo {
    /// Seconds since boot.
    pub uptime: i64,
    /// One-, five-, and fifteen-minute load averages scaled by 65536.
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    /// Total high memory size.
    pub totalhigh: u64,
    /// Available high memory size.
    pub freehigh: u64,
    /// Unit multiplier for memory fields; zero means bytes.
    pub mem_unit: u32,
}

impl From<crabc_core::system::Sysinfo> for Sysinfo {
    fn from(value: crabc_core::system::Sysinfo) -> Self {
        Self {
            uptime: value.uptime,
            loads: value.loads,
            totalram: value.totalram,
            freeram: value.freeram,
            sharedram: value.sharedram,
            bufferram: value.bufferram,
            totalswap: value.totalswap,
            freeswap: value.freeswap,
            procs: value.procs,
            totalhigh: value.totalhigh,
            freehigh: value.freehigh,
            mem_unit: value.mem_unit,
        }
    }
}

/// Returns runtime OS and hardware information.
#[inline]
pub fn uname() -> Uname {
    match crabc_core::system::uname() {
        Ok(value) => Uname(value),
        // Linux treats uname as an infallible system-information operation;
        // preserve Rustix's infallible public contract rather than inventing
        // a recoverable branch for an impossible kernel failure.
        Err(_) => panic!("Linux uname syscall failed"),
    }
}

/// Returns Linux memory, load, and uptime information.
#[inline]
pub fn sysinfo() -> Sysinfo {
    match crabc_core::system::sysinfo() {
        Ok(value) => Sysinfo::from(value),
        // See uname above: Linux supplies this data for a running task.
        Err(_) => panic!("Linux sysinfo syscall failed"),
    }
}
