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
    pub fn sysname(&self) -> &CStr {
        Self::field(&self.0.sysname)
    }
    /// Network node name.
    #[inline]
    pub fn nodename(&self) -> &CStr {
        Self::field(&self.0.nodename)
    }
    /// Kernel release.
    #[inline]
    pub fn release(&self) -> &CStr {
        Self::field(&self.0.release)
    }
    /// Kernel version.
    #[inline]
    pub fn version(&self) -> &CStr {
        Self::field(&self.0.version)
    }
    /// Kernel machine name.
    #[inline]
    pub fn machine(&self) -> &CStr {
        Self::field(&self.0.machine)
    }
    /// Linux NIS domain name.
    #[inline]
    pub fn domainname(&self) -> &CStr {
        Self::field(&self.0.domainname)
    }
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

/// Linux one-, five-, and fifteen-minute load averages.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LoadAverages {
    /// One-minute load average.
    pub one_minute: f64,
    /// Five-minute load average.
    pub five_minutes: f64,
    /// Fifteen-minute load average.
    pub fifteen_minutes: f64,
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

/// Returns the host-wide Linux load averages.
#[inline]
pub fn load_average() -> LoadAverages {
    let loads = crabc_core::system::sysinfo()
        .map(|value| value.loads)
        .unwrap_or_else(|_| panic!("Linux sysinfo syscall failed"));
    const LOAD_AVERAGE_SCALE: f64 = 65_536.0;
    LoadAverages {
        one_minute: loads[0] as f64 / LOAD_AVERAGE_SCALE,
        five_minutes: loads[1] as f64 / LOAD_AVERAGE_SCALE,
        fifteen_minutes: loads[2] as f64 / LOAD_AVERAGE_SCALE,
    }
}

/// Owned Linux inotify watches and byte-preserving event records.
pub mod inotify {
    use bitflags::bitflags;

    use crate::path::Arg;
    use crate::{AsFd, BorrowedFd, OwnedFd, Result};

    const EVENT_HEADER_SIZE: usize = 16;

    bitflags! {
        /// Flags accepted by Linux `inotify_init1`.
        ///
        /// This is deliberately a closed vocabulary. New kernel flags must be
        /// reviewed before a caller can request them from a safe API.
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct CreateFlags: u32 {
            /// Create the descriptor in nonblocking mode.
            const NONBLOCK = 0x0000_0800;
            /// Close the descriptor across a successful exec.
            const CLOEXEC = 0x0008_0000;
        }
    }

    bitflags! {
        /// Linux inotify watch requests and observed event bits.
        ///
        /// Observed records retain unknown future kernel bits. When used as a
        /// watch request, the kernel remains the authority for validation.
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct EventMask: u32 {
            const ACCESS = 0x0000_0001;
            const MODIFY = 0x0000_0002;
            const ATTRIB = 0x0000_0004;
            const CLOSE_WRITE = 0x0000_0008;
            const CLOSE_NOWRITE = 0x0000_0010;
            const CLOSE = Self::CLOSE_WRITE.bits() | Self::CLOSE_NOWRITE.bits();
            const OPEN = 0x0000_0020;
            const MOVED_FROM = 0x0000_0040;
            const MOVED_TO = 0x0000_0080;
            const MOVE = Self::MOVED_FROM.bits() | Self::MOVED_TO.bits();
            const CREATE = 0x0000_0100;
            const DELETE = 0x0000_0200;
            const DELETE_SELF = 0x0000_0400;
            const MOVE_SELF = 0x0000_0800;
            const UNMOUNT = 0x0000_2000;
            const Q_OVERFLOW = 0x0000_4000;
            const IGNORED = 0x0000_8000;
            const ONLYDIR = 0x0100_0000;
            const DONT_FOLLOW = 0x0200_0000;
            const EXCL_UNLINK = 0x0400_0000;
            const MASK_CREATE = 0x1000_0000;
            const MASK_ADD = 0x2000_0000;
            const ISDIR = 0x4000_0000;
            const ONESHOT = 0x8000_0000;
            const _ = !0;
        }
    }

    /// A watch identifier scoped to one [`Inotify`] descriptor.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    #[repr(transparent)]
    pub struct WatchDescriptor(i32);

    impl WatchDescriptor {
        /// Returns the Linux inotify watch descriptor.
        #[inline]
        pub const fn as_raw(self) -> i32 {
            self.0
        }
    }

    /// An owned Linux inotify descriptor.
    ///
    /// Dropping this value closes the descriptor and removes all of its
    /// watches. Watch descriptors cannot outlive the descriptor at the type
    /// level because every mutating operation borrows this owner.
    #[derive(Debug)]
    pub struct Inotify {
        fd: OwnedFd,
    }

    impl Inotify {
        /// Creates one owned inotify descriptor.
        #[inline]
        pub fn new(flags: CreateFlags) -> Result<Self> {
            if CreateFlags::from_bits(flags.bits()).is_none() {
                return Err(crate::Errno::INVAL);
            }
            let fd = crabc_core::inotify::init1(flags.bits())?;
            // SAFETY: a successful `inotify_init1` returns one fresh,
            // non-negative descriptor whose ownership transfers here.
            Ok(Self {
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
            })
        }

        /// Adds a watch for a byte-oriented pathname.
        #[inline]
        pub fn add_watch<P: Arg>(&self, path: P, mask: EventMask) -> Result<WatchDescriptor> {
            path.into_with_c_str(|path| {
                crabc_core::inotify::add_watch(self.fd.as_raw_fd(), path, mask.bits())
                    .map(WatchDescriptor)
            })
        }

        /// Removes one watch. Linux may already have removed it after an
        /// `IGNORED` event, in which case it returns the direct `EINVAL`.
        #[inline]
        pub fn remove_watch(&self, watch: WatchDescriptor) -> Result<()> {
            crabc_core::inotify::rm_watch(self.fd.as_raw_fd(), watch.0)
        }

        /// Borrows the inotify descriptor for polling or descriptor I/O.
        #[inline]
        pub fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }

        /// Reads and validates one kernel batch into caller-owned storage.
        ///
        /// The returned iterator borrows `buffer`; each item either describes
        /// one byte-preserving event or reports malformed record boundaries.
        /// A nonblocking descriptor reports `EAGAIN` before an iterator is
        /// created when no complete batch is available.
        #[inline]
        pub fn read_events<'buffer>(&self, buffer: &'buffer mut [u8]) -> Result<Events<'buffer>> {
            let length = crabc_core::io::read(self.fd.as_raw_fd(), buffer)?;
            Ok(Events {
                bytes: &buffer[..length],
                offset: 0,
                malformed: false,
            })
        }

        /// Transfers the descriptor owner without removing its watches.
        #[inline]
        pub fn into_owned_fd(self) -> OwnedFd {
            self.fd
        }
    }

    impl AsFd for Inotify {
        #[inline]
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.as_fd()
        }
    }

    #[cfg(feature = "std")]
    impl std::os::fd::AsRawFd for Inotify {
        #[inline]
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.as_fd().as_raw_fd()
        }
    }

    #[cfg(feature = "std")]
    impl std::os::fd::AsFd for Inotify {
        #[inline]
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            // SAFETY: `Inotify` owns the descriptor through `OwnedFd`, so it
            // remains open for the returned standard-library borrow.
            unsafe { std::os::fd::BorrowedFd::borrow_raw(self.as_fd().as_raw_fd()) }
        }
    }

    /// One byte-preserving inotify event borrowed from [`Events`].
    #[derive(Debug, Eq, PartialEq)]
    pub struct Event<'buffer> {
        watch: Option<WatchDescriptor>,
        mask: EventMask,
        cookie: u32,
        name: Option<&'buffer [u8]>,
    }

    impl Event<'_> {
        /// Returns the watch that produced this event, or `None` for
        /// descriptor-wide records such as queue overflow.
        #[inline]
        pub const fn watch(&self) -> Option<WatchDescriptor> {
            self.watch
        }

        /// Returns the Linux event mask, retaining unknown future bits.
        #[inline]
        pub const fn mask(&self) -> EventMask {
            self.mask
        }

        /// Returns Linux's move cookie, or zero when the event has none.
        #[inline]
        pub const fn cookie(&self) -> u32 {
            self.cookie
        }

        /// Returns the event's path-component bytes without its terminating
        /// NUL, or `None` when the kernel supplied no name.
        #[inline]
        pub const fn name(&self) -> Option<&[u8]> {
            self.name
        }
    }

    /// An iterator over one validated inotify read batch.
    pub struct Events<'buffer> {
        bytes: &'buffer [u8],
        offset: usize,
        malformed: bool,
    }

    impl<'buffer> Iterator for Events<'buffer> {
        type Item = Result<Event<'buffer>>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.malformed || self.offset == self.bytes.len() {
                return None;
            }
            let remaining = &self.bytes[self.offset..];
            if remaining.len() < EVENT_HEADER_SIZE {
                self.malformed = true;
                return Some(Err(crate::Errno::INVAL));
            }

            let watch = i32::from_ne_bytes(remaining[0..4].try_into().unwrap());
            let mask = u32::from_ne_bytes(remaining[4..8].try_into().unwrap());
            let cookie = u32::from_ne_bytes(remaining[8..12].try_into().unwrap());
            let name_length = u32::from_ne_bytes(remaining[12..16].try_into().unwrap()) as usize;
            let record_length = match EVENT_HEADER_SIZE.checked_add(name_length) {
                Some(length) if length <= remaining.len() => length,
                _ => {
                    self.malformed = true;
                    return Some(Err(crate::Errno::INVAL));
                }
            };
            self.offset += record_length;

            let name_bytes = &remaining[EVENT_HEADER_SIZE..record_length];
            let name = if name_bytes.is_empty() {
                None
            } else {
                match name_bytes.iter().position(|&byte| byte == 0) {
                    Some(length) => Some(&name_bytes[..length]),
                    None => {
                        self.malformed = true;
                        return Some(Err(crate::Errno::INVAL));
                    }
                }
            };
            let watch = match watch {
                -1 => None,
                value if value >= 0 => Some(WatchDescriptor(value)),
                _ => {
                    self.malformed = true;
                    return Some(Err(crate::Errno::INVAL));
                }
            };
            Some(Ok(Event {
                watch,
                mask: EventMask::from_bits_retain(mask),
                cookie,
                name,
            }))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn event_batch_decodes_a_nul_terminated_name() {
            let mut bytes = [0u8; EVENT_HEADER_SIZE + 4];
            bytes[0..4].copy_from_slice(&7_i32.to_ne_bytes());
            bytes[4..8].copy_from_slice(&EventMask::CREATE.bits().to_ne_bytes());
            bytes[8..12].copy_from_slice(&23_u32.to_ne_bytes());
            bytes[12..16].copy_from_slice(&4_u32.to_ne_bytes());
            bytes[16..20].copy_from_slice(b"x\0\0\0");
            let mut events = Events {
                bytes: &bytes,
                offset: 0,
                malformed: false,
            };

            let event = events.next().expect("one event").expect("valid event");
            assert_eq!(event.watch(), Some(WatchDescriptor(7)));
            assert!(event.mask().contains(EventMask::CREATE));
            assert_eq!(event.cookie(), 23);
            assert_eq!(event.name(), Some(b"x".as_slice()));
            assert!(events.next().is_none());
        }

        #[test]
        fn event_batch_rejects_a_truncated_record() {
            let mut events = Events {
                bytes: &[0; EVENT_HEADER_SIZE - 1],
                offset: 0,
                malformed: false,
            };

            assert_eq!(events.next(), Some(Err(crate::Errno::INVAL)));
            assert!(events.next().is_none());
        }

        #[test]
        fn event_batch_rejects_a_name_without_a_nul() {
            let mut bytes = [0u8; EVENT_HEADER_SIZE + 1];
            bytes[12..16].copy_from_slice(&1_u32.to_ne_bytes());
            bytes[16] = b'x';
            let mut events = Events {
                bytes: &bytes,
                offset: 0,
                malformed: false,
            };

            assert_eq!(events.next(), Some(Err(crate::Errno::INVAL)));
            assert!(events.next().is_none());
        }
    }
}
