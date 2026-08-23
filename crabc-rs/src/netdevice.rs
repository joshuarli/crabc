//! Direct Linux network-device queries.
//!
//! These operations use the fixed `SIOCGIF*` ioctl contracts directly. The
//! caller supplies a socket descriptor, as required by Linux, while this
//! module keeps the kernel `ifreq` storage and interface-name bounds private.

use core::num::NonZeroU32;

use crate::{AsFd, OwnedFd, Result};

const IFNAMSIZ: usize = 16;
const SIOCGIFINDEX: u32 = 0x8933;
const SIOCGIFNAME: u32 = 0x8910;

/// The Linux `ifreq` union is 24 bytes on AArch64. The `u64` storage keeps the
/// private union correctly aligned and sized while these ioctls use only the
/// `ifru_ifindex` member for their index input/output.
#[repr(C)]
union IfreqData {
    ifindex: i32,
    _storage: [u64; 3],
}

#[repr(C)]
struct Ifreq {
    name: [u8; IFNAMSIZ],
    data: IfreqData,
}

const _: () = assert!(core::mem::size_of::<Ifreq>() == 40);

/// Queries the Linux interface index for a name through `SIOCGIFINDEX`.
///
/// This is the Rustix-compatible counterpart of `if_nametoindex`, but it
/// intentionally takes the socket descriptor required by the Linux ioctl
/// rather than creating hidden process state. Names containing NUL bytes or
/// occupying the complete `IFNAMSIZ` field are rejected as `ENODEV`, matching
/// Rustix's Linux-raw backend. Kernel failures remain direct [`crate::Errno`]
/// values; no libc, C ABI, or TLS `errno` is consulted.
#[inline]
pub fn name_to_index<Fd: AsFd>(fd: Fd, if_name: &str) -> Result<u32> {
    let bytes = if_name.as_bytes();
    if bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
        return Err(crate::Errno::NODEV);
    }

    let mut request = Ifreq {
        name: [0; IFNAMSIZ],
        // SAFETY: All-zero bytes are a valid representation for the private
        // integer/storage union used by this ioctl request.
        data: unsafe { core::mem::zeroed() },
    };
    request.name[..bytes.len()].copy_from_slice(bytes);

    // SAFETY: `request` is the complete 40-byte Linux/AArch64 `ifreq` layout,
    // its name field is NUL-terminated and bounded, and SIOCGIFINDEX writes
    // the interface index into the union's `ifindex` member.
    unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_fd().as_raw_fd(),
            SIOCGIFINDEX,
            (&mut request as *mut Ifreq).cast(),
        )?;
        Ok(request.data.ifindex as u32)
    }
}

/// Queries the Linux interface name for an index through `SIOCGIFNAME`.
///
/// The returned value owns the kernel's fixed-size name storage and does not
/// require an allocator. Names are validated as UTF-8, matching Rustix's
/// public API; a kernel name containing non-UTF-8 bytes is reported as
/// [`crate::Errno::ILSEQ`].
#[inline]
#[doc(alias = "SIOCGIFNAME")]
pub fn index_to_name_inlined<Fd: AsFd>(fd: Fd, index: u32) -> Result<InlinedName> {
    let (len, name) = index_to_name_raw(fd, index)?;

    // Validate before constructing the public value, whose `AsRef<str>`
    // implementation relies on this invariant.
    core::str::from_utf8(&name[..len])
        .map_err(|_| crate::Errno::ILSEQ)
        .map(|_| InlinedName { len, name })
}

/// Queries the Linux interface name for an index through `SIOCGIFNAME`.
///
/// This allocating convenience wrapper is available when the crate's
/// `alloc` feature is enabled, just like Rustix's `index_to_name` API.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[inline]
#[doc(alias = "SIOCGIFNAME")]
pub fn index_to_name<Fd: AsFd>(fd: Fd, index: u32) -> Result<alloc::string::String> {
    let (len, name) = index_to_name_raw(fd, index)?;

    core::str::from_utf8(&name[..len])
        .map_err(|_| crate::Errno::ILSEQ)
        .map(alloc::borrow::ToOwned::to_owned)
}

/// The inlined Linux interface name returned by [`index_to_name_inlined`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct InlinedName {
    len: usize,
    name: [u8; IFNAMSIZ],
}

impl InlinedName {
    /// Returns the interface name as a string slice.
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// Returns the interface name's UTF-8 bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for InlinedName {
    fn as_ref(&self) -> &[u8] {
        &self.name[..self.len]
    }
}

impl AsRef<str> for InlinedName {
    fn as_ref(&self) -> &str {
        // `InlinedName` is constructed only after UTF-8 validation in
        // `index_to_name_inlined`.
        core::str::from_utf8(&self.name[..self.len]).unwrap()
    }
}

impl core::borrow::Borrow<str> for InlinedName {
    fn borrow(&self) -> &str {
        self.as_ref()
    }
}

impl core::fmt::Display for InlinedName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.as_str().fmt(formatter)
    }
}

/// Performs `SIOCGIFNAME` and returns the bounded name bytes plus length.
#[inline]
fn index_to_name_raw<Fd: AsFd>(fd: Fd, index: u32) -> Result<(usize, [u8; IFNAMSIZ])> {
    let mut request = Ifreq {
        name: [0; IFNAMSIZ],
        // SAFETY: All-zero bytes are a valid representation for the private
        // integer/storage union used by this ioctl request.
        data: unsafe { core::mem::zeroed() },
    };
    // `ifru_ifindex` is a signed 32-bit Linux integer. Rustix performs the
    // same low-bit-preserving cast from its public `u32` index.
    request.data.ifindex = index as i32;

    // SAFETY: `request` is the complete 40-byte Linux/AArch64 `ifreq` layout,
    // and SIOCGIFNAME reads its index member and writes the interface name.
    unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_fd().as_raw_fd(),
            SIOCGIFNAME,
            (&mut request as *mut Ifreq).cast(),
        )?;
    }

    let name = request.name;
    let Some(len) = name.iter().position(|byte| *byte == 0) else {
        return Err(crate::Errno::INVAL);
    };

    let mut output = [0; IFNAMSIZ];
    output[..len].copy_from_slice(&name[..len]);
    Ok((len, output))
}

const NETLINK_FAMILY: u16 = 16;
const NETLINK_ROUTE: i32 = 0;
const SOCK_RAW: u32 = 3;
const SOCK_CLOEXEC: u32 = 0x0008_0000;
const NLMSG_HEADER_LEN: usize = 16;
const NLMSG_REQUEST_LEN: usize = 20;
const NETLINK_BUFFER_LEN: usize = 8192;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;

const IFLA_IFNAME: u16 = 3;
const IFA_LABEL: u16 = 3;

// The link/address attributes used by the owned interface-address snapshot.
// Keep these separate from the C ABI's `struct ifaddrs`: the native records
// below own their bytes and never expose pointers into a packet or allocator
// owned by libc.
#[cfg(feature = "alloc")]
const IFLA_ADDRESS: u16 = 1;
#[cfg(feature = "alloc")]
const IFLA_BROADCAST: u16 = 2;
#[cfg(feature = "alloc")]
const IFLA_STATS: u16 = 7;
#[cfg(feature = "alloc")]
const IFLA_STATS64: u16 = 23;
#[cfg(feature = "alloc")]
const IFA_ADDRESS: u16 = 1;
#[cfg(feature = "alloc")]
const IFA_LOCAL: u16 = 2;
#[cfg(feature = "alloc")]
const IFA_BROADCAST: u16 = 4;
#[cfg(feature = "alloc")]
const AF_INET: u8 = 2;
#[cfg(feature = "alloc")]
const AF_INET6: u8 = 10;

const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTATTR_HEADER_LEN: usize = 4;

/// An owned Linux interface index/name pair.
///
/// The index is nonzero by construction and the name owns its complete
/// `IFNAMSIZ`-bounded storage through [`InlinedName`]. This is the native
/// Rust record emitted by [`for_each_link_name`] and returned by the
/// allocation-enabled [`if_nameindex`]; it contains no borrowed netlink
/// packet pointers or process-global storage.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct InterfaceNameIndex {
    index: NonZeroU32,
    name: InlinedName,
}

impl InterfaceNameIndex {
    /// Returns the nonzero Linux interface index.
    #[inline]
    #[must_use]
    pub const fn index(&self) -> NonZeroU32 {
        self.index
    }

    /// Returns the owned bounded interface name.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> &InlinedName {
        &self.name
    }

    /// Returns the interface name as UTF-8 text.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.name.as_str()
    }

    fn from_netlink(index: u32, bytes: &[u8]) -> Result<Self> {
        let Some(index) = NonZeroU32::new(index) else {
            return Err(crate::Errno::BADMSG);
        };
        if bytes.is_empty() || bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(crate::Errno::BADMSG);
        }
        let name = core::str::from_utf8(bytes).map_err(|_| crate::Errno::ILSEQ)?;
        let mut storage = [0; IFNAMSIZ];
        storage[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            index,
            // SAFETY: `name` validated the exact bytes copied into this
            // bounded record as UTF-8, and the length is less than IFNAMSIZ.
            name: InlinedName {
                len: name.len(),
                name: storage,
            },
        })
    }
}

/// Streams every valid `RTM_NEWLINK` interface name without allocating.
///
/// This is intentionally a link-only operation, not a spelling of musl's
/// `if_nameindex`: it issues one `RTM_GETLINK` dump and invokes `callback` for
/// each link carrying a valid `IFLA_IFNAME`. The callback receives an owned
/// fixed-capacity record, so it may retain or copy it after returning. The
/// callback's error stops the dump and is returned unchanged. Netlink kernel
/// errors, malformed message lengths, and direct socket failures remain typed
/// [`crate::Errno`] values; no libc, C ABI, allocator, or TLS `errno` is used.
#[inline]
pub fn for_each_link_name<F>(callback: F) -> Result<()>
where
    F: FnMut(InterfaceNameIndex) -> Result<()>,
{
    let mut callback = callback;
    enumerate_with_socket(&mut callback, false)
}

/// Returns musl-shaped interface names and indices with owned Rust storage.
///
/// This allocation-enabled counterpart of musl's `if_nameindex` performs both
/// the `RTM_GETLINK(AF_UNSPEC)` and `RTM_GETADDR(AF_INET)` dumps. Link records
/// use `IFLA_IFNAME`, address records use `IFA_LABEL`, and duplicate
/// `(index,name)` pairs are suppressed before the returned vector is exposed.
/// Allocation is explicit in the `alloc` feature and failures are reported as
/// [`crate::Errno::NOBUFS`]. Dropping the returned vector releases its owned
/// records; [`if_freenameindex`] is provided as a named consuming counterpart
/// for code translating the musl operation.
#[cfg(feature = "alloc")]
#[inline]
pub fn if_nameindex() -> Result<alloc::vec::Vec<InterfaceNameIndex>> {
    let mut names = alloc::vec::Vec::new();
    let result = {
        let mut callback = |record: InterfaceNameIndex| {
            if names.iter().any(|existing| existing == &record) {
                return Ok(());
            }
            names.try_reserve(1).map_err(|_| crate::Errno::NOBUFS)?;
            names.push(record);
            Ok(())
        };
        enumerate_with_socket(&mut callback, true)
    };
    result.map(|()| names)
}

/// Releases an owned result returned by [`if_nameindex`].
///
/// Rust ownership already makes `drop(names)` sufficient; this explicit
/// consuming function mirrors musl's `if_freenameindex` name without crossing
/// a public C ABI or calling a C allocator.
#[cfg(feature = "alloc")]
#[inline]
pub fn if_freenameindex(names: alloc::vec::Vec<InterfaceNameIndex>) {
    drop(names);
}

#[cfg(feature = "alloc")]
mod interface_addresses {
    use super::*;

    /// A bounded Linux interface name which preserves the kernel's raw bytes.
    ///
    /// Linux limits an interface name to `IFNAMSIZ - 1` bytes plus a terminating
    /// NUL.  This type deliberately does not require UTF-8; `IFLA_IFNAME` and
    /// `IFA_LABEL` are byte strings at the netlink boundary, and a native snapshot
    /// must not turn a valid non-UTF-8 name into an unrelated error or replacement
    /// string.  It is separate from [`InlinedName`], whose UTF-8 invariant is part
    /// of the existing ioctl-facing API.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct RawInterfaceName {
        len: usize,
        bytes: [u8; IFNAMSIZ],
    }

    impl RawInterfaceName {
        #[inline]
        fn from_netlink(bytes: &[u8]) -> Result<Self> {
            if bytes.is_empty() || bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
                return Err(crate::Errno::BADMSG);
            }
            let mut storage = [0u8; IFNAMSIZ];
            storage[..bytes.len()].copy_from_slice(bytes);
            Ok(Self {
                len: bytes.len(),
                bytes: storage,
            })
        }

        /// Returns the exact non-NUL name bytes supplied by the kernel.
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes[..self.len]
        }

        /// Returns the number of name bytes, excluding the kernel's NUL.
        #[must_use]
        pub const fn len(&self) -> usize {
            self.len
        }

        /// Returns whether the name has no bytes.
        #[must_use]
        pub const fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Interprets the name as UTF-8 when it happens to be text.
        #[must_use]
        pub fn to_str(&self) -> core::result::Result<&str, core::str::Utf8Error> {
            core::str::from_utf8(self.as_bytes())
        }
    }

    impl AsRef<[u8]> for RawInterfaceName {
        fn as_ref(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    /// A link-layer address copied from `IFLA_ADDRESS` or `IFLA_BROADCAST`.
    ///
    /// The kernel's `sockaddr_ll` address payload is bounded to 24 bytes.  The
    /// hardware type is the `ifi_type` field from the enclosing link message;
    /// bytes are retained in wire order and are never interpreted as an Ethernet
    /// address unless a caller chooses to do so.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct PacketAddress {
        hardware_type: u16,
        len: u8,
        bytes: [u8; 24],
    }

    impl PacketAddress {
        fn new(hardware_type: u16, bytes: &[u8]) -> Result<Self> {
            if bytes.len() > 24 {
                return Err(crate::Errno::BADMSG);
            }
            let mut storage = [0u8; 24];
            storage[..bytes.len()].copy_from_slice(bytes);
            Ok(Self {
                hardware_type,
                len: bytes.len() as u8,
                bytes: storage,
            })
        }

        /// Returns the Linux ARPHRD hardware type (`ifi_type`).
        #[must_use]
        pub const fn hardware_type(self) -> u16 {
            self.hardware_type
        }

        /// Returns the copied hardware address bytes.
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes[..self.len as usize]
        }

        /// Returns the copied hardware address length.
        #[must_use]
        pub const fn len(self) -> usize {
            self.len as usize
        }
    }

    /// An IP address together with the Linux interface scope used for link-local
    /// IPv6 addresses. IPv4 and IPv6 addresses outside the link-local/multicast
    /// link-local ranges always carry scope zero, even when the netlink message's
    /// `ifa_scope` field is nonzero.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct ScopedIpAddress {
        address: crate::net::IpAddress,
        scope_id: u32,
    }

    impl ScopedIpAddress {
        fn new(family: u8, bytes: &[u8], index: u32) -> Result<Self> {
            let address = match family {
                AF_INET if bytes.len() == 4 => {
                    crate::net::IpAddress::V4([bytes[0], bytes[1], bytes[2], bytes[3]])
                }
                AF_INET6 if bytes.len() == 16 => {
                    let mut value = [0u8; 16];
                    value.copy_from_slice(bytes);
                    crate::net::IpAddress::V6(value)
                }
                _ => return Err(crate::Errno::BADMSG),
            };
            let scope_id = if family == AF_INET6 && is_ipv6_link_scope(bytes) {
                index
            } else {
                0
            };
            Ok(Self { address, scope_id })
        }

        /// Returns the typed IPv4 or IPv6 address.
        #[must_use]
        pub const fn address(self) -> crate::net::IpAddress {
            self.address
        }

        /// Returns the interface index used to scope this address, or zero.
        #[must_use]
        pub const fn scope_id(self) -> u32 {
            self.scope_id
        }

        /// Returns the address bytes in network order, padded to 16 bytes for
        /// IPv4 in the same way as [`crate::net::IpAddress::octets`].
        #[must_use]
        pub const fn octets(self) -> [u8; 16] {
            self.address.octets()
        }
    }

    /// Returns whether an IPv6 address receives an interface scope identifier.
    ///
    /// `fe80::/10` is unicast link-local and multicast addresses are link-local
    /// when their low-nibble scope field is `2` (`ff02::/16`, including the flag
    /// variants such as `ff12::/16`). Treating every multicast address as
    /// link-local would incorrectly attach a scope to `ff05::/16` and the other
    /// administratively scoped multicast ranges.
    #[inline]
    fn is_ipv6_link_scope(bytes: &[u8]) -> bool {
        bytes.len() == 16
            && ((bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
                || (bytes[0] == 0xff && bytes[1] & 0x0f == 0x02))
    }

    /// A link record from an `RTM_NEWLINK` dump.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct InterfaceLink {
        index: core::num::NonZeroU32,
        name: RawInterfaceName,
        flags: u32,
        address: Option<PacketAddress>,
        broadcast: Option<PacketAddress>,
        stats: Option<alloc::vec::Vec<u8>>,
    }

    impl InterfaceLink {
        /// Returns the nonzero Linux interface index.
        #[must_use]
        pub const fn index(&self) -> core::num::NonZeroU32 {
            self.index
        }

        /// Returns the raw `IFLA_IFNAME` bytes.
        #[must_use]
        pub const fn name(&self) -> &RawInterfaceName {
            &self.name
        }

        /// Returns the Linux `ifi_flags` bit set.
        #[must_use]
        pub const fn flags(&self) -> u32 {
            self.flags
        }

        /// Returns the optional link-layer address.
        #[must_use]
        pub const fn address(&self) -> Option<PacketAddress> {
            self.address
        }

        /// Returns the optional link-layer broadcast address.
        #[must_use]
        pub const fn broadcast(&self) -> Option<PacketAddress> {
            self.broadcast
        }

        /// Returns copied opaque `IFLA_STATS` bytes.
        #[must_use]
        pub fn stats(&self) -> Option<&[u8]> {
            self.stats.as_deref()
        }
    }

    /// Whether an IP record carries an IPv4 broadcast or a point-to-point
    /// destination. These are intentionally distinct values rather than one
    /// nullable sockaddr union.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum IpPeer {
        /// The `IFA_BROADCAST` address.
        Broadcast(ScopedIpAddress),
        /// The peer from `IFA_ADDRESS` when `IFA_LOCAL` supplied the local end.
        Destination(ScopedIpAddress),
    }

    /// An IP record from an `RTM_NEWADDR` dump.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct InterfaceIp {
        index: core::num::NonZeroU32,
        name: RawInterfaceName,
        link_flags: u32,
        address_flags: u8,
        address: ScopedIpAddress,
        netmask: crate::net::IpAddress,
        broadcast: Option<ScopedIpAddress>,
        destination: Option<ScopedIpAddress>,
    }

    impl InterfaceIp {
        /// Returns the linked nonzero Linux interface index.
        #[must_use]
        pub const fn index(&self) -> core::num::NonZeroU32 {
            self.index
        }

        /// Returns `IFA_LABEL`, or the linked interface name when the label is
        /// absent, as raw bounded bytes.
        #[must_use]
        pub const fn name(&self) -> &RawInterfaceName {
            &self.name
        }

        /// Returns the linked `ifi_flags` bit set.
        #[must_use]
        pub const fn link_flags(&self) -> u32 {
            self.link_flags
        }

        /// Returns the address message's `ifa_flags` byte.
        #[must_use]
        pub const fn address_flags(&self) -> u8 {
            self.address_flags
        }

        /// Returns the local/primary typed IP address.
        #[must_use]
        pub const fn address(&self) -> ScopedIpAddress {
            self.address
        }

        /// Returns the prefix-derived typed netmask.
        #[must_use]
        pub const fn netmask(&self) -> crate::net::IpAddress {
            self.netmask
        }

        /// Returns a compact broadcast/destination view, preserving which netlink
        /// attribute supplied the selected value. Use [`Self::broadcast`] and
        /// [`Self::destination`] when both attributes are present.
        #[must_use]
        pub const fn peer(&self) -> Option<IpPeer> {
            match (self.broadcast, self.destination) {
                (Some(value), _) => Some(IpPeer::Broadcast(value)),
                (None, Some(value)) => Some(IpPeer::Destination(value)),
                (None, None) => None,
            }
        }

        /// Returns only the broadcast value, if this is a broadcast interface.
        #[must_use]
        pub const fn broadcast(&self) -> Option<ScopedIpAddress> {
            self.broadcast
        }

        /// Returns only the point-to-point destination, if `IFA_LOCAL` and
        /// `IFA_ADDRESS` supplied separate endpoints.
        #[must_use]
        pub const fn destination(&self) -> Option<ScopedIpAddress> {
            self.destination
        }
    }

    /// One owned entry in an [`InterfaceAddresses`] snapshot.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub enum InterfaceAddress {
        /// A link record emitted in `RTM_GETLINK` kernel order.
        Link(InterfaceLink),
        /// An IP record emitted in `RTM_GETADDR` kernel order.
        Ip(InterfaceIp),
    }

    /// Compatibility spelling for callers that prefer “record” to “entry”.
    pub type InterfaceAddressRecord = InterfaceAddress;

    /// Compatibility spelling for callers that prefer a short entry name.
    pub type InterfaceEntry = InterfaceAddress;

    /// An owned, ordered snapshot of Linux interface links and IP addresses.
    ///
    /// Construction performs a direct `RTM_GETLINK(AF_UNSPEC)` dump followed by a
    /// direct `RTM_GETADDR(AF_UNSPEC)` dump over one `NETLINK_ROUTE` socket. Every
    /// name, packet address, IP value, netmask, peer value, and link-statistics
    /// byte is copied into this value. Dropping it releases the Rust-owned `Vec`s;
    /// there is no C `freeifaddrs` analogue and no public C allocator boundary.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct InterfaceAddresses {
        entries: alloc::vec::Vec<InterfaceAddress>,
    }

    impl InterfaceAddresses {
        /// Collects the current kernel interface snapshot.
        pub fn new() -> Result<Self> {
            let entries = collect_interface_addresses()?;
            Ok(Self { entries })
        }

        /// Collects the current kernel interface snapshot.
        #[inline]
        pub fn collect() -> Result<Self> {
            Self::new()
        }

        /// Borrows entries in the order returned by the two kernel dumps.
        #[must_use]
        pub fn as_slice(&self) -> &[InterfaceAddress] {
            &self.entries
        }

        /// Borrows entries in the order returned by the two kernel dumps.
        #[must_use]
        pub fn entries(&self) -> &[InterfaceAddress] {
            self.as_slice()
        }

        /// Returns the number of owned records.
        #[must_use]
        pub const fn len(&self) -> usize {
            self.entries.len()
        }

        /// Returns whether the snapshot has no records.
        #[must_use]
        pub const fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        /// Transfers the owned records to the caller.
        #[must_use]
        pub fn into_vec(self) -> alloc::vec::Vec<InterfaceAddress> {
            self.entries
        }
    }

    impl core::ops::Deref for InterfaceAddresses {
        type Target = [InterfaceAddress];

        fn deref(&self) -> &Self::Target {
            self.as_slice()
        }
    }

    impl<'a> IntoIterator for &'a InterfaceAddresses {
        type Item = &'a InterfaceAddress;
        type IntoIter = core::slice::Iter<'a, InterfaceAddress>;

        fn into_iter(self) -> Self::IntoIter {
            self.entries.iter()
        }
    }

    fn collect_interface_addresses() -> Result<alloc::vec::Vec<InterfaceAddress>> {
        let fd = unsafe {
            // SAFETY: A successful direct socket syscall returns a fresh owned
            // descriptor. The private netlink protocol and type are fixed here.
            OwnedFd::from_raw_fd(crabc_core::net::socket(
                NETLINK_FAMILY as i32,
                SOCK_RAW | SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )?)
        };

        let mut entries = alloc::vec::Vec::new();
        let result = enumerate_interface_dump(&fd, InterfaceDump::Link, 1, &mut entries)
            .and_then(|()| enumerate_interface_dump(&fd, InterfaceDump::Address, 2, &mut entries));
        let close_result = fd.close();
        result.and(close_result).map(|()| entries)
    }

    #[derive(Copy, Clone)]
    enum InterfaceDump {
        Link,
        Address,
    }

    impl InterfaceDump {
        #[inline]
        const fn request_type(self) -> u16 {
            match self {
                Self::Link => RTM_GETLINK,
                Self::Address => RTM_GETADDR,
            }
        }

        #[inline]
        const fn record_type(self) -> u16 {
            match self {
                Self::Link => RTM_NEWLINK,
                Self::Address => RTM_NEWADDR,
            }
        }
    }

    fn enumerate_interface_dump(
        fd: &OwnedFd,
        dump: InterfaceDump,
        sequence: u32,
        entries: &mut alloc::vec::Vec<InterfaceAddress>,
    ) -> Result<()> {
        let mut request = [0u8; NLMSG_REQUEST_LEN];
        write_u32(&mut request, 0, NLMSG_REQUEST_LEN as u32);
        write_u16(&mut request, 4, dump.request_type());
        write_u16(&mut request, 6, NLM_F_REQUEST | NLM_F_DUMP);
        write_u32(&mut request, 8, sequence);
        // rtgenmsg family is AF_UNSPEC for both dumps.
        request[16] = 0;

        let mut address = [0u8; 12];
        write_u16(&mut address, 0, NETLINK_FAMILY);
        let sent = unsafe {
            // SAFETY: The request and sockaddr_nl bytes remain live and readable
            // for this complete direct sendto syscall.
            crabc_core::net::sendto_raw(
                fd.as_raw_fd(),
                request.as_ptr(),
                request.len(),
                0,
                address.as_ptr(),
                address.len() as u32,
            )?
        };
        if sent != request.len() {
            return Err(crate::Errno::IO);
        }

        let mut packet = [0u8; NETLINK_BUFFER_LEN];
        loop {
            let received = unsafe {
                // SAFETY: `packet` is writable for its complete fixed capacity;
                // no source address is requested from this connected netlink
                // receive boundary.
                crabc_core::net::recvfrom_raw(
                    fd.as_raw_fd(),
                    packet.as_mut_ptr(),
                    packet.len(),
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )?
            };
            if received == 0 {
                return Err(crate::Errno::IO);
            }
            if parse_interface_packet(&packet[..received], dump, sequence, entries)? {
                return Ok(());
            }
        }
    }

    fn parse_interface_packet(
        packet: &[u8],
        dump: InterfaceDump,
        sequence: u32,
        entries: &mut alloc::vec::Vec<InterfaceAddress>,
    ) -> Result<bool> {
        let mut offset = 0usize;
        let mut done = false;
        while offset < packet.len() {
            let remaining = packet.len() - offset;
            if remaining < NLMSG_HEADER_LEN {
                return Err(crate::Errno::BADMSG);
            }
            let length = read_u32(packet, offset)? as usize;
            if length < NLMSG_HEADER_LEN || length > remaining {
                return Err(crate::Errno::BADMSG);
            }
            let aligned = align4(length)?;
            if aligned > remaining {
                return Err(crate::Errno::BADMSG);
            }
            let message = &packet[offset..offset + aligned];
            if read_u32(message, 8)? != sequence {
                return Err(crate::Errno::BADMSG);
            }
            let message_type = read_u16(message, 4)?;
            let declared = &message[..length];
            match message_type {
                NLMSG_NOOP => {}
                NLMSG_DONE => done = true,
                NLMSG_OVERRUN => return Err(crate::Errno::OVERFLOW),
                NLMSG_ERROR => parse_netlink_error(declared)?,
                value if value == dump.record_type() => match dump {
                    InterfaceDump::Link => parse_interface_link(declared, entries)?,
                    InterfaceDump::Address => parse_interface_ip(declared, entries)?,
                },
                _ => {}
            }
            offset = offset.checked_add(aligned).ok_or(crate::Errno::BADMSG)?;
        }
        Ok(done)
    }

    fn push_interface_entry(
        entries: &mut alloc::vec::Vec<InterfaceAddress>,
        entry: InterfaceAddress,
    ) -> Result<()> {
        entries.try_reserve(1).map_err(|_| crate::Errno::NOBUFS)?;
        entries.push(entry);
        Ok(())
    }

    fn parse_interface_link(
        message: &[u8],
        entries: &mut alloc::vec::Vec<InterfaceAddress>,
    ) -> Result<()> {
        let declared = read_u32(message, 0)? as usize;
        if declared < NLMSG_HEADER_LEN + IFINFOMSG_LEN || declared > message.len() {
            return Err(crate::Errno::BADMSG);
        }
        let payload = &message[NLMSG_HEADER_LEN..declared];
        let index = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if index <= 0 {
            return Ok(());
        }
        let index = core::num::NonZeroU32::new(index as u32).ok_or(crate::Errno::BADMSG)?;
        let hardware_type = read_u16(payload, 2)?;
        let flags = read_u32(payload, 8)?;
        let mut name = None;
        let mut address = None;
        let mut broadcast = None;
        let mut stats = None;
        for_each_attribute(&payload[IFINFOMSG_LEN..], |kind, data| {
            match kind {
                IFLA_IFNAME => name = Some(parse_string_attribute(data)?),
                IFLA_ADDRESS => address = Some(PacketAddress::new(hardware_type, data)?),
                IFLA_BROADCAST => broadcast = Some(PacketAddress::new(hardware_type, data)?),
                IFLA_STATS | IFLA_STATS64 => {
                    let mut copied = alloc::vec::Vec::new();
                    copied
                        .try_reserve(data.len())
                        .map_err(|_| crate::Errno::NOBUFS)?;
                    copied.extend_from_slice(data);
                    stats = Some(copied);
                }
                _ => {}
            }
            Ok(())
        })?;
        let Some(name) = name else {
            // A link without IFLA_IFNAME is not useful to an ifaddrs-style view;
            // this is the same skip behavior as the existing link-name stream.
            return Ok(());
        };
        push_interface_entry(
            entries,
            InterfaceAddress::Link(InterfaceLink {
                index,
                name,
                flags,
                address,
                broadcast,
                stats,
            }),
        )
    }

    fn parse_interface_ip(
        message: &[u8],
        entries: &mut alloc::vec::Vec<InterfaceAddress>,
    ) -> Result<()> {
        let declared = read_u32(message, 0)? as usize;
        if declared < NLMSG_HEADER_LEN + IFADDRMSG_LEN || declared > message.len() {
            return Err(crate::Errno::BADMSG);
        }
        let payload = &message[NLMSG_HEADER_LEN..declared];
        let family = payload[0];
        let prefix_len = payload[1];
        let address_flags = payload[2];
        let _scope = payload[3];
        let index = read_u32(payload, 4)?;
        let Some(index) = core::num::NonZeroU32::new(index) else {
            return Ok(());
        };

        let expected_len = match family {
            AF_INET => 4,
            AF_INET6 => 16,
            // AF_UNSPEC dumps can contain families this vocabulary does not
            // represent. Validate framing/attributes, then safely skip them.
            _ => 0,
        };
        if expected_len == 0 {
            // Preserve the netlink framing check for an unrepresented family, but
            // do not interpret its attributes as IPv4/IPv6 payloads. In
            // particular, a valid IFA_ADDRESS for another family need not fit the
            // zero-byte native address shape.
            for_each_attribute(&payload[IFADDRMSG_LEN..], |_, _| Ok(()))?;
            return Ok(());
        }
        let mut address_bytes = None::<[u8; 16]>;
        let mut local_bytes = None::<[u8; 16]>;
        let mut broadcast = None::<[u8; 16]>;
        let mut label = None;
        for_each_attribute(&payload[IFADDRMSG_LEN..], |kind, data| {
            match kind {
                IFA_ADDRESS => {
                    if expected_len != 0 && data.len() != expected_len {
                        return Err(crate::Errno::BADMSG);
                    }
                    let mut copied = [0u8; 16];
                    copied[..expected_len].copy_from_slice(data);
                    address_bytes = Some(copied);
                }
                IFA_LOCAL => {
                    if expected_len != 0 && data.len() != expected_len {
                        return Err(crate::Errno::BADMSG);
                    }
                    let mut copied = [0u8; 16];
                    copied[..expected_len].copy_from_slice(data);
                    local_bytes = Some(copied);
                }
                IFA_BROADCAST => {
                    if expected_len != 0 && data.len() != expected_len {
                        return Err(crate::Errno::BADMSG);
                    }
                    let mut copied = [0u8; 16];
                    copied[..expected_len].copy_from_slice(data);
                    broadcast = Some(copied);
                }
                IFA_LABEL => label = Some(parse_string_attribute(data)?),
                _ => {}
            }
            Ok(())
        })?;
        if usize::from(prefix_len) > if family == AF_INET { 32 } else { 128 } {
            return Err(crate::Errno::BADMSG);
        }

        // Address records are meaningful only after their RTM_GETLINK record has
        // been seen. The dump ordering lets this remain a small bounded linear
        // lookup without a second allocation or a process-global map.
        let Some((link_name, link_flags)) = entries.iter().find_map(|entry| match entry {
            InterfaceAddress::Link(link) if link.index == index => Some((link.name, link.flags)),
            _ => None,
        }) else {
            return Ok(());
        };

        // IFA_LOCAL is the primary address whenever present. IFA_ADDRESS is then
        // the point-to-point destination, independent of netlink attribute order.
        let primary = local_bytes.as_ref().or(address_bytes.as_ref());
        let Some(primary) = primary else {
            return Ok(());
        };
        let address = ScopedIpAddress::new(family, &primary[..expected_len], index.get())?;
        let netmask = prefix_netmask(family, prefix_len)?;
        // IFA_LOCAL is the primary address whenever present. An IFA_ADDRESS
        // value alongside it is the point-to-point destination, independent of
        // netlink attribute order. For a normal interface with no local attr,
        // IFA_BROADCAST is kept as a distinct peer kind.
        let destination = if local_bytes.is_some() {
            address_bytes
                .as_ref()
                .map(|value| ScopedIpAddress::new(family, &value[..expected_len], index.get()))
                .transpose()?
        } else {
            None
        };
        let broadcast = broadcast
            .as_ref()
            .map(|value| ScopedIpAddress::new(family, &value[..expected_len], index.get()))
            .transpose()?;

        let name = label.unwrap_or(link_name);
        push_interface_entry(
            entries,
            InterfaceAddress::Ip(InterfaceIp {
                index,
                name,
                link_flags,
                address_flags,
                address,
                netmask,
                broadcast,
                destination,
            }),
        )
    }

    fn parse_string_attribute(data: &[u8]) -> Result<RawInterfaceName> {
        if data.len() < 2 || data.last().copied() != Some(0) || data[..data.len() - 1].contains(&0)
        {
            return Err(crate::Errno::BADMSG);
        }
        RawInterfaceName::from_netlink(&data[..data.len() - 1])
    }

    fn for_each_attribute<F>(attributes: &[u8], mut callback: F) -> Result<()>
    where
        F: FnMut(u16, &[u8]) -> Result<()>,
    {
        let mut offset = 0usize;
        while offset < attributes.len() {
            let remaining = attributes.len() - offset;
            if remaining < RTATTR_HEADER_LEN {
                return Err(crate::Errno::BADMSG);
            }
            let length = read_u16(attributes, offset)? as usize;
            if length < RTATTR_HEADER_LEN || length > remaining {
                return Err(crate::Errno::BADMSG);
            }
            let aligned = align4(length)?;
            if aligned > remaining {
                return Err(crate::Errno::BADMSG);
            }
            let kind = read_u16(attributes, offset + 2)? & 0x3fff;
            callback(
                kind,
                &attributes[offset + RTATTR_HEADER_LEN..offset + length],
            )?;
            offset = offset.checked_add(aligned).ok_or(crate::Errno::BADMSG)?;
        }
        Ok(())
    }

    fn prefix_netmask(family: u8, prefix_len: u8) -> Result<crate::net::IpAddress> {
        let (bits, bytes) = match family {
            AF_INET => (32usize, 4usize),
            AF_INET6 => (128usize, 16usize),
            _ => return Err(crate::Errno::BADMSG),
        };
        let prefix_len = usize::from(prefix_len);
        if prefix_len > bits {
            return Err(crate::Errno::BADMSG);
        }
        let mut value = [0u8; 16];
        let full_bytes = prefix_len / 8;
        let partial_bits = prefix_len % 8;
        let mut index = 0usize;
        while index < full_bytes {
            value[index] = 0xff;
            index += 1;
        }
        if partial_bits != 0 {
            value[full_bytes] = 0xff << (8 - partial_bits);
        }
        if bytes == 4 {
            Ok(crate::net::IpAddress::V4([
                value[0], value[1], value[2], value[3],
            ]))
        } else {
            Ok(crate::net::IpAddress::V6(value))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }

        fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn attribute(kind: u16, data: &[u8]) -> alloc::vec::Vec<u8> {
            let length = RTATTR_HEADER_LEN + data.len();
            let aligned = align4(length).expect("test attribute aligns");
            let mut output = alloc::vec![0u8; aligned];
            put_u16(&mut output, 0, length as u16);
            put_u16(&mut output, 2, kind);
            output[RTATTR_HEADER_LEN..length].copy_from_slice(data);
            output
        }

        fn message(kind: u16, sequence: u32, payload: &[u8]) -> alloc::vec::Vec<u8> {
            let length = NLMSG_HEADER_LEN + payload.len();
            let aligned = align4(length).expect("test message aligns");
            let mut output = alloc::vec![0u8; aligned];
            put_u32(&mut output, 0, length as u32);
            put_u16(&mut output, 4, kind);
            put_u32(&mut output, 8, sequence);
            output[NLMSG_HEADER_LEN..length].copy_from_slice(payload);
            output
        }

        fn link_message() -> alloc::vec::Vec<u8> {
            let mut payload = alloc::vec![0u8; IFINFOMSG_LEN];
            put_u16(&mut payload, 2, 772); // ARPHRD_LOOPBACK
            put_u32(&mut payload, 4, 1);
            put_u32(&mut payload, 8, 0x1234);
            payload.extend(attribute(IFLA_IFNAME, &[b'l', 0x80, 0]));
            payload.extend(attribute(IFLA_ADDRESS, &[1, 2, 3, 4, 5, 6]));
            payload.extend(attribute(IFLA_BROADCAST, &[7, 8, 9]));
            payload.extend(attribute(IFLA_STATS, &[0xaa, 0xbb, 0xcc]));
            message(RTM_NEWLINK, 1, &payload)
        }

        fn address_message(
            sequence: u32,
            family: u8,
            prefix: u8,
            index: u32,
            attributes: &[u8],
        ) -> alloc::vec::Vec<u8> {
            let mut payload = alloc::vec![family, prefix, 7, 0];
            payload.extend_from_slice(&index.to_le_bytes());
            payload.extend_from_slice(attributes);
            message(RTM_NEWADDR, sequence, &payload)
        }

        #[test]
        fn link_parser_preserves_raw_name_packet_values_flags_and_stats() {
            let packet = link_message();
            let mut entries = alloc::vec::Vec::new();
            assert!(
                !parse_interface_packet(&packet, InterfaceDump::Link, 1, &mut entries)
                    .expect("parse synthetic link")
            );
            let InterfaceAddress::Link(link) = &entries[0] else {
                panic!("expected link entry")
            };
            assert_eq!(link.index().get(), 1);
            assert_eq!(link.name().as_bytes(), &[b'l', 0x80]);
            assert_eq!(link.flags(), 0x1234);
            let packet_address = link.address().expect("packet address");
            assert_eq!(packet_address.hardware_type(), 772);
            assert_eq!(packet_address.as_bytes(), &[1, 2, 3, 4, 5, 6]);
            assert_eq!(
                link.broadcast().expect("packet broadcast").as_bytes(),
                &[7, 8, 9]
            );
            assert_eq!(link.stats(), Some(&[0xaa, 0xbb, 0xcc][..]));
        }

        #[test]
        fn ip_parser_uses_local_as_primary_regardless_of_attribute_order() {
            let mut entries = alloc::vec::Vec::new();
            let link = link_message();
            parse_interface_packet(&link, InterfaceDump::Link, 1, &mut entries)
                .expect("parse synthetic link");
            let mut attributes = alloc::vec::Vec::new();
            // Put IFA_ADDRESS before IFA_LOCAL to cover point-to-point order.
            attributes.extend(attribute(IFA_ADDRESS, &[10, 0, 0, 2]));
            attributes.extend(attribute(IFA_LABEL, &[b'p', b'2', b'p', 0]));
            attributes.extend(attribute(IFA_LOCAL, &[10, 0, 0, 1]));
            let packet = address_message(2, AF_INET, 24, 1, &attributes);
            parse_interface_packet(&packet, InterfaceDump::Address, 2, &mut entries)
                .expect("parse synthetic address");
            let InterfaceAddress::Ip(ip) = &entries[1] else {
                panic!("expected IP entry")
            };
            assert_eq!(ip.name().as_bytes(), b"p2p");
            assert_eq!(
                ip.address().address(),
                crate::net::IpAddress::V4([10, 0, 0, 1])
            );
            assert_eq!(
                ip.destination().expect("P2P destination").address(),
                crate::net::IpAddress::V4([10, 0, 0, 2])
            );
            assert_eq!(ip.broadcast(), None);
            assert_eq!(ip.netmask(), crate::net::IpAddress::V4([255, 255, 255, 0]));
        }

        #[test]
        fn ipv6_scope_is_limited_to_unicast_and_multicast_link_local() {
            let mut entries = alloc::vec::Vec::new();
            let link = link_message();
            parse_interface_packet(&link, InterfaceDump::Link, 1, &mut entries)
                .expect("parse synthetic link");
            // The transient flag makes this `ff12`, proving that the scope
            // predicate uses the low nibble rather than requiring `ff02` exactly.
            let multicast_link_local = [0xff, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let multicast_site_local = [0xff, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let mut attrs = alloc::vec::Vec::new();
            attrs.extend(attribute(IFA_ADDRESS, &multicast_link_local));
            let packet = address_message(2, AF_INET6, 64, 1, &attrs);
            parse_interface_packet(&packet, InterfaceDump::Address, 2, &mut entries)
                .expect("parse multicast link-local");
            let mut attrs = alloc::vec::Vec::new();
            attrs.extend(attribute(IFA_ADDRESS, &multicast_site_local));
            let packet = address_message(2, AF_INET6, 64, 1, &attrs);
            parse_interface_packet(&packet, InterfaceDump::Address, 2, &mut entries)
                .expect("parse site-local multicast");
            let InterfaceAddress::Ip(link_local) = &entries[1] else {
                panic!("expected IPv6 entry")
            };
            let InterfaceAddress::Ip(site_local) = &entries[2] else {
                panic!("expected IPv6 entry")
            };
            assert_eq!(link_local.address().scope_id(), 1);
            assert_eq!(site_local.address().scope_id(), 0);
            assert_eq!(
                link_local.netmask(),
                crate::net::IpAddress::V6([
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
                ])
            );
        }

        #[test]
        fn malformed_attributes_and_unlinked_addresses_are_rejected_or_skipped() {
            let mut entries = alloc::vec::Vec::new();
            let mut payload = alloc::vec![0u8; IFINFOMSG_LEN];
            put_u32(&mut payload, 4, 1);
            // rta_len smaller than the four-byte attribute header.
            payload.extend_from_slice(&[2, 0, IFLA_IFNAME as u8, 0]);
            let packet = message(RTM_NEWLINK, 1, &payload);
            assert_eq!(
                parse_interface_packet(&packet, InterfaceDump::Link, 1, &mut entries),
                Err(crate::Errno::BADMSG)
            );

            let mut attrs = alloc::vec::Vec::new();
            attrs.extend(attribute(IFA_ADDRESS, &[192, 0, 2, 1]));
            let packet = address_message(2, AF_INET, 24, 99, &attrs);
            parse_interface_packet(&packet, InterfaceDump::Address, 2, &mut entries)
                .expect("unlinked address is skipped");
            assert!(entries.is_empty());
        }

        #[test]
        fn unrepresented_address_family_validates_framing_without_ip_copy() {
            let mut entries = alloc::vec::Vec::new();
            let mut attributes = alloc::vec::Vec::new();
            attributes.extend(attribute(IFA_ADDRESS, &[1, 2, 3]));
            let packet = address_message(2, 42, 0, 1, &attributes);

            parse_interface_packet(&packet, InterfaceDump::Address, 2, &mut entries)
                .expect("unknown families are ignored after framing validation");
            assert!(entries.is_empty());
        }
    }
}

#[cfg(feature = "alloc")]
pub use interface_addresses::*;

#[derive(Copy, Clone)]
enum NetlinkDump {
    Link,
    Address,
}

impl NetlinkDump {
    #[inline]
    const fn request_type(self) -> u16 {
        match self {
            Self::Link => RTM_GETLINK,
            Self::Address => RTM_GETADDR,
        }
    }

    #[inline]
    const fn family(self) -> u8 {
        match self {
            Self::Link => 0,    // AF_UNSPEC
            Self::Address => 2, // AF_INET
        }
    }

    #[inline]
    const fn record_type(self) -> u16 {
        match self {
            Self::Link => RTM_NEWLINK,
            Self::Address => RTM_NEWADDR,
        }
    }

    #[inline]
    const fn payload_len(self) -> usize {
        match self {
            Self::Link => IFINFOMSG_LEN,
            Self::Address => IFADDRMSG_LEN,
        }
    }

    #[inline]
    const fn name_attribute(self) -> u16 {
        match self {
            Self::Link => IFLA_IFNAME,
            Self::Address => IFA_LABEL,
        }
    }
}

fn enumerate_with_socket<F>(callback: &mut F, include_addresses: bool) -> Result<()>
where
    F: FnMut(InterfaceNameIndex) -> Result<()>,
{
    let fd = unsafe {
        // SAFETY: A successful direct socket syscall returns a fresh owned
        // descriptor. The private netlink protocol and type are fixed here.
        OwnedFd::from_raw_fd(crabc_core::net::socket(
            NETLINK_FAMILY as i32,
            SOCK_RAW | SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )?)
    };

    let result = enumerate_dump(&fd, NetlinkDump::Link, 1, callback);
    let result = if result.is_ok() && include_addresses {
        enumerate_dump(&fd, NetlinkDump::Address, 2, callback)
    } else {
        result
    };
    // Consume the owner explicitly so this operation exercises the direct
    // close boundary even when a callback or netlink parser reports failure.
    let close_result = fd.close();
    result.and(close_result)
}

fn enumerate_dump<F>(fd: &OwnedFd, dump: NetlinkDump, sequence: u32, callback: &mut F) -> Result<()>
where
    F: FnMut(InterfaceNameIndex) -> Result<()>,
{
    let mut request = [0u8; NLMSG_REQUEST_LEN];
    write_u32(&mut request, 0, NLMSG_REQUEST_LEN as u32);
    write_u16(&mut request, 4, dump.request_type());
    write_u16(&mut request, 6, NLM_F_REQUEST | NLM_F_DUMP);
    write_u32(&mut request, 8, sequence);
    // The sender port ID is zero and the rtgenmsg family occupies byte 16.
    request[16] = dump.family();

    let mut address = [0u8; 12];
    write_u16(&mut address, 0, NETLINK_FAMILY);
    // nl_pad, nl_pid, and nl_groups remain zero for a kernel-directed dump.
    let sent = unsafe {
        // SAFETY: The request and sockaddr_nl bytes remain live and readable
        // for this complete direct sendto syscall.
        crabc_core::net::sendto_raw(
            fd.as_raw_fd(),
            request.as_ptr(),
            request.len(),
            0,
            address.as_ptr(),
            address.len() as u32,
        )?
    };
    if sent != request.len() {
        return Err(crate::Errno::IO);
    }

    let mut packet = [0u8; NETLINK_BUFFER_LEN];
    loop {
        let received = unsafe {
            // SAFETY: `packet` is writable for its complete fixed capacity;
            // no source address is requested from this connected netlink
            // receive boundary.
            crabc_core::net::recvfrom_raw(
                fd.as_raw_fd(),
                packet.as_mut_ptr(),
                packet.len(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )?
        };
        if received == 0 {
            return Err(crate::Errno::IO);
        }
        parse_netlink_packet(&packet[..received], dump, sequence, callback)?;
        if packet_contains_done(&packet[..received], sequence)? {
            return Ok(());
        }
    }
}

fn parse_netlink_packet<F>(
    packet: &[u8],
    dump: NetlinkDump,
    sequence: u32,
    callback: &mut F,
) -> Result<()>
where
    F: FnMut(InterfaceNameIndex) -> Result<()>,
{
    let mut offset = 0usize;
    while offset < packet.len() {
        let remaining = packet.len() - offset;
        if remaining < NLMSG_HEADER_LEN {
            return Err(crate::Errno::BADMSG);
        }
        let length = read_u32(packet, offset)? as usize;
        if length < NLMSG_HEADER_LEN || length > remaining {
            return Err(crate::Errno::BADMSG);
        }
        let aligned = align4(length)?;
        if aligned > remaining {
            return Err(crate::Errno::BADMSG);
        }
        // Include the alignment padding in the private parser view. The
        // declared `nlmsg_len` still bounds payload/attributes; the extra
        // bytes only make a final attribute's four-byte alignment visible.
        let message = &packet[offset..offset + aligned];
        let message_sequence = read_u32(message, 8)?;
        if message_sequence != sequence {
            return Err(crate::Errno::BADMSG);
        }
        let message_type = read_u16(message, 4)?;
        match message_type {
            NLMSG_NOOP => {}
            NLMSG_DONE => return Ok(()),
            NLMSG_OVERRUN => return Err(crate::Errno::OVERFLOW),
            NLMSG_ERROR => parse_netlink_error(message)?,
            value if value == dump.record_type() => {
                if let Some(record) = parse_name_record(message, dump)? {
                    callback(record)?;
                }
            }
            // A dump can contain future record types. Once the bounded
            // framing has been validated, ignoring unknown records preserves
            // forward compatibility without interpreting unknown payloads.
            _ => {}
        }
        offset = offset.checked_add(aligned).ok_or(crate::Errno::BADMSG)?;
    }
    Ok(())
}

fn packet_contains_done(packet: &[u8], sequence: u32) -> Result<bool> {
    let mut offset = 0usize;
    while offset < packet.len() {
        let remaining = packet.len() - offset;
        if remaining < NLMSG_HEADER_LEN {
            return Err(crate::Errno::BADMSG);
        }
        let length = read_u32(packet, offset)? as usize;
        if length < NLMSG_HEADER_LEN || length > remaining {
            return Err(crate::Errno::BADMSG);
        }
        let aligned = align4(length)?;
        if aligned > remaining {
            return Err(crate::Errno::BADMSG);
        }
        if read_u32(packet, offset + 8)? != sequence {
            return Err(crate::Errno::BADMSG);
        }
        if read_u16(packet, offset + 4)? == NLMSG_DONE {
            return Ok(true);
        }
        offset = offset.checked_add(aligned).ok_or(crate::Errno::BADMSG)?;
    }
    Ok(false)
}

fn parse_netlink_error(message: &[u8]) -> Result<()> {
    if message.len() < NLMSG_HEADER_LEN + 4 {
        return Err(crate::Errno::BADMSG);
    }
    let raw = i32::from_le_bytes([
        message[NLMSG_HEADER_LEN],
        message[NLMSG_HEADER_LEN + 1],
        message[NLMSG_HEADER_LEN + 2],
        message[NLMSG_HEADER_LEN + 3],
    ]);
    if raw == 0 {
        return Ok(());
    }
    if raw >= 0 {
        return Err(crate::Errno::BADMSG);
    }
    let errno = raw.checked_neg().ok_or(crate::Errno::BADMSG)?;
    Err(crate::Errno::from_raw(errno).ok_or(crate::Errno::BADMSG)?)
}

fn parse_name_record(message: &[u8], dump: NetlinkDump) -> Result<Option<InterfaceNameIndex>> {
    let payload_len = dump.payload_len();
    let declared_length = read_u32(message, 0)? as usize;
    if declared_length < NLMSG_HEADER_LEN + payload_len || declared_length > message.len() {
        return Err(crate::Errno::BADMSG);
    }
    let payload = &message[NLMSG_HEADER_LEN..declared_length];
    let final_padding = message.len() - declared_length;
    let index = match dump {
        NetlinkDump::Link => {
            let raw = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            if raw <= 0 {
                return Ok(None);
            }
            raw as u32
        }
        NetlinkDump::Address => read_u32(payload, 4)?,
    };
    if index == 0 {
        return Ok(None);
    }
    let attributes = &payload[payload_len..];
    let wanted = dump.name_attribute();
    let mut offset = 0usize;
    while offset < attributes.len() {
        let remaining = attributes.len() - offset;
        if remaining < RTATTR_HEADER_LEN {
            return Err(crate::Errno::BADMSG);
        }
        let length = read_u16(attributes, offset)? as usize;
        if length < RTATTR_HEADER_LEN || length > remaining {
            return Err(crate::Errno::BADMSG);
        }
        let aligned = align4(length)?;
        if aligned > remaining.saturating_add(final_padding) {
            return Err(crate::Errno::BADMSG);
        }
        let kind = read_u16(attributes, offset + 2)? & 0x3fff;
        if kind == wanted {
            let data = &attributes[offset + RTATTR_HEADER_LEN..offset + length];
            // Linux string attributes are strict NUL-terminated payloads. Do
            // not silently truncate interior NULs or accept trailing bytes:
            // that would turn malformed kernel wire data into a different
            // public interface name.
            if data.len() < 2
                || data.last().copied() != Some(0)
                || data[..data.len() - 1].contains(&0)
            {
                return Err(crate::Errno::BADMSG);
            }
            return InterfaceNameIndex::from_netlink(index, &data[..data.len() - 1]).map(Some);
        }
        offset = offset.checked_add(aligned).ok_or(crate::Errno::BADMSG)?;
    }
    Ok(None)
}

fn align4(length: usize) -> Result<usize> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(crate::Errno::BADMSG)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset.checked_add(2).ok_or(crate::Errno::BADMSG)?;
    let value = bytes.get(offset..end).ok_or(crate::Errno::BADMSG)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(crate::Errno::BADMSG)?;
    let value = bytes.get(offset..end).ok_or(crate::Errno::BADMSG)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        align4, parse_netlink_packet, write_u16, write_u32, InterfaceNameIndex, NetlinkDump,
        IFA_LABEL, IFLA_IFNAME, NLMSG_HEADER_LEN, RTM_NEWADDR, RTM_NEWLINK,
    };

    #[test]
    fn malformed_netlink_message_lengths_are_rejected() {
        let mut packet = [0u8; NLMSG_HEADER_LEN];
        packet[..4].copy_from_slice(&8u32.to_le_bytes());
        packet[8..12].copy_from_slice(&1u32.to_le_bytes());
        let mut callback = |_| Ok(());
        assert_eq!(
            parse_netlink_packet(&packet, NetlinkDump::Link, 1, &mut callback),
            Err(crate::Errno::BADMSG)
        );
    }

    #[test]
    fn netlink_alignment_is_checked_without_overflow() {
        assert_eq!(align4(16).expect("aligned header"), 16);
        assert_eq!(align4(usize::MAX), Err(crate::Errno::BADMSG));
    }

    #[test]
    fn link_ifname_attribute_becomes_an_owned_record() {
        let mut packet = [0u8; 40];
        write_u32(&mut packet, 0, 39);
        write_u16(&mut packet, 4, RTM_NEWLINK);
        write_u32(&mut packet, 8, 1);
        packet[20..24].copy_from_slice(&1i32.to_le_bytes());
        write_u16(&mut packet, 32, 7);
        write_u16(&mut packet, 34, IFLA_IFNAME);
        packet[36..39].copy_from_slice(b"lo\0");

        let mut record = None;
        parse_netlink_packet(&packet, NetlinkDump::Link, 1, &mut |entry| {
            record = Some(entry);
            Ok(())
        })
        .expect("parse a valid RTM_NEWLINK packet");
        let record: InterfaceNameIndex = record.expect("IFLA_IFNAME record");
        assert_eq!(record.index().get(), 1);
        assert_eq!(record.as_str(), "lo");
    }

    #[test]
    fn address_ifa_label_attribute_becomes_an_owned_record() {
        let mut packet = [0u8; 36];
        write_u32(&mut packet, 0, 33);
        write_u16(&mut packet, 4, RTM_NEWADDR);
        write_u32(&mut packet, 8, 2);
        packet[20..24].copy_from_slice(&2u32.to_le_bytes());
        write_u16(&mut packet, 24, 9);
        write_u16(&mut packet, 26, IFA_LABEL);
        packet[28..33].copy_from_slice(b"eth0\0");

        let mut record = None;
        parse_netlink_packet(&packet, NetlinkDump::Address, 2, &mut |entry| {
            record = Some(entry);
            Ok(())
        })
        .expect("parse a valid RTM_NEWADDR packet");
        let record: InterfaceNameIndex = record.expect("IFA_LABEL record");
        assert_eq!(record.index().get(), 2);
        assert_eq!(record.as_str(), "eth0");
    }

    #[test]
    fn missing_name_attribute_is_skipped() {
        let mut packet = [0u8; 32];
        write_u32(&mut packet, 0, 32);
        write_u16(&mut packet, 4, RTM_NEWLINK);
        write_u32(&mut packet, 8, 1);
        packet[20..24].copy_from_slice(&1i32.to_le_bytes());

        let mut called = false;
        parse_netlink_packet(&packet, NetlinkDump::Link, 1, &mut |_| {
            called = true;
            Ok(())
        })
        .expect("missing IFLA_IFNAME is not malformed");
        assert!(!called);
    }

    #[test]
    fn name_attribute_requires_one_terminal_nul() {
        let mut packet = [0u8; 44];
        write_u32(&mut packet, 0, 41);
        write_u16(&mut packet, 4, RTM_NEWLINK);
        write_u32(&mut packet, 8, 1);
        packet[20..24].copy_from_slice(&1i32.to_le_bytes());
        write_u16(&mut packet, 32, 9);
        write_u16(&mut packet, 34, IFLA_IFNAME);
        packet[36..41].copy_from_slice(b"lo\0x\0");

        assert_eq!(
            parse_netlink_packet(&packet, NetlinkDump::Link, 1, &mut |_| Ok(())),
            Err(crate::Errno::BADMSG)
        );
    }
}
