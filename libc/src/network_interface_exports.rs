// Linux interface-name APIs.  The two point lookups use the kernel's ioctl
// interface, while if_nameindex uses the rtnetlink link dump so that every
// interface currently present in the namespace is returned (including links
// without an address).  Keep the wire layouts local: these are Linux UAPI
// layouts, not the public C `struct ifreq` ABI.

const CABI_IF_NAMESIZE: usize = 16;
const CABI_IFREQ_SIZE: usize = 40;
const CABI_IFR_INDEX_OFFSET: usize = 16;
const CABI_SIOCGIFNAME: u32 = 0x8910;
const CABI_SIOCGIFINDEX: u32 = 0x8933;
const CABI_AF_NETLINK: c_int = 16;
const CABI_NETLINK_ROUTE: c_int = 0;
const CABI_SOCK_RAW: c_int = 3;
const CABI_SOCK_CLOEXEC: c_int = 0x80000;
const CABI_NLM_F_REQUEST: u16 = 1;
const CABI_NLM_F_DUMP: u16 = 0x300;
const CABI_NLMSG_NOOP: u16 = 1;
const CABI_NLMSG_ERROR: u16 = 2;
const CABI_NLMSG_DONE: u16 = 3;
const CABI_NLMSG_OVERRUN: u16 = 4;
const CABI_RTM_NEWLINK: u16 = 16;
const CABI_RTM_GETLINK: u16 = 18;
const CABI_IFLA_IFNAME: u16 = 3;
const CABI_NETLINK_BUFFER_SIZE: usize = 32 * 1024;

#[repr(C)]
pub struct CabiIfNameIndex {
    pub if_index: c_uint,
    pub if_name: *mut c_char,
}

#[repr(C)]
struct CabiNetlinkHeader {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
struct CabiNetlinkDumpRequest {
    header: CabiNetlinkHeader,
    family: u8,
    _padding: [u8; 3],
}

#[repr(C)]
struct CabiNetlinkAddress {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
struct CabiIfInfoMessage {
    ifi_family: u8,
    _ifi_pad: u8,
    ifi_type: u16,
    ifi_index: c_int,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
struct CabiRouteAttribute {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
struct CabiIfNameMap {
    index: c_uint,
    name_len: u8,
    name: [u8; CABI_IF_NAMESIZE],
}

struct CabiIfNameMapContext {
    list: *mut CabiIfNameMap,
    count: usize,
    capacity: usize,
    string_bytes: usize,
}

#[inline]
unsafe fn cabi_if_ioctl_request(fd: c_int, request: u32, ifr: *mut u8) -> i64 {
    sys_ioctl(fd, request, ifr)
}

// Add a single netlink name to the temporary map.  RTM_GETLINK emits one
// IFLA_IFNAME attribute per link, but suppress duplicates defensively because
// the public API promises one entry per interface index.
unsafe fn cabi_if_map_add(
    ctx: &mut CabiIfNameMapContext,
    index: c_uint,
    name: *const u8,
    name_len: usize,
) -> bool {
    if index == 0 || name.is_null() || name_len == 0 || name_len >= CABI_IF_NAMESIZE {
        return true;
    }

    let mut i = 0;
    while i < ctx.count {
        let existing = &*ctx.list.add(i);
        if existing.index == index
            && existing.name_len as usize == name_len
            && core::slice::from_raw_parts(existing.name.as_ptr(), name_len)
                == core::slice::from_raw_parts(name, name_len)
        {
            return true;
        }
        i += 1;
    }

    if ctx.count == ctx.capacity {
        let next_capacity = if ctx.capacity == 0 {
            8
        } else {
            match ctx.capacity.checked_mul(2) {
                Some(value) => value,
                None => {
                    cabi_interface_set_errno(ENOBUFS_VAL);
                    return false;
                }
            }
        };
        let bytes = match next_capacity.checked_mul(core::mem::size_of::<CabiIfNameMap>()) {
            Some(value) => value,
            None => {
                cabi_interface_set_errno(ENOBUFS_VAL);
                return false;
            }
        };
        let next = realloc(ctx.list as *mut c_void, bytes) as *mut CabiIfNameMap;
        if next.is_null() {
            return false;
        }
        ctx.list = next;
        ctx.capacity = next_capacity;
    }

    let map = &mut *ctx.list.add(ctx.count);
    map.index = index;
    map.name_len = name_len as u8;
    core::ptr::copy_nonoverlapping(name, map.name.as_mut_ptr(), name_len);
    let string_bytes = match name_len.checked_add(1) {
        Some(value) => value,
        None => {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
    };
    ctx.string_bytes = match ctx.string_bytes.checked_add(string_bytes) {
        Some(value) => value,
        None => {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
    };
    ctx.count += 1;
    true
}

// Parse one RTM_NEWLINK message.  A malformed kernel message is treated as a
// failed enumeration rather than allowing an unchecked attribute length to
// escape the receive buffer.
unsafe fn cabi_if_parse_link(
    message: *const u8,
    message_len: usize,
    ctx: &mut CabiIfNameMapContext,
) -> bool {
    if message_len < core::mem::size_of::<CabiNetlinkHeader>() + core::mem::size_of::<CabiIfInfoMessage>() {
        cabi_interface_set_errno(ENOBUFS_VAL);
        return false;
    }
    let info = core::ptr::read_unaligned(
        message.add(core::mem::size_of::<CabiNetlinkHeader>()) as *const CabiIfInfoMessage,
    );
    if info.ifi_index <= 0 {
        return true;
    }

    let mut offset = core::mem::size_of::<CabiNetlinkHeader>()
        + core::mem::size_of::<CabiIfInfoMessage>();
    while offset < message_len {
        if message_len - offset < core::mem::size_of::<CabiRouteAttribute>() {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        let attribute = core::ptr::read_unaligned(
            message.add(offset) as *const CabiRouteAttribute,
        );
        let attribute_len = attribute.rta_len as usize;
        if attribute_len < core::mem::size_of::<CabiRouteAttribute>()
            || attribute_len > message_len - offset
        {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        if attribute.rta_type == CABI_IFLA_IFNAME {
            let data = message.add(offset + core::mem::size_of::<CabiRouteAttribute>());
            let data_len = attribute_len - core::mem::size_of::<CabiRouteAttribute>();
            let mut name_len = data_len;
            let mut j = 0;
            while j < data_len {
                if *data.add(j) == 0 {
                    name_len = j;
                    break;
                }
                j += 1;
            }
            if !cabi_if_map_add(ctx, info.ifi_index as c_uint, data, name_len) {
                return false;
            }
        }
        let aligned_len = match attribute_len.checked_add(3) {
            Some(value) => value & !3,
            None => {
                cabi_interface_set_errno(ENOBUFS_VAL);
                return false;
            }
        };
        if aligned_len > message_len - offset {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        offset += aligned_len;
    }
    true
}

unsafe fn cabi_if_collect_links(ctx: &mut CabiIfNameMapContext) -> bool {
    let fd = socket(
        CABI_AF_NETLINK,
        CABI_SOCK_RAW | CABI_SOCK_CLOEXEC,
        CABI_NETLINK_ROUTE,
    );
    if fd < 0 {
        return false;
    }

    let request = CabiNetlinkDumpRequest {
        header: CabiNetlinkHeader {
            nlmsg_len: core::mem::size_of::<CabiNetlinkDumpRequest>() as u32,
            nlmsg_type: CABI_RTM_GETLINK,
            nlmsg_flags: CABI_NLM_F_REQUEST | CABI_NLM_F_DUMP,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        family: 0,
        _padding: [0; 3],
    };
    let destination = CabiNetlinkAddress {
        nl_family: CABI_AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let sent = sys_sendto(
        fd,
        &request as *const CabiNetlinkDumpRequest as *const c_void,
        core::mem::size_of::<CabiNetlinkDumpRequest>(),
        0,
        &destination as *const CabiNetlinkAddress as *const sockaddr,
        core::mem::size_of::<CabiNetlinkAddress>() as c_uint,
    );
    if sent < 0 {
        cabi_interface_set_errno((-sent) as c_int);
        sys_close(fd as i64);
        return false;
    }

    let mut buffer = [0u8; CABI_NETLINK_BUFFER_SIZE];
    loop {
        let received = sys_recvfrom(
            fd,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if received <= 0 {
            if received < 0 {
                cabi_interface_set_errno((-received) as c_int);
            } else {
                cabi_interface_set_errno(EIO_VAL);
            }
            sys_close(fd as i64);
            return false;
        }
        let received = received as usize;
        let mut offset = 0usize;
        while offset < received {
            if received - offset < core::mem::size_of::<CabiNetlinkHeader>() {
                cabi_interface_set_errno(ENOBUFS_VAL);
                sys_close(fd as i64);
                return false;
            }
            let header = core::ptr::read_unaligned(
                buffer.as_ptr().add(offset) as *const CabiNetlinkHeader,
            );
            let message_len = header.nlmsg_len as usize;
            if message_len < core::mem::size_of::<CabiNetlinkHeader>()
                || message_len > received - offset
            {
                cabi_interface_set_errno(ENOBUFS_VAL);
                sys_close(fd as i64);
                return false;
            }
            match header.nlmsg_type {
                CABI_NLMSG_DONE => {
                    sys_close(fd as i64);
                    return true;
                }
                CABI_NLMSG_ERROR => {
                    if message_len >= core::mem::size_of::<CabiNetlinkHeader>() + 4 {
                        let error = core::ptr::read_unaligned(
                            buffer.as_ptr().add(offset + core::mem::size_of::<CabiNetlinkHeader>())
                                as *const c_int,
                        );
                        if error != 0 {
                            cabi_interface_set_errno(if error < 0 { -error } else { error });
                        } else {
                            cabi_interface_set_errno(EIO_VAL);
                        }
                    } else {
                        cabi_interface_set_errno(ENOBUFS_VAL);
                    }
                    sys_close(fd as i64);
                    return false;
                }
                CABI_NLMSG_NOOP => {}
                CABI_NLMSG_OVERRUN => {
                    cabi_interface_set_errno(ENOBUFS_VAL);
                    sys_close(fd as i64);
                    return false;
                }
                CABI_RTM_NEWLINK => {
                    if !cabi_if_parse_link(
                        buffer.as_ptr().add(offset),
                        message_len,
                        ctx,
                    ) {
                        sys_close(fd as i64);
                        return false;
                    }
                }
                _ => {}
            }
            let aligned_len = match message_len.checked_add(3) {
                Some(value) => value & !3,
                None => {
                    cabi_interface_set_errno(ENOBUFS_VAL);
                    sys_close(fd as i64);
                    return false;
                }
            };
            if aligned_len > received - offset {
                cabi_interface_set_errno(ENOBUFS_VAL);
                sys_close(fd as i64);
                return false;
            }
            offset += aligned_len;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn if_nametoindex(name: *const c_char) -> c_uint {
    if name.is_null() {
        cabi_interface_set_errno(EFAULT_VAL);
        return 0;
    }
    let fd = socket(AF_UNIX, SOCK_DGRAM | CABI_SOCK_CLOEXEC, 0);
    if fd < 0 {
        return 0;
    }
    let mut ifr = [0u8; CABI_IFREQ_SIZE];
    let mut i = 0;
    while i < CABI_IF_NAMESIZE {
        let byte = *name.add(i) as u8;
        ifr[i] = byte;
        i += 1;
        if byte == 0 {
            break;
        }
    }
    let result = cabi_if_ioctl_request(fd, CABI_SIOCGIFINDEX, ifr.as_mut_ptr());
    sys_close(fd as i64);
    if result < 0 {
        cabi_interface_set_errno((-result) as c_int);
        return 0;
    }
    core::ptr::read_unaligned(ifr.as_ptr().add(CABI_IFR_INDEX_OFFSET) as *const c_uint)
}

#[no_mangle]
pub unsafe extern "C" fn if_indextoname(index: c_uint, name: *mut c_char) -> *mut c_char {
    if name.is_null() {
        cabi_interface_set_errno(EFAULT_VAL);
        return core::ptr::null_mut();
    }
    let fd = socket(AF_UNIX, SOCK_DGRAM | CABI_SOCK_CLOEXEC, 0);
    if fd < 0 {
        return core::ptr::null_mut();
    }
    let mut ifr = [0u8; CABI_IFREQ_SIZE];
    core::ptr::write_unaligned(
        ifr.as_mut_ptr().add(CABI_IFR_INDEX_OFFSET) as *mut c_uint,
        index,
    );
    let result = cabi_if_ioctl_request(fd, CABI_SIOCGIFNAME, ifr.as_mut_ptr());
    sys_close(fd as i64);
    if result < 0 {
        cabi_interface_set_errno((-result) as c_int);
        if cabi_interface_errno() == ENODEV_VAL {
            cabi_interface_set_errno(ENXIO_VAL);
        }
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(
        ifr.as_ptr() as *const c_char,
        name,
        CABI_IF_NAMESIZE,
    );
    name
}

#[no_mangle]
pub unsafe extern "C" fn if_nameindex() -> *mut CabiIfNameIndex {
    let mut ctx = CabiIfNameMapContext {
        list: core::ptr::null_mut(),
        count: 0,
        capacity: 0,
        string_bytes: 0,
    };
    if !cabi_if_collect_links(&mut ctx) {
        free(ctx.list as *mut c_void);
        return core::ptr::null_mut();
    }

    let entry_count = match ctx.count.checked_add(1) {
        Some(value) => value,
        None => {
            free(ctx.list as *mut c_void);
            cabi_interface_set_errno(ENOBUFS_VAL);
            return core::ptr::null_mut();
        }
    };
    let entries_bytes = match entry_count.checked_mul(core::mem::size_of::<CabiIfNameIndex>()) {
        Some(value) => value,
        None => {
            free(ctx.list as *mut c_void);
            cabi_interface_set_errno(ENOBUFS_VAL);
            return core::ptr::null_mut();
        }
    };
    let total = match entries_bytes.checked_add(ctx.string_bytes) {
        Some(value) => value,
        None => {
            free(ctx.list as *mut c_void);
            cabi_interface_set_errno(ENOBUFS_VAL);
            return core::ptr::null_mut();
        }
    };
    let result = malloc(total) as *mut CabiIfNameIndex;
    if result.is_null() {
        free(ctx.list as *mut c_void);
        return core::ptr::null_mut();
    }

    let mut strings = (result as *mut u8).add(entries_bytes);
    let mut i = 0;
    while i < ctx.count {
        let source = &*ctx.list.add(i);
        let destination = result.add(i);
        (*destination).if_index = source.index;
        (*destination).if_name = strings as *mut c_char;
        core::ptr::copy_nonoverlapping(source.name.as_ptr(), strings, source.name_len as usize);
        strings = strings.add(source.name_len as usize);
        *strings = 0;
        strings = strings.add(1);
        i += 1;
    }
    (*result.add(ctx.count)).if_index = 0;
    (*result.add(ctx.count)).if_name = core::ptr::null_mut();
    free(ctx.list as *mut c_void);
    result
}

#[no_mangle]
pub unsafe extern "C" fn if_freenameindex(index: *mut CabiIfNameIndex) {
    free(index as *mut c_void);
}

// getifaddrs/freeifaddrs use the same rtnetlink source as if_nameindex, but
// retain link and address records separately.  Every pointer exposed through
// struct ifaddrs points into the allocation for its own node (or into the
// link node for a shared name), so one freeifaddrs walk owns the whole result.

const CABI_IFADDRS_HASH_SIZE: usize = 64;
const CABI_IFLA_ADDRESS: u16 = 1;
const CABI_IFLA_BROADCAST: u16 = 2;
const CABI_IFLA_STATS: u16 = 7;
const CABI_IFA_ADDRESS: u16 = 1;
const CABI_IFA_LOCAL: u16 = 2;
const CABI_IFA_LABEL: u16 = 3;
const CABI_IFA_BROADCAST: u16 = 4;
const CABI_RTM_NEWADDR: u16 = 20;
const CABI_RTM_GETADDR: u16 = 22;
const CABI_AF_INET: u8 = 2;
const CABI_AF_INET6: u8 = 10;
const CABI_AF_PACKET: u16 = 17;

#[repr(C)]
pub struct CabiIfAddrs {
    pub ifa_next: *mut CabiIfAddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_ifu: CabiIfAddrsIfu,
    pub ifa_data: *mut c_void,
}

#[repr(C)]
pub union CabiIfAddrsIfu {
    pub ifu_broadaddr: *mut sockaddr,
    pub ifu_dstaddr: *mut sockaddr,
}

#[repr(C)]
struct CabiIfAddrsStorage {
    ifa: CabiIfAddrs,
    hash_next: *mut CabiIfAddrsStorage,
    addr: [u8; 36],
    netmask: [u8; 36],
    ifu: [u8; 36],
    index: c_uint,
    name: [c_char; CABI_IF_NAMESIZE + 1],
}

#[repr(C)]
struct CabiIfAddrMessage {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

struct CabiIfAddrsContext {
    first: *mut CabiIfAddrs,
    last: *mut CabiIfAddrs,
    hash: [*mut CabiIfAddrsStorage; CABI_IFADDRS_HASH_SIZE],
}

#[inline]
unsafe fn ifaddrs_storage_addr(storage: *mut CabiIfAddrsStorage) -> *mut sockaddr {
    (*storage).addr.as_mut_ptr() as *mut sockaddr
}

#[inline]
unsafe fn ifaddrs_storage_netmask(storage: *mut CabiIfAddrsStorage) -> *mut sockaddr {
    (*storage).netmask.as_mut_ptr() as *mut sockaddr
}

#[inline]
unsafe fn ifaddrs_storage_ifu(storage: *mut CabiIfAddrsStorage) -> *mut sockaddr {
    (*storage).ifu.as_mut_ptr() as *mut sockaddr
}

#[inline]
unsafe fn ifaddrs_set_family(storage: *mut u8, family: u16) {
    core::ptr::write_unaligned(storage as *mut u16, family);
}

unsafe fn ifaddrs_copy_addr(
    storage: *mut u8,
    family: u8,
    source: *const u8,
    source_len: usize,
    ifindex: u32,
) -> bool {
    if source.is_null() {
        return false;
    }
    match family {
        CABI_AF_INET => {
            if source_len < 4 {
                return false;
            }
            core::ptr::write_bytes(storage, 0, 16);
            ifaddrs_set_family(storage, CABI_AF_INET as u16);
            core::ptr::copy_nonoverlapping(source, storage.add(4), 4);
            true
        }
        CABI_AF_INET6 => {
            if source_len < 16 {
                return false;
            }
            core::ptr::write_bytes(storage, 0, 28);
            ifaddrs_set_family(storage, CABI_AF_INET6 as u16);
            core::ptr::copy_nonoverlapping(source, storage.add(8), 16);
            let address = core::slice::from_raw_parts(source, 16);
            let link_local = (address[0] == 0xfe && address[1] & 0xc0 == 0x80)
                || (address[0] == 0xff && address[1] == 0x02);
            if link_local {
                core::ptr::write_unaligned(storage.add(24) as *mut u32, ifindex);
            }
            true
        }
        _ => false,
    }
}

unsafe fn ifaddrs_copy_lladdr(
    storage: *mut u8,
    source: *const u8,
    source_len: usize,
    ifindex: i32,
    hatype: u16,
) -> bool {
    if source.is_null() || source_len > 24 {
        return false;
    }
    core::ptr::write_bytes(storage, 0, 36);
    ifaddrs_set_family(storage, CABI_AF_PACKET);
    core::ptr::write_unaligned(storage.add(4) as *mut i32, ifindex);
    core::ptr::write_unaligned(storage.add(8) as *mut u16, hatype);
    *storage.add(11) = source_len as u8;
    core::ptr::copy_nonoverlapping(source, storage.add(12), source_len);
    true
}

unsafe fn ifaddrs_copy_netmask(
    storage: *mut u8,
    family: u8,
    prefix_len: u8,
) -> bool {
    let mut address = [0u8; 16];
    let bits = if family == CABI_AF_INET { 32 } else if family == CABI_AF_INET6 { 128 } else { return false };
    let prefix_len = (prefix_len as usize).min(bits);
    let full_bytes = prefix_len / 8;
    let partial_bits = prefix_len % 8;
    let mut i = 0;
    while i < full_bytes {
        address[i] = 0xff;
        i += 1;
    }
    if partial_bits != 0 {
        address[full_bytes] = 0xff << (8 - partial_bits);
    }
    ifaddrs_copy_addr(storage, family, address.as_ptr(), if family == CABI_AF_INET { 4 } else { 16 }, 0)
}

unsafe fn ifaddrs_find(
    ctx: &mut CabiIfAddrsContext,
    index: u32,
) -> *mut CabiIfAddrsStorage {
    let mut current = ctx.hash[(index as usize) % CABI_IFADDRS_HASH_SIZE];
    while !current.is_null() {
        if (*current).index == index {
            return current;
        }
        current = (*current).hash_next;
    }
    core::ptr::null_mut()
}

unsafe fn ifaddrs_append(ctx: &mut CabiIfAddrsContext, storage: *mut CabiIfAddrsStorage) {
    (*storage).ifa.ifa_next = core::ptr::null_mut();
    if ctx.first.is_null() {
        ctx.first = &mut (*storage).ifa;
    } else {
        (*ctx.last).ifa_next = &mut (*storage).ifa;
    }
    ctx.last = &mut (*storage).ifa;
}

unsafe fn ifaddrs_attr_bounds(
    message: *const u8,
    message_len: usize,
    attrs_offset: &mut usize,
) -> bool {
    while *attrs_offset < message_len {
        if message_len - *attrs_offset < core::mem::size_of::<CabiRouteAttribute>() {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        let attr = core::ptr::read_unaligned(message.add(*attrs_offset) as *const CabiRouteAttribute);
        let attr_len = attr.rta_len as usize;
        if attr_len < core::mem::size_of::<CabiRouteAttribute>()
            || attr_len > message_len - *attrs_offset
        {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        let aligned = match attr_len.checked_add(3) {
            Some(value) => value & !3,
            None => {
                cabi_interface_set_errno(ENOBUFS_VAL);
                return false;
            }
        };
        if aligned > message_len - *attrs_offset {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        *attrs_offset += aligned;
    }
    true
}

unsafe fn ifaddrs_parse_link(
    message: *const u8,
    message_len: usize,
    ctx: &mut CabiIfAddrsContext,
) -> bool {
    let header_len = core::mem::size_of::<CabiNetlinkHeader>();
    let info_len = core::mem::size_of::<CabiIfInfoMessage>();
    if message_len < header_len + info_len {
        cabi_interface_set_errno(ENOBUFS_VAL);
        return false;
    }
    let info = core::ptr::read_unaligned(message.add(header_len) as *const CabiIfInfoMessage);
    if info.ifi_index <= 0 {
        return true;
    }

    let mut attrs = header_len + info_len;
    let attrs_end = message_len;
    let mut stats_len = 0usize;
    while attrs < attrs_end {
        if attrs_end - attrs < core::mem::size_of::<CabiRouteAttribute>() {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        let attr = core::ptr::read_unaligned(message.add(attrs) as *const CabiRouteAttribute);
        let attr_len = attr.rta_len as usize;
        if attr_len < core::mem::size_of::<CabiRouteAttribute>() || attr_len > attrs_end - attrs {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        if attr.rta_type == CABI_IFLA_STATS {
            stats_len = stats_len.max(attr_len - core::mem::size_of::<CabiRouteAttribute>());
        }
        let aligned = match attr_len.checked_add(3) {
            Some(value) => value & !3,
            None => {
                cabi_interface_set_errno(ENOBUFS_VAL);
                return false;
            }
        };
        if aligned > attrs_end - attrs {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
        attrs += aligned;
    }

    let allocation_size = match core::mem::size_of::<CabiIfAddrsStorage>().checked_add(stats_len) {
        Some(value) => value,
        None => {
            cabi_interface_set_errno(ENOBUFS_VAL);
            return false;
        }
    };
    let storage = calloc(1, allocation_size) as *mut CabiIfAddrsStorage;
    if storage.is_null() {
        return false;
    }
    (*storage).index = info.ifi_index as c_uint;
    (*storage).ifa.ifa_flags = info.ifi_flags;

    attrs = header_len + info_len;
    while attrs < attrs_end {
        let attr = core::ptr::read_unaligned(message.add(attrs) as *const CabiRouteAttribute);
        let attr_len = attr.rta_len as usize;
        let data = message.add(attrs + core::mem::size_of::<CabiRouteAttribute>());
        let data_len = attr_len - core::mem::size_of::<CabiRouteAttribute>();
        match attr.rta_type {
            CABI_IFLA_IFNAME => {
                if data_len < (*storage).name.len() {
                    core::ptr::copy_nonoverlapping(
                        data,
                        (*storage).name.as_mut_ptr() as *mut u8,
                        data_len,
                    );
                    if data_len == 0 || *(*storage).name.as_ptr().add(data_len.saturating_sub(1)) != 0 {
                        (*storage).name[data_len] = 0;
                    }
                    (*storage).ifa.ifa_name = (*storage).name.as_mut_ptr();
                }
            }
            CABI_IFLA_ADDRESS => {
                let _ = ifaddrs_copy_lladdr(
                    (*storage).addr.as_mut_ptr(),
                    data,
                    data_len,
                    info.ifi_index,
                    info.ifi_type,
                );
                if data_len <= 24 {
                    (*storage).ifa.ifa_addr = ifaddrs_storage_addr(storage);
                }
            }
            CABI_IFLA_BROADCAST => {
                let _ = ifaddrs_copy_lladdr(
                    (*storage).ifu.as_mut_ptr(),
                    data,
                    data_len,
                    info.ifi_index,
                    info.ifi_type,
                );
                if data_len <= 24 {
                    (*storage).ifa.ifa_ifu.ifu_broadaddr = ifaddrs_storage_ifu(storage);
                }
            }
            CABI_IFLA_STATS => {
                if data_len <= stats_len {
                    (*storage).ifa.ifa_data = (storage as *mut u8).add(core::mem::size_of::<CabiIfAddrsStorage>()) as *mut c_void;
                    core::ptr::copy_nonoverlapping(data, (*storage).ifa.ifa_data as *mut u8, data_len);
                }
            }
            _ => {}
        }
        attrs += (attr_len + 3) & !3;
    }

    if (*storage).ifa.ifa_name.is_null() {
        free(storage as *mut c_void);
        return true;
    }
    let bucket = ((*storage).index as usize) % CABI_IFADDRS_HASH_SIZE;
    (*storage).hash_next = ctx.hash[bucket];
    ctx.hash[bucket] = storage;
    ifaddrs_append(ctx, storage);
    true
}

unsafe fn ifaddrs_parse_addr(
    message: *const u8,
    message_len: usize,
    ctx: &mut CabiIfAddrsContext,
) -> bool {
    let header_len = core::mem::size_of::<CabiNetlinkHeader>();
    let addr_len = core::mem::size_of::<CabiIfAddrMessage>();
    if message_len < header_len + addr_len {
        cabi_interface_set_errno(ENOBUFS_VAL);
        return false;
    }
    let address = core::ptr::read_unaligned(message.add(header_len) as *const CabiIfAddrMessage);
    let link = ifaddrs_find(ctx, address.ifa_index);
    if link.is_null() {
        return true;
    }

    let mut attrs = header_len + addr_len;
    if !ifaddrs_attr_bounds(message, message_len, &mut attrs) {
        return false;
    }
    let allocation_size = core::mem::size_of::<CabiIfAddrsStorage>();
    let storage = calloc(1, allocation_size) as *mut CabiIfAddrsStorage;
    if storage.is_null() {
        return false;
    }
    (*storage).index = address.ifa_index;
    (*storage).ifa.ifa_name = (*link).ifa.ifa_name;
    (*storage).ifa.ifa_flags = (*link).ifa.ifa_flags;

    attrs = header_len + addr_len;
    while attrs < message_len {
        let attr = core::ptr::read_unaligned(message.add(attrs) as *const CabiRouteAttribute);
        let attr_len = attr.rta_len as usize;
        let data = message.add(attrs + core::mem::size_of::<CabiRouteAttribute>());
        let data_len = attr_len - core::mem::size_of::<CabiRouteAttribute>();
        match attr.rta_type {
            CABI_IFA_ADDRESS => {
                let target = if (*storage).ifa.ifa_addr.is_null() {
                    (*storage).addr.as_mut_ptr()
                } else {
                    (*storage).ifu.as_mut_ptr()
                };
                if ifaddrs_copy_addr(target, address.ifa_family, data, data_len, address.ifa_index) {
                    if (*storage).ifa.ifa_addr.is_null() {
                        (*storage).ifa.ifa_addr = ifaddrs_storage_addr(storage);
                    } else {
                        (*storage).ifa.ifa_ifu.ifu_dstaddr = ifaddrs_storage_ifu(storage);
                    }
                }
            }
            CABI_IFA_LOCAL => {
                if !(*storage).ifa.ifa_addr.is_null() {
                    core::ptr::copy_nonoverlapping(
                        (*storage).addr.as_ptr(),
                        (*storage).ifu.as_mut_ptr(),
                        36,
                    );
                    (*storage).ifa.ifa_ifu.ifu_dstaddr = ifaddrs_storage_ifu(storage);
                    core::ptr::write_bytes((*storage).addr.as_mut_ptr(), 0, 36);
                    (*storage).ifa.ifa_addr = core::ptr::null_mut();
                }
                if ifaddrs_copy_addr(
                    (*storage).addr.as_mut_ptr(),
                    address.ifa_family,
                    data,
                    data_len,
                    address.ifa_index,
                ) {
                    (*storage).ifa.ifa_addr = ifaddrs_storage_addr(storage);
                }
            }
            CABI_IFA_BROADCAST => {
                if ifaddrs_copy_addr(
                    (*storage).ifu.as_mut_ptr(),
                    address.ifa_family,
                    data,
                    data_len,
                    address.ifa_index,
                ) {
                    (*storage).ifa.ifa_ifu.ifu_broadaddr = ifaddrs_storage_ifu(storage);
                }
            }
            CABI_IFA_LABEL => {
                if data_len < (*storage).name.len() {
                    core::ptr::copy_nonoverlapping(
                        data,
                        (*storage).name.as_mut_ptr() as *mut u8,
                        data_len,
                    );
                    if data_len == 0 || *(*storage).name.as_ptr().add(data_len.saturating_sub(1)) != 0 {
                        (*storage).name[data_len] = 0;
                    }
                    (*storage).ifa.ifa_name = (*storage).name.as_mut_ptr();
                }
            }
            _ => {}
        }
        attrs += (attr_len + 3) & !3;
    }
    if !(*storage).ifa.ifa_addr.is_null() {
        let _ = ifaddrs_copy_netmask(
            (*storage).netmask.as_mut_ptr(),
            address.ifa_family,
            address.ifa_prefixlen,
        );
        if address.ifa_family == CABI_AF_INET || address.ifa_family == CABI_AF_INET6 {
            (*storage).ifa.ifa_netmask = ifaddrs_storage_netmask(storage);
        }
    }
    ifaddrs_append(ctx, storage);
    true
}

unsafe fn ifaddrs_dump(
    fd: c_int,
    request_type: u16,
    sequence: u32,
    ctx: &mut CabiIfAddrsContext,
) -> bool {
    let request = CabiNetlinkDumpRequest {
        header: CabiNetlinkHeader {
            nlmsg_len: core::mem::size_of::<CabiNetlinkDumpRequest>() as u32,
            nlmsg_type: request_type,
            nlmsg_flags: CABI_NLM_F_REQUEST | CABI_NLM_F_DUMP,
            nlmsg_seq: sequence,
            nlmsg_pid: 0,
        },
        family: 0,
        _padding: [0; 3],
    };
    let destination = CabiNetlinkAddress {
        nl_family: CABI_AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let sent = sys_sendto(
        fd,
        &request as *const CabiNetlinkDumpRequest as *const c_void,
        core::mem::size_of::<CabiNetlinkDumpRequest>(),
        0,
        &destination as *const CabiNetlinkAddress as *const sockaddr,
        core::mem::size_of::<CabiNetlinkAddress>() as c_uint,
    );
    if sent < 0 {
        cabi_interface_set_errno((-sent) as c_int);
        return false;
    }

    let mut buffer = [0u8; CABI_NETLINK_BUFFER_SIZE];
    loop {
        let received = sys_recvfrom(
            fd,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if received <= 0 {
            if received < 0 {
                cabi_interface_set_errno((-received) as c_int);
            } else {
                cabi_interface_set_errno(EIO_VAL);
            }
            return false;
        }
        let received = received as usize;
        let mut offset = 0usize;
        while offset < received {
            if received - offset < core::mem::size_of::<CabiNetlinkHeader>() {
                cabi_interface_set_errno(ENOBUFS_VAL);
                return false;
            }
            let header = core::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const CabiNetlinkHeader);
            let message_len = header.nlmsg_len as usize;
            if message_len < core::mem::size_of::<CabiNetlinkHeader>() || message_len > received - offset {
                cabi_interface_set_errno(ENOBUFS_VAL);
                return false;
            }
            match header.nlmsg_type {
                CABI_NLMSG_DONE => return true,
                CABI_NLMSG_ERROR => {
                    if message_len >= core::mem::size_of::<CabiNetlinkHeader>() + 4 {
                        let error = core::ptr::read_unaligned(
                            buffer.as_ptr().add(offset + core::mem::size_of::<CabiNetlinkHeader>())
                                as *const c_int,
                        );
                        cabi_interface_set_errno(if error < 0 { -error } else if error > 0 { error } else { EIO_VAL });
                    } else {
                        cabi_interface_set_errno(ENOBUFS_VAL);
                    }
                    return false;
                }
                CABI_NLMSG_NOOP => {}
                CABI_NLMSG_OVERRUN => {
                    cabi_interface_set_errno(ENOBUFS_VAL);
                    return false;
                }
                CABI_RTM_NEWLINK if request_type == CABI_RTM_GETLINK => {
                    if !ifaddrs_parse_link(buffer.as_ptr().add(offset), message_len, ctx) {
                        return false;
                    }
                }
                CABI_RTM_NEWADDR if request_type == CABI_RTM_GETADDR => {
                    if !ifaddrs_parse_addr(buffer.as_ptr().add(offset), message_len, ctx) {
                        return false;
                    }
                }
                _ => {}
            }
            let aligned = match message_len.checked_add(3) {
                Some(value) => value & !3,
                None => {
                    cabi_interface_set_errno(ENOBUFS_VAL);
                    return false;
                }
            };
            if aligned > received - offset {
                cabi_interface_set_errno(ENOBUFS_VAL);
                return false;
            }
            offset += aligned;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn freeifaddrs(mut ifp: *mut CabiIfAddrs) {
    while !ifp.is_null() {
        let next = (*ifp).ifa_next;
        free(ifp as *mut c_void);
        ifp = next;
    }
}

#[no_mangle]
pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut CabiIfAddrs) -> c_int {
    if ifap.is_null() {
        cabi_interface_set_errno(EFAULT_VAL);
        return -1;
    }
    *ifap = core::ptr::null_mut();
    let mut ctx = CabiIfAddrsContext {
        first: core::ptr::null_mut(),
        last: core::ptr::null_mut(),
        hash: [core::ptr::null_mut(); CABI_IFADDRS_HASH_SIZE],
    };
    let fd = socket(
        CABI_AF_NETLINK,
        CABI_SOCK_RAW | CABI_SOCK_CLOEXEC,
        CABI_NETLINK_ROUTE,
    );
    if fd < 0 {
        return -1;
    }
    if !ifaddrs_dump(fd, CABI_RTM_GETLINK, 1, &mut ctx)
        || !ifaddrs_dump(fd, CABI_RTM_GETADDR, 2, &mut ctx)
    {
        sys_close(fd as i64);
        freeifaddrs(ctx.first);
        return -1;
    }
    sys_close(fd as i64);
    *ifap = ctx.first;
    0
}
