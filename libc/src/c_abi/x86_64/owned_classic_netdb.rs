//! Owned classic netdb C contracts from pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT).
//! `src/network/gethostby{name,name2,addr}{,_r}.c` map to the host wrappers;
//! `getservby{name,port}{,_r}.c` to the service wrappers; `ent.c`, `netname.c`
//! and `herror.c` to their named entries. Modern `getaddrinfo.c` and
//! `getnameinfo.c` share the owned allocation-free lookup backends. Allocation
//! and freeaddrinfo retain the existing opaque page-per-node lifetime rather
//! than importing musl's private aibuf layout. Nonreentrant host calls have
//! distinct forward/reverse heap owners; service calls have distinct static
//! records. Callers serialize each nonreentrant owner and borrow results only
//! until its next call. Reentrant buffers never borrow those static owners.
//! DNS uses owned_resolver_transport's explicit C cancellation/cleanup owner
//! around the shared core exchange. It preserves native/private raw transport
//! behavior and the bounded sequential scheduler rather than importing musl's
//! parallel msend. The separate cancellation gate proves the named lifecycle;
//! this module still claims no complete resolver-family source parity.
use core::{ffi::{c_char,c_int,c_uint,c_void}, mem, ptr};
use super::{c_status, errno, h_errno, hstrerror, inet_address, integer_parse,
    interface_discovery, numeric_netdb, owned_netdb_lookup as lookup,
    pthread_cancel, raw_syscall, stdio_standard};
use lookup::{Address, Service, MAX_ADDRS, bytes, line_bytes, whitespace};
use numeric_netdb::{CabiAddrInfo,CabiSockaddr};
use crabc_core::resolver::DnsResponse;

#[repr(C)]
pub struct Hostent { name: *mut c_char, aliases: *mut *mut c_char, family: c_int, length: c_int, addresses: *mut *mut c_char }
#[repr(C)]
pub struct Netent { name: *mut c_char, aliases: *mut *mut c_char, family: c_int, network: u32 }
#[repr(C)]
pub struct Servent { name: *mut c_char, aliases: *mut *mut c_char, port: c_int, protocol: *mut c_char }
unsafe extern "C" { fn malloc(size: usize) -> *mut c_void; fn free(p: *mut c_void); fn fprintf(file: *mut stdio_standard::StandardStream, format: *const c_char, ...) -> c_int; }
const EMPTY_SERVICE: Servent = Servent { name: ptr::null_mut(), aliases: ptr::null_mut(), port: 0, protocol: ptr::null_mut() };
static mut FORWARD_HOST: *mut Hostent = ptr::null_mut();
static mut REVERSE_HOST: *mut Hostent = ptr::null_mut();
static mut NAME_SERVICE: Servent = EMPTY_SERVICE;
static mut PORT_SERVICE: Servent = EMPTY_SERVICE;
static mut NAME_SERVICE_BUFFER: [usize;2] = [0;2];
static mut PORT_SERVICE_BUFFER: [usize;4] = [0;4];

/// # Safety
/// Name must be NUL-terminated; h, res and err must be writable records;
/// buf must designate buflen writable bytes disjoint from those records.
#[no_mangle]
pub unsafe extern "C" fn gethostbyname2_r(name: *const c_char, af: c_int, h: *mut Hostent, buf: *mut c_char, buflen: usize, res: *mut *mut Hostent, err: *mut c_int) -> c_int {
    unsafe { *res = ptr::null_mut(); }
    let mut addresses = [Address::EMPTY;MAX_ADDRS]; let mut canon = [0u8;256];
    let count = unsafe { lookup::names(&mut addresses, &mut canon, name, af, 2) };
    if count < 0 {
        let (error, result) = match count { -2 => (1,0), -5 => (4,0), -3 => (2,11), -11 => (3,unsafe { *errno::__errno_location() }), _ => (3,74) };
        unsafe { *err = error; } return result;
    }
    let count = count as usize; let length = if af == 10 { 16 } else { 4 };
    unsafe { (*h).family = af; (*h).length = length as c_int; }
    let name = unsafe { bytes(name) }; let canonical = line_bytes(&canon);
    let align = (buf as usize).wrapping_neg() & 7;
    let need = 32 + (count+1)*(8+length) + name.len()+1 + canonical.len()+1 + align;
    if need > buflen { return 34; }
    unsafe {
        let aliases = buf.add(align).cast::<*mut c_char>(); let list = aliases.add(3);
        let mut cursor = list.add(count+1).cast::<c_char>();
        (*h).aliases = aliases; (*h).addresses = list;
        for (i,a) in addresses[..count].iter().enumerate() {
            *list.add(i) = cursor; ptr::copy_nonoverlapping(a.bytes.as_ptr().cast(), cursor, length); cursor = cursor.add(length);
        }
        *list.add(count) = ptr::null_mut();
        (*h).name = cursor; *aliases = cursor;
        ptr::copy_nonoverlapping(canon.as_ptr().cast(),cursor,canonical.len()+1); cursor = cursor.add(canonical.len()+1);
        *aliases.add(1) = ptr::null_mut(); *aliases.add(2) = ptr::null_mut();
        if name != canonical { *aliases.add(1) = cursor; ptr::copy_nonoverlapping(name.as_ptr().cast(),cursor,name.len()); *cursor.add(name.len()) = 0; }
        *res = h;
    }
    0
}
/// # Safety
/// Same writable-record, string and buffer obligations as gethostbyname2_r.
#[no_mangle]
pub unsafe extern "C" fn gethostbyname_r(name: *const c_char,h: *mut Hostent,buf: *mut c_char,n: usize,res: *mut *mut Hostent,err: *mut c_int) -> c_int {
    unsafe { gethostbyname2_r(name,2,h,buf,n,res,err) }
}
/// # Safety
/// addr must contain len readable bytes; h/res/err must be writable; buf
/// must contain buflen writable bytes disjoint from the other arguments.
#[no_mangle]
pub unsafe extern "C" fn gethostbyaddr_r(addr: *const c_void,len: c_uint,af: c_int,h: *mut Hostent,buf: *mut c_char,buflen: usize,res: *mut *mut Hostent,err: *mut c_int) -> c_int {
    unsafe { *res = ptr::null_mut(); }
    if !((af == 2 && len == 4) || (af == 10 && len == 16)) { unsafe { *err = 3; } return 22; }
    let align = (buf as usize).wrapping_neg() & 7; let overhead = align+32+len as usize;
    if buflen <= overhead { return 34; }
    let mut address = Address::for_family(af);
    unsafe { ptr::copy_nonoverlapping(addr.cast(),address.bytes.as_mut_ptr(),len as usize); }
    let (socket,socket_len) = lookup::sockaddr(&address,0);
    unsafe {
        let list = buf.add(align).cast::<*mut c_char>(); let aliases = list.add(2);
        let data = aliases.add(2).cast::<c_char>(); let name = data.add(len as usize);
        (*h).addresses = list; (*h).aliases = aliases;
        *list = data; *list.add(1) = ptr::null_mut(); *aliases = name; *aliases.add(1) = ptr::null_mut();
        ptr::copy_nonoverlapping(addr.cast::<c_char>(),data,len as usize);
        let result = getnameinfo(socket.as_ptr().cast(),socket_len,name,(buflen-overhead) as u32,ptr::null_mut(),0,0);
        match result { 0 => (), -3 => { *err = 2; return 11; }, -12 => return 34, -11 => { *err = 3; return *errno::__errno_location(); }, _ => { *err = 3; return 74; } }
        (*h).family = af; (*h).length = len as c_int; (*h).name = name; *res = h;
    }
    0
}
unsafe fn static_host(owner: *mut *mut Hostent, call: impl Fn(*mut Hostent,*mut c_char,usize,*mut *mut Hostent,*mut c_int)->c_int) -> *mut Hostent {
    let mut size = 63usize; let mut result = ptr::null_mut();
    loop {
        unsafe { free((*owner).cast()); }
        size = size.wrapping_mul(2).wrapping_add(1);
        let record = unsafe { malloc(size).cast::<Hostent>() }; unsafe { *owner = record; }
        if record.is_null() { unsafe { h_errno::set(3); } return ptr::null_mut(); }
        let code = call(record,unsafe { record.add(1).cast() },size-mem::size_of::<Hostent>(),&mut result,unsafe { h_errno::location() });
        if code != 34 { return result; }
    }
}
/// # Safety
/// name must be NUL-terminated. Calls sharing the forward result owner must
/// be serialized, and borrowed results expire on its next call.
#[no_mangle]
pub unsafe extern "C" fn gethostbyname2(name: *const c_char, af: c_int) -> *mut Hostent {
    unsafe { static_host(ptr::addr_of_mut!(FORWARD_HOST), |h,b,n,r,e| gethostbyname2_r(name,af,h,b,n,r,e)) }
}
/// # Safety
/// Same string, serialization and result-lifetime obligations as gethostbyname2.
#[no_mangle]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut Hostent { unsafe { gethostbyname2(name,2) } }
/// # Safety
/// addr must contain len readable bytes. Calls sharing the reverse result
/// owner must be serialized; borrowed results expire on its next call.
#[no_mangle]
pub unsafe extern "C" fn gethostbyaddr(addr: *const c_void,len: c_uint,af: c_int) -> *mut Hostent {
    unsafe { static_host(ptr::addr_of_mut!(REVERSE_HOST), |h,b,n,r,e| gethostbyaddr_r(addr,len,af,h,b,n,r,e)) }
}
/// # Safety
/// name and nonnull protocol must be NUL-terminated; record/result must be
/// writable and buffer must contain n writable bytes disjoint from them.
#[no_mangle]
pub unsafe extern "C" fn getservbyname_r(name: *const c_char,protocol: *const c_char,record: *mut Servent,buffer: *mut c_char,n: usize,result: *mut *mut Servent) -> c_int {
    unsafe { *result = ptr::null_mut(); }
    let mut end = ptr::null_mut(); unsafe { integer_parse::strtoul(name,&mut end,10); }
    if unsafe { *end } == 0 { return 2; }
    let align = (buffer as usize).wrapping_neg()&7; if n < 16+align { return 34; }
    let proto = if protocol.is_null() { 0 } else { match unsafe { bytes(protocol) } { b"tcp" => 6, b"udp" => 17, _ => return 22 } };
    let mut services = [Service::EMPTY;2]; let count = unsafe { lookup::services(&mut services,name,proto,0,0) };
    if count < 0 { return if count == -10 || count == -11 { 12 } else { 2 }; }
    unsafe {
        (*record).name = name.cast_mut(); (*record).aliases = buffer.add(align).cast();
        *(*record).aliases = name.cast_mut(); *(*record).aliases.add(1) = ptr::null_mut();
        (*record).port = services[0].port.to_be() as c_int;
        (*record).protocol = if services[0].protocol == 6 { c"tcp".as_ptr() } else { c"udp".as_ptr() }.cast_mut(); *result = record;
    }
    0
}
/// # Safety
/// nonnull protocol must be NUL-terminated; record/result must be writable;
/// buffer must contain n writable bytes disjoint from the records.
#[no_mangle]
pub unsafe extern "C" fn getservbyport_r(port: c_int,protocol: *const c_char,record: *mut Servent,buffer: *mut c_char,n: usize,result: *mut *mut Servent) -> c_int {
    if protocol.is_null() {
        let r = unsafe { getservbyport_r(port,c"tcp".as_ptr(),record,buffer,n,result) };
        return if r == 0 { 0 } else { unsafe { getservbyport_r(port,c"udp".as_ptr(),record,buffer,n,result) } };
    }
    unsafe { *result = ptr::null_mut(); }
    let align = (buffer as usize).wrapping_neg()&7; if n <= 16+align { return 34; }
    let flags = match unsafe { bytes(protocol) } { b"tcp" => 0, b"udp" => 16, _ => return 22 };
    let a = Address::for_family(2);
    let (socket,length) = lookup::sockaddr(&a,u16::from_be(port as u16));
    unsafe {
        (*record).port = port; (*record).protocol = protocol.cast_mut();
        (*record).aliases = buffer.add(align).cast(); (*record).name = buffer.add(align+16);
        *(*record).aliases = (*record).name; *(*record).aliases.add(1) = ptr::null_mut();
        let r = getnameinfo(socket.as_ptr().cast(),length,ptr::null_mut(),0,(*record).name,(n-align-16) as u32,flags);
        if r != 0 { return match r { -10|-11 => 12, -12 => 34, _ => 2 }; }
        if integer_parse::strtol((*record).name,ptr::null_mut(),10) == u16::from_be(port as u16) as i64 { return 2; }
        *result = record;
    }
    0
}
/// # Safety
/// Strings must be NUL-terminated. Calls sharing this static result must be
/// serialized and borrowed records expire on the next getservbyname call.
#[no_mangle]
pub unsafe extern "C" fn getservbyname(name: *const c_char,protocol: *const c_char) -> *mut Servent {
    let mut result = ptr::null_mut();
    unsafe { if getservbyname_r(name,protocol,ptr::addr_of_mut!(NAME_SERVICE),ptr::addr_of_mut!(NAME_SERVICE_BUFFER).cast(),16,&mut result) != 0 { ptr::null_mut() } else { result } }
}
/// # Safety
/// nonnull protocol must be NUL-terminated. Serialize calls sharing the
/// static result; borrowed records expire on the next getservbyport call.
#[no_mangle]
pub unsafe extern "C" fn getservbyport(port: c_int,protocol: *const c_char) -> *mut Servent {
    let mut result = ptr::null_mut();
    unsafe { if getservbyport_r(port,protocol,ptr::addr_of_mut!(PORT_SERVICE),ptr::addr_of_mut!(PORT_SERVICE_BUFFER).cast(),32,&mut result) != 0 { ptr::null_mut() } else { result } }
}
// musl deliberately provides no hosts/networks enumeration or network DB.
// These source bodies do not inspect arguments, files, errno or h_errno.
#[no_mangle] pub extern "C" fn gethostent() -> *mut Hostent { ptr::null_mut() }
#[no_mangle] pub extern "C" fn getnetent() -> *mut Netent { ptr::null_mut() }
#[no_mangle] pub extern "C" fn getnetbyname(_: *const c_char) -> *mut Netent { ptr::null_mut() }
#[no_mangle] pub extern "C" fn getnetbyaddr(_: u32,_: c_int) -> *mut Netent { ptr::null_mut() }
/// # Safety
/// A nonnull message must be NUL-terminated and readable during reporting.
#[no_mangle]
pub unsafe extern "C" fn herror(message: *const c_char) {
    unsafe { fprintf(stdio_standard::stderr,c"%s%s%s\n".as_ptr(),
        if message.is_null() { c"".as_ptr() } else { message },
        if message.is_null() { c"".as_ptr() } else { c": ".as_ptr() },hstrerror::hstrerror(h_errno::current())); }
}

fn comment(line: &mut [u8]) { if let Some(p) = line.iter().position(|&c| c == b'#') { line[p] = b'\n'; if p+1 < line.len() { line[p+1] = 0; } } }
unsafe fn reverse_hosts(output: &mut [u8;256],address: &Address) {
    let mut target = address.bytes;
    if address.family == 2 { target[12..].copy_from_slice(&address.bytes[..4]); target[..12].copy_from_slice(&lookup::V4_PREFIX); }
    let _ = unsafe { stdio_standard::with_readonly_file(c"/etc/hosts".as_ptr(),1024,|file| {
        let mut line = [0u8;512];
        while !stdio_standard::fgets(line.as_mut_ptr().cast(),512,file).is_null() {
            comment(&mut line); let data = line_bytes(&line);
            let Some(end) = data.iter().position(|&c| whitespace(c)) else { continue; };
            line[end] = 0; let mut parsed = Address::EMPTY;
            if lookup::numeric(&mut parsed,line.as_ptr().cast(),0) <= 0 { continue; }
            if parsed.family == 2 { let v4 = parsed.bytes; parsed.bytes[12..].copy_from_slice(&v4[..4]); parsed.bytes[..12].copy_from_slice(&lookup::V4_PREFIX); parsed.scope = 0; }
            if parsed.bytes != target || parsed.scope != address.scope { continue; }
            let data = line_bytes(&line[end+1..]); let start = data.iter().position(|&c| !whitespace(c)).unwrap_or(data.len());
            let value = &data[start..]; let value = &value[..value.iter().position(|&c| whitespace(c)).unwrap_or(value.len())];
            if value.len() < 256 { lookup::copy_name(output,value); break; }
        }
    }) };
}
unsafe fn reverse_services(output: &mut [u8;256],port: u16,dgram: bool) {
    let _ = unsafe { stdio_standard::with_readonly_file(c"/etc/services".as_ptr(),1024,|file| {
        let mut line = [0u8;128];
        while !stdio_standard::fgets(line.as_mut_ptr().cast(),128,file).is_null() {
            comment(&mut line); let data = line_bytes(&line);
            let Some(end) = data.iter().position(|&c| whitespace(c)) else { continue; };
            line[end] = 0; let p = line.as_ptr().add(end+1).cast(); let mut z = ptr::null_mut();
            let value = integer_parse::strtoul(p,&mut z,10);
            if value != port as u64 || z.cast_const() == p { continue; }
            if !bytes(z).starts_with(if dgram { b"/udp" } else { b"/tcp" }) || end+1 > 32 { continue; }
            lookup::copy_name(output,&line[..end]); break;
        }
    }) };
}
fn decimal(output: &mut [u8],mut value: u32) -> usize {
    let mut digits = [0u8;10]; let mut n = 0;
    loop { digits[n] = b'0'+(value%10) as u8; n += 1; value /= 10; if value == 0 { break; } }
    for i in 0..n { output[i] = digits[n-1-i]; } n
}
fn reverse_question(address: &Address,output: &mut [u8;80]) -> usize {
    let v4 = address.family == 2 || address.bytes[..12] == lookup::V4_PREFIX;
    let mut n = 0;
    if v4 {
        let a = if address.family == 2 { &address.bytes[..4] } else { &address.bytes[12..] };
        for &byte in a.iter().rev() { n += decimal(&mut output[n..],byte as u32); output[n] = b'.'; n += 1; }
        output[n..n+12].copy_from_slice(b"in-addr.arpa"); n+12
    } else {
        let hex = b"0123456789abcdef";
        for &byte in address.bytes.iter().rev() { output[n] = hex[(byte&15) as usize]; output[n+1] = b'.'; output[n+2] = hex[(byte>>4) as usize]; output[n+3] = b'.'; n += 4; }
        output[n..n+8].copy_from_slice(b"ip6.arpa"); n+8
    }
}
/// # Safety
/// sa must contain sl readable initialized sockaddr bytes. Nonnull node and
/// serv must designate nodelen/servlen writable bytes; outputs are disjoint.
#[no_mangle]
pub unsafe extern "C" fn getnameinfo(sa: *const CabiSockaddr,sl: c_uint,node: *mut c_char,nodelen: c_uint,serv: *mut c_char,servlen: c_uint,flags: c_int) -> c_int {
    let family = unsafe { ptr::read_unaligned(sa.cast::<u16>()) } as c_int;
    let mut address = Address::for_family(family);
    let s = sa.cast::<u8>();
    unsafe {
        match family {
            2 if sl >= 16 => ptr::copy_nonoverlapping(s.add(4),address.bytes.as_mut_ptr(),4),
            10 if sl >= 28 => { ptr::copy_nonoverlapping(s.add(8),address.bytes.as_mut_ptr(),16); address.scope = ptr::read_unaligned(s.add(24).cast()); }
            _ => return -6,
        }
    }
    if !node.is_null() && nodelen > 0 {
        let mut output = [0u8;256];
        if flags & 1 == 0 { unsafe { reverse_hosts(&mut output,&address); } }
        if output[0] == 0 && flags & 1 == 0 {
            let mut question = [0u8;80]; let n = reverse_question(&address,&mut question); let mut reply = [0u8;512];
            if let Ok(conf) = unsafe { lookup::configuration() } {
                if let Ok((len,id)) = unsafe { lookup::query(&conf,&question[..n],12,&mut reply) } {
                    if let Ok(response) = DnsResponse::parse(&reply[..len],&question[..n],12,id) {
                        let mut ordinal = 0;
                        loop { match response.rdata_at(12,ordinal,&mut output) { Ok(Some(n)) if n < 256 => output[n] = 0, Ok(None) => break, _ => { output[0] = 0; break; } } ordinal += 1; }
                    }
                }
            }
        }
        if output[0] == 0 {
            if flags & 8 != 0 { return -2; }
            unsafe { inet_address::inet_ntop(family,address.bytes.as_ptr().cast(),output.as_mut_ptr().cast(),256); }
            if address.scope != 0 {
                let mut n = line_bytes(&output).len(); output[n] = b'%'; n += 1;
                let mut interface = [0u8;16];
                let resolved = flags & 0x100 == 0 && lookup::linklocal(&address.bytes)
                    && !unsafe { interface_discovery::if_indextoname(address.scope,interface.as_mut_ptr().cast()) }.is_null();
                if resolved { let name = line_bytes(&interface); output[n..n+name.len()].copy_from_slice(name); n += name.len(); }
                else { n += decimal(&mut output[n..],address.scope); }
                output[n] = 0;
            }
        }
        let n = line_bytes(&output).len(); if n >= nodelen as usize { return -12; }
        unsafe { ptr::copy_nonoverlapping(output.as_ptr().cast(),node,n+1); }
    }
    if !serv.is_null() && servlen > 0 {
        let port = u16::from_be(unsafe { ptr::read_unaligned(s.add(2).cast()) }); let mut output = [0u8;256];
        if flags & 2 == 0 { unsafe { reverse_services(&mut output,port,flags&16 != 0); } }
        if output[0] == 0 { let n = decimal(&mut output,port as u32); output[n] = 0; }
        let n = line_bytes(&output).len(); if n >= servlen as usize { return -12; }
        unsafe { ptr::copy_nonoverlapping(output.as_ptr().cast(),serv,n+1); }
    }
    0
}
/// # Safety
/// Nonnull host/service strings must be NUL-terminated; nonnull hint must
/// be readable. res must be writable. Release successful lists only with
/// this runtime's freeaddrinfo; do not free or modify individual nodes.
#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(host: *const c_char,serv: *const c_char,hint: *const CabiAddrInfo,res: *mut *mut CabiAddrInfo) -> c_int {
    if host.is_null() && serv.is_null() { return -2; }
    let (mut family,flags,proto,socktype) = if hint.is_null() { (0,0,0,0) } else { unsafe { ((*hint).family,(*hint).flags,(*hint).protocol,(*hint).socktype) } };
    if flags & !0x43f != 0 { return -1; } if !matches!(family,0|2|10) { return -6; }
    let mut no_family = false;
    if flags & 32 != 0 {
        for (af,other) in [(2,10),(10,2)] {
            if family == other { continue; }
            let mut a = Address::for_family(af); if af == 2 { a.bytes[..4].copy_from_slice(&[127,0,0,1]); } else { a.bytes[15] = 1; }
            let (socket,len) = lookup::sockaddr(&a,65535);
            let fd = unsafe { c_status(raw_syscall::syscall3(41,af as i64,2|0x80000,17)) };
            if fd >= 0 {
                let mut cancel = 0; unsafe { pthread_cancel::pthread_setcancelstate(1,&mut cancel); }
                let r = unsafe { c_status(raw_syscall::syscall3(42,fd as i64,socket.as_ptr() as i64,len as i64)) };
                let saved = unsafe { *errno::__errno_location() };
                unsafe { pthread_cancel::pthread_setcancelstate(cancel,ptr::null_mut()); c_status(raw_syscall::syscall1(3,fd as i64)); }
                if r == 0 { continue; } unsafe { errno::set_errno(saved); }
            }
            if !matches!(unsafe { *errno::__errno_location() },99|97|113|100|101) { return -11; }
            if family == af { no_family = true; } family = other;
        }
    }
    let mut ports = [Service::EMPTY;2]; let nports = unsafe { lookup::services(&mut ports,serv,proto,socktype,flags) };
    if nports < 0 { return nports; }
    let mut addresses = [Address::EMPTY;MAX_ADDRS]; let mut canon = [0u8;256];
    let count = unsafe { lookup::names(&mut addresses,&mut canon,host,family,flags) };
    if count < 0 { return count; } if no_family { return -5; }
    let mut first = ptr::null_mut(); let mut last = ptr::null_mut();
    for address in &addresses[..count as usize] { for port in &ports[..nports as usize] {
        let result = unsafe { numeric_netdb::append_node(&mut first,&mut last,
            numeric_netdb::Address { family: address.family,bytes: address.bytes },
            port.socktype as i32,port.protocol as i32,port.port,flags,
            if canon[0] == 0 { ptr::null() } else { canon.as_ptr().cast() }) };
        if let Err(error) = result { unsafe { numeric_netdb::freeaddrinfo(first); } return error; }
        unsafe {
            if address.family == 10 { numeric_netdb::set_owned_scope(last,address.scope); }
            (*last).canonname = (*first).canonname;
        }
    } }
    unsafe { *res = first; } 0
}
