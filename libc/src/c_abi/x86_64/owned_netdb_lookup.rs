//! Allocation-free owned netdb backends, translated from musl 1.2.6
//! `src/network/{lookup_name,lookup_ipliteral,lookup_serv,resolvconf}.c`.
//! Fixed release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT;
//! archive/license provenance is recorded in `compat/upstreams.toml`.
//! Conventional files use the owned stack FILE adapter. DNS framing and
//! bounded transport remain in crabc-core; there is no libc resolver-state
//! cache and these helpers never mutate h_errno. Source destination policy
//! remains scalar. The native transport sends family queries sequentially
//! instead of musl's parallel msend, retaining the established bounded core
//! transport contract and independent response validation. That raw transport
//! is not a deferred C cancellation point and has no C cancellation cleanup
//! registration. An owned cancellation/descriptor cleanup adapter remains a
//! resolver-family closure obligation. Only the source sorting and address
//! configuration cancellation masks are preserved by this slice. Typed
//! rdata_at extraction groups address records and CNAMEs; musl callback
//! interleaving after malformed address RDLENGTH is not qualified here.
use core::{ffi::{c_char, c_int}, ptr};
use super::{c_status, errno, inet_address, integer_parse, interface_discovery,
    locale_multibyte, pthread_cancel, raw_syscall, stdio_standard};
use crabc_core::resolver::{self, ExchangeConfig, ExchangeError, NameServer, DnsResponse};

pub(super) const MAX_ADDRS: usize = 48;
pub(super) const V4_PREFIX: [u8; 12] = [0,0,0,0,0,0,0,0,0,0,255,255];
#[derive(Clone, Copy)]
pub(super) struct Address { pub family: c_int, pub scope: u32, pub bytes: [u8;16], key: i32 }
impl Address { pub const fn for_family(family: c_int) -> Self { Self { family, ..Self::EMPTY } } pub const EMPTY: Self = Self { family: 0, scope: 0, bytes: [0;16], key: 0 }; }
#[derive(Clone, Copy)]
pub(super) struct Service { pub port: u16, pub protocol: u8, pub socktype: u8 }
impl Service { pub const EMPTY: Self = Self { port: 0, protocol: 0, socktype: 0 }; }

pub(super) unsafe fn bytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { core::ffi::CStr::from_ptr(p).to_bytes() }
}
pub(super) fn whitespace(c: u8) -> bool { c == b' ' || c.wrapping_sub(b'\t') < 5 }
pub(super) fn line_bytes(line: &[u8]) -> &[u8] { &line[..line.iter().position(|&c| c == 0).unwrap_or(line.len())] }
fn strip_comment(line: &mut [u8]) {
    if let Some(i) = line.iter().position(|&c| c == b'#') {
        line[i] = b'\n'; if i+1 < line.len() { line[i+1] = 0; }
    }
}
fn valid_hostname(name: &[u8]) -> bool {
    if name.is_empty() || name.len() >= 255 { return false; }
    let mut value = [0u8;256]; value[..name.len()].copy_from_slice(name);
    (unsafe { locale_multibyte::mbstowcs(ptr::null_mut(), value.as_ptr().cast(), 0) != usize::MAX })
        && name.iter().all(|c| *c >= 128 || *c == b'.' || *c == b'-' || c.is_ascii_alphanumeric())
}
pub(super) fn copy_name(output: &mut [u8;256], name: &[u8]) {
    output[..name.len()].copy_from_slice(name); output[name.len()] = 0;
}
pub(super) fn linklocal(a: &[u8;16]) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0x80 || a[0] == 0xff && a[1] & 15 == 2
}

pub(super) unsafe fn numeric(out: &mut Address, name: *const c_char, family: c_int) -> c_int {
    let mut a = [0u8;16];
    if unsafe { inet_address::__inet_aton(name, a.as_mut_ptr().cast()) } > 0 {
        if family == 10 { return -5; }
        *out = Address { family: 2, bytes: a, ..Address::EMPTY }; return 1;
    }
    let text = unsafe { bytes(name) };
    let percent = text.iter().position(|&c| c == b'%');
    let mut temp = [0u8;64];
    let numeric_name = match percent {
        Some(p) if p < 64 => { temp[..p].copy_from_slice(&text[..p]); temp.as_ptr().cast() }
        _ => name,
    };
    if unsafe { inet_address::inet_pton(10, numeric_name, a.as_mut_ptr().cast()) } <= 0 { return 0; }
    if family == 2 { return -5; }
    let mut scope = 0u64;
    if let Some(p) = percent {
        let suffix = unsafe { name.add(p+1) };
        let mut end = unsafe { suffix.sub(1) } as *mut c_char;
        if text.get(p+1).is_some_and(u8::is_ascii_digit) {
            scope = unsafe { integer_parse::strtoull(suffix, &mut end, 10) };
        }
        if unsafe { *end } != 0 {
            if !linklocal(&a) { return -2; }
            scope = unsafe { interface_discovery::if_nametoindex(suffix) } as u64;
            if scope == 0 { return -2; }
        }
        if scope > u32::MAX as u64 { return -2; }
    }
    *out = Address { family: 10, scope: scope as u32, bytes: a, key: 0 }; 1
}

unsafe fn hosts(out: &mut [Address;MAX_ADDRS], canon: &mut [u8;256], name: &[u8], family: c_int) -> c_int {
    let mut count = 0; let mut bad_family = 0; let mut have_canon = false;
    let result = unsafe { stdio_standard::with_readonly_file(c"/etc/hosts".as_ptr(), 1024, |file| {
        let mut line = [0u8;512];
        while !stdio_standard::fgets(line.as_mut_ptr().cast(), 512, file).is_null() && count < MAX_ADDRS {
            strip_comment(&mut line);
            let data = line_bytes(&line);
            if !(1..data.len()).any(|p| data[p..].starts_with(name)
                && whitespace(data[p-1]) && data.get(p+name.len()).is_some_and(|&c| whitespace(c))) { continue; }
            let end = data.iter().position(|&c| whitespace(c)).unwrap_or(data.len());
            line[end] = 0;
            match numeric(&mut out[count], line.as_ptr().cast(), family) {
                1 => count += 1, 0 => continue, _ => bad_family = -5,
            }
            if have_canon { continue; }
            let start = end+1;
            let rest = line_bytes(&line[start..]);
            let rest = &rest[rest.iter().position(|&c| !whitespace(c)).unwrap_or(rest.len())..];
            let canonical = &rest[..rest.iter().position(|&c| whitespace(c)).unwrap_or(rest.len())];
            if valid_hostname(canonical) { copy_name(canon, canonical); have_canon = true; }
        }
    }) };
    match result { Err(2|20|13) => 0, Err(_) => -11, Ok(()) if count > 0 => count as c_int, _ => bad_family }
}

pub(super) unsafe fn services(out: &mut [Service;2], name: *const c_char, mut proto: c_int, socktype: c_int, flags: c_int) -> c_int {
    match socktype {
        1 => { if proto == 0 { proto = 6; } if proto != 6 { return -8; } }
        2 => { if proto == 0 { proto = 17; } if proto != 17 { return -8; } }
        0 => (),
        _ => { if !name.is_null() { return -8; } out[0] = Service { port: 0, protocol: proto as u8, socktype: socktype as u8 }; return 1; }
    }
    let mut end = c"".as_ptr() as *mut c_char;
    let port = if name.is_null() { 0 } else {
        if unsafe { *name } == 0 { return -8; }
        unsafe { integer_parse::strtoul(name, &mut end, 10) }
    };
    let mut count = 0;
    if unsafe { *end } == 0 {
        if port > 65535 { return -8; }
        if proto != 17 { out[count] = Service { port: port as u16, protocol: 6, socktype: 1 }; count += 1; }
        if proto != 6 { out[count] = Service { port: port as u16, protocol: 17, socktype: 2 }; count += 1; }
        return count as c_int;
    }
    if flags & 0x400 != 0 { return -2; }
    let requested = unsafe { bytes(name) };
    let result = unsafe { stdio_standard::with_readonly_file(c"/etc/services".as_ptr(), 1024, |file| {
        let mut line = [0u8;128];
        while !stdio_standard::fgets(line.as_mut_ptr().cast(), 128, file).is_null() && count < 2 {
            strip_comment(&mut line);
            let data = line_bytes(&line);
            if !(0..data.len()).any(|p| data[p..].starts_with(requested)
                && (p == 0 || whitespace(data[p-1]))
                && data.get(p+requested.len()).is_none_or(|&c| whitespace(c))) { continue; }
            let p = data.iter().position(|&c| whitespace(c)).unwrap_or(data.len());
            let start = line.as_ptr().add(p).cast();
            let mut end = ptr::null_mut();
            let port = integer_parse::strtoul(start, &mut end, 10);
            if port > 65535 || end.cast_const() == start { continue; }
            let suffix = bytes(end);
            if suffix.starts_with(b"/udp") && proto != 6 { out[count] = Service { port: port as u16, protocol: 17, socktype: 2 }; count += 1; }
            if suffix.starts_with(b"/tcp") && proto != 17 { out[count] = Service { port: port as u16, protocol: 6, socktype: 1 }; count += 1; }
        }
    }) };
    match result { Err(2|20|13) => -8, Err(_) => -11, _ if count > 0 => count as c_int, _ => -8 }
}

pub(super) struct Config { pub exchange: ExchangeConfig, search: [u8;256], ndots: usize }
pub(super) unsafe fn configuration() -> Result<Config,c_int> {
    let mut conf = Config { exchange: ExchangeConfig::single(NameServer::ipv4([127,0,0,1]), 5000), search: [0;256], ndots: 1 };
    conf.exchange.attempts = 2;
    let mut count = 0;
    let result = unsafe { stdio_standard::with_readonly_file(c"/etc/resolv.conf".as_ptr(), 248, |file| {
        let mut line = [0u8;256];
        while !stdio_standard::fgets(line.as_mut_ptr().cast(), 256, file).is_null() {
            if !line_bytes(&line).contains(&b'\n') && stdio_standard::feof(file) == 0 {
                loop { let c = stdio_standard::fgetc(file); if c == -1 || c == 10 { break; } }
                continue;
            }
            let data = line_bytes(&line);
            if data.starts_with(b"options") && data.get(7).is_some_and(|&c| whitespace(c)) {
                for (key, cap) in [(b"ndots:".as_slice(),15), (b"attempts:".as_slice(),10), (b"timeout:".as_slice(),60)] {
                    if let Some(p) = data.windows(key.len()).position(|s| s == key) {
                        let p = p+key.len();
                        if !data.get(p).is_some_and(|c| c.is_ascii_digit() || key == b"timeout:" && *c == b'.') { continue; }
                        let start = line.as_ptr().add(p).cast(); let mut end = ptr::null_mut();
                        let value = integer_parse::strtoul(start, &mut end, 10).min(cap);
                        if end.cast_const() != start {
                            match key { b"ndots:" => conf.ndots = value as usize, b"attempts:" => conf.exchange.attempts = value as u8, _ => conf.exchange.timeout_ms = value as u32 * 1000 }
                        }
                    }
                }
            } else if data.starts_with(b"nameserver") && data.get(10).is_some_and(|&c| whitespace(c)) {
                if count >= 3 { continue; }
                let start = (11..data.len()).find(|&i| !whitespace(data[i])).unwrap_or(data.len());
                let end = (start..data.len()).find(|&i| whitespace(data[i])).unwrap_or(data.len());
                line[end] = 0;
                let mut address = Address::EMPTY;
                if numeric(&mut address, line.as_ptr().add(start).cast(), 0) > 0 {
                    conf.exchange.nameservers[count] = NameServer { family: address.family as u16, address: address.bytes, port: 53, scope_id: address.scope }; count += 1;
                }
            } else if (data.starts_with(b"search") || data.starts_with(b"domain")) && data.get(6).is_some_and(|&c| whitespace(c)) {
                let start = (7..data.len()).find(|&i| !whitespace(data[i])).unwrap_or(data.len());
                copy_name(&mut conf.search, &data[start..]);
            }
        }
    }) };
    if let Err(error) = result { if !matches!(error, 2|20|13) { return Err(-1); } }
    conf.exchange.nameserver_count = count.max(1);
    Ok(conf)
}

pub(super) unsafe fn query(config: &Config, name: &[u8], kind: u16, answer: &mut [u8]) -> Result<(usize,u16), c_int> {
    let mut time = [0i64;2];
    unsafe { c_status(raw_syscall::syscall2(228, 0, time.as_mut_ptr() as i64)); }
    let id = (time[1] + time[1]/65536) as u16;
    let mut wire = [0u8;280];
    let length = resolver::encode_query(name, kind, id, &mut wire).map_err(|_| 0)?;
    match resolver::exchange_with_setup_error(&config.exchange, &wire[..length], id, answer) {
        Ok(n) => Ok((n,id)),
        Err(ExchangeError::Setup(error)) => { unsafe { errno::set_errno(error.raw()) }; Err(-11) }
        Err(ExchangeError::Transport(_)) => Err(-3),
    }
}

unsafe fn dns(out: &mut [Address;MAX_ADDRS], canon: &mut [u8;256], name: &[u8], family: c_int, conf: &Config) -> c_int {
    let mut replies = [[0u8;4800];2]; let mut lengths = [0;2]; let mut ids = [0;2]; let mut kinds = [0;2]; let mut errors = [0;2]; let mut nq = 0;
    for (excluded, kind) in [(10,1), (2,28)] {
        if family == excluded { continue; }
        kinds[nq] = kind;
        match unsafe { query(conf, name, kind, &mut replies[nq]) } {
            Ok((n,id)) => { lengths[nq] = n; ids[nq] = id; },
            // Socket setup is the msend operation's system failure, whereas
            // an unanswered individual query belongs to its family slot.
            Err(-11) => return -11,
            Err(0) => return 0,
            Err(error) => errors[nq] = error,
        }
        nq += 1;
    }
    // musl inspects A before AAAA after collecting both outcomes. An earlier
    // NXDOMAIN therefore wins over a later timeout and permits search to
    // continue; the opposite order retains TRY_AGAIN.
    for i in 0..nq {
        if errors[i] != 0 || lengths[i] < 4 { return -3; }
        match replies[i][3] & 15 { 0 => (), 2 => return -3, 3 => return 0, _ => return -4 }
    }
    let mut count = 0;
    for i in (0..nq).rev() {
        let Ok(response) = DnsResponse::parse(&replies[i][..lengths[i]], name, kinds[i], ids[i]) else { continue; };
        let mut ordinal = 0;
        while count < MAX_ADDRS {
            let mut address = Address::EMPTY;
            let Ok(Some(n)) = response.rdata_at(kinds[i], ordinal, &mut address.bytes) else { break; };
            if n != if kinds[i] == 1 { 4 } else { 16 } { break; }
            address.family = if kinds[i] == 1 { 2 } else { 10 }; out[count] = address; count += 1; ordinal += 1;
        }
        let mut ordinal = 0; let mut cname = [0u8;256];
        while let Ok(Some(n)) = response.rdata_at(5, ordinal, &mut cname) {
            if valid_hostname(&cname[..n]) { copy_name(canon, &cname[..n]); } ordinal += 1;
        }
    }
    if count > 0 { count as c_int } else { -5 }
}

unsafe fn dns_search(out: &mut [Address;MAX_ADDRS], canon: &mut [u8;256], name: &[u8], family: c_int) -> c_int {
    let conf = match unsafe { configuration() } { Ok(c) => c, Err(e) => return e };
    let mut length = name.len();
    let search = name.iter().filter(|&&c| c == b'.').count() < conf.ndots && name.last() != Some(&b'.');
    if name.last() == Some(&b'.') { length -= 1; }
    if length == 0 || name[length-1] == b'.' { return -2; }
    copy_name(canon, &name[..length]);
    if search {
        for suffix in line_bytes(&conf.search).split(|&c| whitespace(c)).filter(|s| !s.is_empty()) {
            if suffix.len() >= 255-length { continue; }
            canon[length] = b'.'; canon[length+1..length+1+suffix.len()].copy_from_slice(suffix); canon[length+1+suffix.len()] = 0;
            let request = *canon;
            let count = unsafe { dns(out, canon, line_bytes(&request), family, &conf) };
            if count != 0 { return count; }
        }
    }
    canon[length] = 0;
    unsafe { dns(out, canon, name, family, &conf) }
}

fn mapped(address: &Address) -> [u8;16] {
    if address.family == 10 { address.bytes } else {
        let mut result = [0u8;16]; result[..12].copy_from_slice(&V4_PREFIX); result[12..].copy_from_slice(&address.bytes[..4]); result
    }
}
fn policy(a: &[u8;16]) -> (i32,i32) {
    if *a == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1] { (50,0) }
    else if a[..12] == V4_PREFIX { (35,4) }
    else if a[..2] == [0x20,2] { (30,2) }
    else if a[..4] == [0x20,1,0,0] { (5,5) }
    else if a[0] & 0xfe == 0xfc { (3,13) }
    else { (40,1) }
}
fn scope(a: &[u8;16]) -> i32 {
    if a[0] == 255 { (a[1]&15) as i32 }
    else if a[0] == 0xfe && a[1]&0xc0 == 0x80 || *a == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1] { 2 }
    else if a[0] == 0xfe && a[1]&0xc0 == 0xc0 { 5 } else { 14 }
}
/// Initialized Linux sockaddr bytes, reused by source selection and netdb ABI.
pub(super) fn sockaddr(a: &Address, port: u16) -> ([u8;28],u32) {
    let mut s = [0u8;28]; s[..2].copy_from_slice(&(a.family as u16).to_ne_bytes()); s[2..4].copy_from_slice(&port.to_be_bytes());
    if a.family == 2 { s[4..8].copy_from_slice(&a.bytes[..4]); (s,16) }
    else { s[8..24].copy_from_slice(&a.bytes); s[24..28].copy_from_slice(&a.scope.to_ne_bytes()); (s,28) }
}
unsafe fn sort_addresses(addresses: &mut [Address]) {
    let mut cancel = 0;
    unsafe { pthread_cancel::pthread_setcancelstate(1, &mut cancel); }
    for (i, a) in addresses.iter_mut().enumerate() {
        let destination = mapped(a); let (precedence,label) = policy(&destination); let dscope = scope(&destination);
        let mut key = 0; let mut prefix = 0;
        let (destination_sa, length) = sockaddr(a,65535); let mut source_sa = [0u8;28]; let mut source_length = length;
        let fd = unsafe { c_status(raw_syscall::syscall3(41, a.family as i64, 2|0x80000, 17)) };
        if fd >= 0 {
            if unsafe { c_status(raw_syscall::syscall3(42, fd as i64, destination_sa.as_ptr() as i64, length as i64)) } == 0 {
                key |= 0x40000000;
                if unsafe { c_status(raw_syscall::syscall3(51, fd as i64, source_sa.as_mut_ptr() as i64, &mut source_length as *mut u32 as i64)) } == 0 {
                    let mut source = [0u8;16];
                    if a.family == 2 { source[..12].copy_from_slice(&V4_PREFIX); source[12..].copy_from_slice(&source_sa[4..8]); }
                    else { source.copy_from_slice(&source_sa[8..24]); }
                    if dscope == scope(&source) { key |= 0x20000000; }
                    if label == policy(&source).1 { key |= 0x10000000; }
                    for bit in 0..128 { if (source[bit/8] ^ destination[bit/8]) & (128 >> (bit%8)) != 0 { break; } prefix += 1; }
                }
            }
            unsafe { c_status(raw_syscall::syscall1(3, fd as i64)); }
        }
        a.key = key | precedence<<20 | (15-dscope)<<16 | prefix<<8 | (MAX_ADDRS-i) as i32;
    }
    addresses.sort_unstable_by(|a,b| b.key.cmp(&a.key));
    unsafe { pthread_cancel::pthread_setcancelstate(cancel, ptr::null_mut()); }
}

pub(super) unsafe fn names(out: &mut [Address;MAX_ADDRS], canon: &mut [u8;256], name: *const c_char, mut family: c_int, mut flags: c_int) -> c_int {
    canon[0] = 0;
    let text = if name.is_null() { &[][..] } else {
        let mut length = 0;
        while length < 255 && unsafe { *name.add(length) } != 0 { length += 1; }
        if length == 0 || length >= 255 { return -2; }
        let value = unsafe { core::slice::from_raw_parts(name.cast::<u8>(), length) }; copy_name(canon, value); value
    };
    if flags & 8 != 0 { if family == 10 { family = 0; } else { flags &= !8; } }
    let mut count = 0;
    if name.is_null() {
        for af in [2,10] {
            if af == 2 && family == 10 || af == 10 && family == 2 { continue; }
            let a = &mut out[count]; *a = Address { family: af, ..Address::EMPTY };
            if flags & 1 == 0 { if af == 2 { a.bytes[..4].copy_from_slice(&[127,0,0,1]); } else { a.bytes[15] = 1; } }
            count += 1;
        }
    } else {
        let mut result = unsafe { numeric(&mut out[0], name, family) };
        if result == 0 && flags & 4 == 0 {
            result = unsafe { hosts(out, canon, text, family) };
            if result == 0 { result = unsafe { dns_search(out, canon, text, family) }; }
        }
        if result <= 0 { return if result == 0 { -2 } else { result }; }
        count = result as usize;
    }
    if flags & 8 != 0 {
        if flags & 16 == 0 && out[..count].iter().any(|a| a.family == 10) {
            let mut n = 0; for i in 0..count { if out[i].family == 10 { out[n] = out[i]; n += 1; } } count = n;
        }
        for a in &mut out[..count] { if a.family == 2 { a.bytes = mapped(a); a.family = 10; } }
    }
    if count >= 2 && family != 2 && out[..count].iter().any(|a| a.family != 2) { unsafe { sort_addresses(&mut out[..count]); } }
    count as c_int
}
