// Legacy network database APIs backed by the administrator's files.
//
// These interfaces deliberately do not ask a resolver or synthesize records:
// hosts come from /etc/hosts and the remaining databases come from their
// corresponding /etc files.  The non-reentrant interfaces own one process
// global result per database, while the *_r host interfaces copy into the
// caller's storage as required by their ABI.

const M4_NDB_O_RDONLY: c_int = 0;
const M4_NDB_AF_INET: c_int = 2;
const M4_NDB_AF_INET6: c_int = 10;
const M4_NDB_HOST_NOT_FOUND: c_int = 1;
const M4_NDB_NO_DATA: c_int = 4;
const M4_NDB_MAX_ALIASES: usize = 64;
const M4_NDB_READ_CHUNK: usize = 4096;

#[repr(C)]
pub struct M4Hostent {
    pub h_name: *mut c_char,
    pub h_aliases: *mut *mut c_char,
    pub h_addrtype: c_int,
    pub h_length: c_int,
    pub h_addr_list: *mut *mut c_char,
}

#[repr(C)]
pub struct M4Netent {
    pub n_name: *mut c_char,
    pub n_aliases: *mut *mut c_char,
    pub n_addrtype: c_int,
    pub n_net: u32,
}

#[repr(C)]
pub struct M4Protoent {
    pub p_name: *mut c_char,
    pub p_aliases: *mut *mut c_char,
    pub p_proto: c_int,
}

#[repr(C)]
pub struct M4Servent {
    pub s_name: *mut c_char,
    pub s_aliases: *mut *mut c_char,
    pub s_port: c_int,
    pub s_proto: *mut c_char,
}

struct M4NdbFile {
    data: *mut u8,
    length: usize,
    position: usize,
    stayopen: bool,
}

const M4_NDB_EMPTY_FILE: M4NdbFile = M4NdbFile {
    data: core::ptr::null_mut(),
    length: 0,
    position: 0,
    stayopen: false,
};

unsafe fn m4_ndb_set_errno_from(result: i64) {
    if result < 0 && result >= -4095 {
        ERRNO = (-result) as c_int;
    }
}

unsafe fn m4_ndb_dispose(file: *mut M4NdbFile) {
    if file.is_null() {
        return;
    }
    if !(*file).data.is_null() {
        free((*file).data as *mut c_void);
    }
    *file = M4_NDB_EMPTY_FILE;
}

// Read a small administrator file without relying on stdio.  A trailing NUL
// is kept in the allocation so token pointers are ordinary C strings.
unsafe fn m4_ndb_load(path: *const u8, file: *mut M4NdbFile) -> bool {
    if path.is_null() || file.is_null() {
        ERRNO = EINVAL_VAL;
        return false;
    }
    m4_ndb_dispose(file);
    let fd = sys_openat(AT_FDCWD, path, M4_NDB_O_RDONLY, 0);
    if fd < 0 {
        m4_ndb_set_errno_from(fd);
        return false;
    }
    let mut data: *mut u8 = core::ptr::null_mut();
    let mut capacity = 0usize;
    let mut length = 0usize;
    loop {
        if length == capacity {
            let next = if capacity == 0 {
                M4_NDB_READ_CHUNK
            } else {
                match capacity.checked_mul(2) {
                    Some(value) => value,
                    None => {
                        let _ = sys_close(fd);
                        free(data as *mut c_void);
                        ERRNO = ENOMEM_VAL;
                        return false;
                    }
                }
            };
            let allocation = match next.checked_add(1) {
                Some(value) => value,
                None => {
                    let _ = sys_close(fd);
                    free(data as *mut c_void);
                    ERRNO = ENOMEM_VAL;
                    return false;
                }
            };
            let replacement = realloc(data as *mut c_void, allocation) as *mut u8;
            if replacement.is_null() {
                let _ = sys_close(fd);
                free(data as *mut c_void);
                ERRNO = ENOMEM_VAL;
                return false;
            }
            data = replacement;
            capacity = next;
        }
        let read_count = sys_read(fd, data.add(length), capacity - length);
        if read_count < 0 {
            m4_ndb_set_errno_from(read_count);
            let _ = sys_close(fd);
            free(data as *mut c_void);
            return false;
        }
        if read_count == 0 {
            break;
        }
        length += read_count as usize;
    }
    let _ = sys_close(fd);
    if data.is_null() {
        data = calloc(1, 1) as *mut u8;
        if data.is_null() {
            ERRNO = ENOMEM_VAL;
            return false;
        }
    } else {
        *data.add(length) = 0;
    }
    (*file).data = data;
    (*file).length = length;
    (*file).position = 0;
    true
}

unsafe fn m4_ndb_next_line(file: *mut M4NdbFile) -> *mut u8 {
    if file.is_null() || (*file).data.is_null() || (*file).position >= (*file).length {
        return core::ptr::null_mut();
    }
    let line = (*file).data.add((*file).position);
    let mut end = line;
    let limit = (*file).data.add((*file).length);
    while end < limit && *end != b'\n' {
        end = end.add(1);
    }
    if end < limit {
        *end = 0;
        (*file).position = end.add(1).offset_from((*file).data) as usize;
    } else {
        (*file).position = (*file).length;
        *end = 0;
    }
    if end > line && *end.sub(1) == b'\r' {
        *end.sub(1) = 0;
    }
    line
}

#[inline]
unsafe fn m4_ndb_space(value: u8) -> bool {
    matches!(value, b' ' | b'\t' | b'\r' | b'\n' | b'\x0B' | b'\x0C')
}

// Return the next whitespace-delimited field and stop at a comment.  The
// line is tokenized in place; database buffers are owned until the next
// result/reset operation.
unsafe fn m4_ndb_field(cursor: *mut *mut u8) -> *mut c_char {
    if cursor.is_null() || (*cursor).is_null() {
        return core::ptr::null_mut();
    }
    let mut p = *cursor;
    while m4_ndb_space(*p) {
        p = p.add(1);
    }
    if *p == 0 || *p == b'#' {
        *cursor = p;
        return core::ptr::null_mut();
    }
    let start = p;
    while *p != 0 && !m4_ndb_space(*p) && *p != b'#' {
        p = p.add(1);
    }
    if *p == b'#' {
        *p = 0;
    } else if *p != 0 {
        *p = 0;
        p = p.add(1);
    }
    *cursor = p;
    start as *mut c_char
}

unsafe fn m4_ndb_ascii_equal(left: *const c_char, right: *const c_char) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    let mut a = left as *const u8;
    let mut b = right as *const u8;
    loop {
        let mut x = *a;
        let mut y = *b;
        if x >= b'A' && x <= b'Z' {
            x += b'a' - b'A';
        }
        if y >= b'A' && y <= b'Z' {
            y += b'a' - b'A';
        }
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
        a = a.add(1);
        b = b.add(1);
    }
}

unsafe fn m4_ndb_decimal(text: *const c_char) -> Option<c_int> {
    if text.is_null() || *text == 0 {
        return None;
    }
    let mut p = text as *const u8;
    let mut value = 0u64;
    while *p != 0 {
        if *p < b'0' || *p > b'9' {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((*p - b'0') as u64)?;
        if value > c_int::MAX as u64 {
            return None;
        }
        p = p.add(1);
    }
    Some(value as c_int)
}

unsafe fn m4_ndb_ipv4(text: *const c_char) -> Option<u32> {
    let mut bytes = [0u8; 4];
    if inet_aton(text, bytes.as_mut_ptr() as *mut c_void) != 1 {
        return None;
    }
    // inet_network accepts the abbreviated classful forms used by
    // /etc/networks (for example, the conventional "loopback 127" entry).
    Some(inet_network(text))
}

unsafe fn m4_ndb_ipv4_bytes(text: *const c_char, destination: *mut u8) -> bool {
    if destination.is_null() {
        return false;
    }
    inet_pton(M4_NDB_AF_INET, text, destination as *mut c_void) == 1
}

unsafe fn m4_ndb_ipv6_bytes(text: *const c_char, destination: *mut u8) -> bool {
    if destination.is_null() {
        return false;
    }
    inet_pton(M4_NDB_AF_INET6, text, destination as *mut c_void) == 1
}

// ================================ hosts ================================

static mut M4_HOST_ENUM: M4NdbFile = M4_NDB_EMPTY_FILE;
static mut M4_HOST_DIRECT: M4NdbFile = M4_NDB_EMPTY_FILE;
static mut M4_HOST_RESULT: M4Hostent = M4Hostent {
    h_name: core::ptr::null_mut(),
    h_aliases: core::ptr::null_mut(),
    h_addrtype: 0,
    h_length: 0,
    h_addr_list: core::ptr::null_mut(),
};
static mut M4_HOST_ALIASES: [*mut c_char; M4_NDB_MAX_ALIASES + 1] = [core::ptr::null_mut(); M4_NDB_MAX_ALIASES + 1];
static mut M4_HOST_ADDR_LIST: [*mut c_char; 2] = [core::ptr::null_mut(); 2];
static mut M4_HOST_ADDR: [u8; 16] = [0; 16];

struct M4HostRecord {
    name: *mut c_char,
    aliases: [*mut c_char; M4_NDB_MAX_ALIASES],
    alias_count: usize,
    family: c_int,
    length: usize,
    address: [u8; 16],
}

unsafe fn m4_host_record(line: *mut u8, record: *mut M4HostRecord) -> bool {
    if line.is_null() || record.is_null() {
        return false;
    }
    let mut cursor = line;
    let address = m4_ndb_field(&mut cursor);
    let name = m4_ndb_field(&mut cursor);
    if address.is_null() || name.is_null() {
        return false;
    }
    let mut parsed = M4HostRecord {
        name,
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        family: 0,
        length: 0,
        address: [0; 16],
    };
    if m4_ndb_ipv4_bytes(address, parsed.address.as_mut_ptr()) {
        parsed.family = M4_NDB_AF_INET;
        parsed.length = 4;
    } else if m4_ndb_ipv6_bytes(address, parsed.address.as_mut_ptr()) {
        parsed.family = M4_NDB_AF_INET6;
        parsed.length = 16;
    } else {
        return false;
    }
    while parsed.alias_count < M4_NDB_MAX_ALIASES {
        let alias = m4_ndb_field(&mut cursor);
        if alias.is_null() {
            break;
        }
        parsed.aliases[parsed.alias_count] = alias;
        parsed.alias_count += 1;
    }
    *record = parsed;
    true
}

unsafe fn m4_host_name_matches(record: *const M4HostRecord, name: *const c_char) -> bool {
    if record.is_null() || name.is_null() {
        return false;
    }
    if m4_ndb_ascii_equal((*record).name, name) {
        return true;
    }
    let mut index = 0;
    while index < (*record).alias_count {
        if m4_ndb_ascii_equal((*record).aliases[index], name) {
            return true;
        }
        index += 1;
    }
    false
}

unsafe fn m4_host_install(record: *const M4HostRecord) -> *mut M4Hostent {
    if record.is_null() {
        return core::ptr::null_mut();
    }
    let aliases = core::ptr::addr_of_mut!(M4_HOST_ALIASES);
    let addresses = core::ptr::addr_of_mut!(M4_HOST_ADDR_LIST);
    let address = core::ptr::addr_of_mut!(M4_HOST_ADDR);
    let mut index = 0;
    while index < (*record).alias_count {
        (*aliases)[index] = (*record).aliases[index];
        index += 1;
    }
    (*aliases)[(*record).alias_count] = core::ptr::null_mut();
    core::ptr::copy_nonoverlapping((*record).address.as_ptr(), (*address).as_mut_ptr(), (*record).length);
    (*addresses)[0] = (*address).as_mut_ptr() as *mut c_char;
    (*addresses)[1] = core::ptr::null_mut();
    M4_HOST_RESULT.h_name = (*record).name;
    M4_HOST_RESULT.h_aliases = aliases as *mut *mut c_char;
    M4_HOST_RESULT.h_addrtype = (*record).family;
    M4_HOST_RESULT.h_length = (*record).length as c_int;
    M4_HOST_RESULT.h_addr_list = addresses as *mut *mut c_char;
    core::ptr::addr_of_mut!(M4_HOST_RESULT)
}

unsafe fn m4_host_find(
    file: *mut M4NdbFile,
    name: *const c_char,
    address: *const u8,
    address_length: usize,
    family: c_int,
) -> *mut M4Hostent {
    let mut record = M4HostRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        family: 0,
        length: 0,
        address: [0; 16],
    };
    loop {
        let line = m4_ndb_next_line(file);
        if line.is_null() {
            break;
        }
        if !m4_host_record(line, &mut record) {
            continue;
        }
        if family != 0 && record.family != family {
            continue;
        }
        let matched = if !name.is_null() {
            m4_host_name_matches(&record, name)
        } else if !address.is_null() && address_length == record.length {
            core::slice::from_raw_parts(address, address_length)
                == core::slice::from_raw_parts(record.address.as_ptr(), address_length)
        } else {
            false
        };
        if matched {
            return m4_host_install(&record);
        }
    }
    core::ptr::null_mut()
}

unsafe fn m4_host_next(file: *mut M4NdbFile) -> *mut M4Hostent {
    let mut record = M4HostRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        family: 0,
        length: 0,
        address: [0; 16],
    };
    loop {
        let line = m4_ndb_next_line(file);
        if line.is_null() {
            return core::ptr::null_mut();
        }
        if m4_host_record(line, &mut record) {
            return m4_host_install(&record);
        }
    }
}

unsafe fn m4_host_direct_lookup(
    name: *const c_char,
    address: *const u8,
    address_length: usize,
    family: c_int,
) -> *mut M4Hostent {
    m4_ndb_dispose(core::ptr::addr_of_mut!(M4_HOST_DIRECT));
    if !m4_ndb_load(
        b"/etc/hosts\0".as_ptr(),
        core::ptr::addr_of_mut!(M4_HOST_DIRECT),
    ) {
        h_errno = M4_NDB_HOST_NOT_FOUND;
        return core::ptr::null_mut();
    }
    let result = m4_host_find(
        core::ptr::addr_of_mut!(M4_HOST_DIRECT),
        name,
        address,
        address_length,
        family,
    );
    if result.is_null() {
        h_errno = M4_NDB_HOST_NOT_FOUND;
        m4_ndb_dispose(core::ptr::addr_of_mut!(M4_HOST_DIRECT));
    } else {
        h_errno = 0;
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyname2(
    name: *const c_char,
    family: c_int,
) -> *mut M4Hostent {
    if name.is_null() {
        ERRNO = EINVAL_VAL;
        h_errno = M4_NDB_HOST_NOT_FOUND;
        return core::ptr::null_mut();
    }
    if family != M4_NDB_AF_INET && family != M4_NDB_AF_INET6 {
        h_errno = M4_NDB_NO_DATA;
        return core::ptr::null_mut();
    }
    m4_host_direct_lookup(name, core::ptr::null(), 0, family)
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut M4Hostent {
    gethostbyname2(name, M4_NDB_AF_INET)
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyaddr(
    address: *const c_void,
    length: c_uint,
    family: c_int,
) -> *mut M4Hostent {
    if address.is_null() {
        ERRNO = EINVAL_VAL;
        h_errno = M4_NDB_HOST_NOT_FOUND;
        return core::ptr::null_mut();
    }
    let expected = if family == M4_NDB_AF_INET {
        4
    } else if family == M4_NDB_AF_INET6 {
        16
    } else {
        h_errno = M4_NDB_NO_DATA;
        return core::ptr::null_mut();
    };
    if length as usize != expected {
        h_errno = M4_NDB_NO_DATA;
        return core::ptr::null_mut();
    }
    m4_host_direct_lookup(
        core::ptr::null(),
        address as *const u8,
        expected,
        family,
    )
}

#[no_mangle]
pub unsafe extern "C" fn sethostent(stayopen: c_int) {
    let file = core::ptr::addr_of_mut!(M4_HOST_ENUM);
    if (*file).data.is_null() {
        if !m4_ndb_load(b"/etc/hosts\0".as_ptr(), file) {
            return;
        }
    } else {
        (*file).position = 0;
    }
    (*file).stayopen = stayopen != 0;
}

#[no_mangle]
pub unsafe extern "C" fn endhostent() {
    m4_ndb_dispose(core::ptr::addr_of_mut!(M4_HOST_ENUM));
}

#[no_mangle]
pub unsafe extern "C" fn gethostent() -> *mut M4Hostent {
    let file = core::ptr::addr_of_mut!(M4_HOST_ENUM);
    if (*file).data.is_null() {
        sethostent(0);
        if (*file).data.is_null() {
            return core::ptr::null_mut();
        }
    }
    m4_host_next(file)
}

unsafe fn m4_ndb_align(value: usize, alignment: usize) -> Option<usize> {
    value.checked_add(alignment.wrapping_sub(1)).map(|v| v & !(alignment - 1))
}

unsafe fn m4_ndb_copy_string(
    source: *const c_char,
    destination: *mut u8,
    end: *mut u8,
) -> Option<*mut c_char> {
    if source.is_null() || destination.is_null() || end.is_null() {
        return None;
    }
    let length = strlen(source).checked_add(1)?;
    // Check integer addresses before forming a possibly out-of-bounds pointer;
    // callers use this path specifically to distinguish ERANGE from memory
    // corruption when the supplied reentrant buffer is too small.
    let next = (destination as usize).checked_add(length)?;
    if next > end as usize {
        return None;
    }
    core::ptr::copy_nonoverlapping(source as *const u8, destination, length);
    Some(destination as *mut c_char)
}

unsafe fn m4_host_copy_reentrant(
    source: *const M4HostRecord,
    destination: *mut M4Hostent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Hostent,
) -> c_int {
    if source.is_null() || destination.is_null() || result.is_null() {
        return EINVAL_VAL;
    }
    *result = core::ptr::null_mut();
    let pointer_size = core::mem::size_of::<*mut c_char>();
    let alias_bytes = match (*source).alias_count.checked_add(1).and_then(|v| v.checked_mul(pointer_size)) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let address_bytes = match 2usize.checked_mul(pointer_size) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let base = buffer as usize;
    let aligned = match m4_ndb_align(base, pointer_size) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let pointer_offset = aligned.checked_sub(base).unwrap_or(0);
    let pointer_total = match pointer_offset.checked_add(alias_bytes).and_then(|v| v.checked_add(address_bytes)) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    if buffer.is_null() || pointer_total > buffer_size {
        return ERANGE_VAL;
    }
    let alias_slots = (buffer as *mut u8).add(pointer_offset) as *mut *mut c_char;
    let address_slots = alias_slots.add((*source).alias_count + 1);
    let mut cursor = (address_slots as *mut u8).add(address_bytes);
    let end = (buffer as *mut u8).add(buffer_size);
    let name = match m4_ndb_copy_string((*source).name, cursor, end) {
        Some(value) => {
            cursor = cursor.add(strlen((*source).name) + 1);
            value
        }
        None => return ERANGE_VAL,
    };
    let mut index = 0;
    while index < (*source).alias_count {
        let alias = match m4_ndb_copy_string((*source).aliases[index], cursor, end) {
            Some(value) => value,
            None => return ERANGE_VAL,
        };
        cursor = cursor.add(strlen((*source).aliases[index]) + 1);
        *alias_slots.add(index) = alias;
        index += 1;
    }
    *alias_slots.add((*source).alias_count) = core::ptr::null_mut();
    let address = cursor;
    let next = match (address as usize).checked_add((*source).length) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    if next > end as usize {
        return ERANGE_VAL;
    }
    core::ptr::copy_nonoverlapping((*source).address.as_ptr(), address, (*source).length);
    *address_slots = address as *mut c_char;
    *address_slots.add(1) = core::ptr::null_mut();
    (*destination).h_name = name;
    (*destination).h_aliases = alias_slots;
    (*destination).h_addrtype = (*source).family;
    (*destination).h_length = (*source).length as c_int;
    (*destination).h_addr_list = address_slots;
    *result = destination;
    0
}

unsafe fn m4_host_reentrant(
    name: *const c_char,
    address: *const u8,
    address_length: usize,
    family: c_int,
    destination: *mut M4Hostent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Hostent,
    error: *mut c_int,
) -> c_int {
    if result.is_null() || error.is_null() || destination.is_null() {
        if !result.is_null() {
            *result = core::ptr::null_mut();
        }
        ERRNO = EINVAL_VAL;
        return EINVAL_VAL;
    }
    *result = core::ptr::null_mut();
    *error = M4_NDB_HOST_NOT_FOUND;
    if (name.is_null() && address.is_null()) || (!name.is_null() && !address.is_null()) {
        ERRNO = EINVAL_VAL;
        return EINVAL_VAL;
    }
    if family != M4_NDB_AF_INET && family != M4_NDB_AF_INET6 {
        *error = M4_NDB_NO_DATA;
        return EAFNOSUPPORT_VAL;
    }
    if !address.is_null() && address_length != if family == M4_NDB_AF_INET { 4 } else { 16 } {
        *error = M4_NDB_NO_DATA;
        return EINVAL_VAL;
    }
    let mut file = M4_NDB_EMPTY_FILE;
    if !m4_ndb_load(b"/etc/hosts\0".as_ptr(), &mut file) {
        // A missing hosts file is an ordinary negative lookup in musl's
        // resolver path; report it through h_errnop without inventing an
        // errno-style failure for the reentrant API.
        if ERRNO == ENOENT_VAL || ERRNO == ENOTDIR_VAL || ERRNO == EACCES_VAL {
            return 0;
        }
        return if ERRNO == 0 { ENOENT_VAL } else { ERRNO };
    }
    let mut record = M4HostRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        family: 0,
        length: 0,
        address: [0; 16],
    };
    let mut found = false;
    loop {
        let line = m4_ndb_next_line(&mut file);
        if line.is_null() {
            break;
        }
        if !m4_host_record(line, &mut record) || record.family != family {
            continue;
        }
        if !name.is_null() {
            if m4_host_name_matches(&record, name) {
                found = true;
                break;
            }
        } else if core::slice::from_raw_parts(address, address_length)
            == core::slice::from_raw_parts(record.address.as_ptr(), address_length)
        {
            found = true;
            break;
        }
    }
    let code = if found {
        m4_host_copy_reentrant(&record, destination, buffer, buffer_size, result)
    } else {
        0
    };
    free(file.data as *mut c_void);
    if code != 0 {
        ERRNO = code;
    } else if found {
        *error = 0;
    }
    code
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyname2_r(
    name: *const c_char,
    family: c_int,
    destination: *mut M4Hostent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Hostent,
    error: *mut c_int,
) -> c_int {
    m4_host_reentrant(name, core::ptr::null(), 0, family, destination, buffer, buffer_size, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyname_r(
    name: *const c_char,
    destination: *mut M4Hostent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Hostent,
    error: *mut c_int,
) -> c_int {
    gethostbyname2_r(name, M4_NDB_AF_INET, destination, buffer, buffer_size, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyaddr_r(
    address: *const c_void,
    length: c_uint,
    family: c_int,
    destination: *mut M4Hostent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Hostent,
    error: *mut c_int,
) -> c_int {
    m4_host_reentrant(core::ptr::null(), address as *const u8, length as usize, family, destination, buffer, buffer_size, result, error)
}

// =============================== networks ===============================

static mut M4_NETWORK_ENUM: M4NdbFile = M4_NDB_EMPTY_FILE;
static mut M4_NETWORK_DIRECT: M4NdbFile = M4_NDB_EMPTY_FILE;
static mut M4_NETWORK_RESULT: M4Netent = M4Netent {
    n_name: core::ptr::null_mut(),
    n_aliases: core::ptr::null_mut(),
    n_addrtype: 0,
    n_net: 0,
};
static mut M4_NETWORK_ALIASES: [*mut c_char; M4_NDB_MAX_ALIASES + 1] = [core::ptr::null_mut(); M4_NDB_MAX_ALIASES + 1];

struct M4NetworkRecord {
    name: *mut c_char,
    aliases: [*mut c_char; M4_NDB_MAX_ALIASES],
    alias_count: usize,
    network: u32,
}

unsafe fn m4_network_record(line: *mut u8, record: *mut M4NetworkRecord) -> bool {
    if line.is_null() || record.is_null() {
        return false;
    }
    let mut cursor = line;
    let name = m4_ndb_field(&mut cursor);
    let number = m4_ndb_field(&mut cursor);
    if name.is_null() || number.is_null() {
        return false;
    }
    let network = match m4_ndb_ipv4(number) {
        Some(value) => value,
        None => return false,
    };
    let mut parsed = M4NetworkRecord {
        name,
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        network,
    };
    while parsed.alias_count < M4_NDB_MAX_ALIASES {
        let alias = m4_ndb_field(&mut cursor);
        if alias.is_null() {
            break;
        }
        parsed.aliases[parsed.alias_count] = alias;
        parsed.alias_count += 1;
    }
    *record = parsed;
    true
}

unsafe fn m4_network_install(record: *const M4NetworkRecord) -> *mut M4Netent {
    let aliases = core::ptr::addr_of_mut!(M4_NETWORK_ALIASES);
    let mut index = 0;
    while index < (*record).alias_count {
        (*aliases)[index] = (*record).aliases[index];
        index += 1;
    }
    (*aliases)[(*record).alias_count] = core::ptr::null_mut();
    M4_NETWORK_RESULT.n_name = (*record).name;
    M4_NETWORK_RESULT.n_aliases = aliases as *mut *mut c_char;
    M4_NETWORK_RESULT.n_addrtype = M4_NDB_AF_INET;
    M4_NETWORK_RESULT.n_net = (*record).network;
    core::ptr::addr_of_mut!(M4_NETWORK_RESULT)
}

unsafe fn m4_network_next(file: *mut M4NdbFile) -> *mut M4Netent {
    let mut record = M4NetworkRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        network: 0,
    };
    loop {
        let line = m4_ndb_next_line(file);
        if line.is_null() {
            return core::ptr::null_mut();
        }
        if m4_network_record(line, &mut record) {
            return m4_network_install(&record);
        }
    }
}

unsafe fn m4_network_lookup(name: *const c_char, network: Option<u32>) -> *mut M4Netent {
    let file = core::ptr::addr_of_mut!(M4_NETWORK_DIRECT);
    m4_ndb_dispose(file);
    if !m4_ndb_load(b"/etc/networks\0".as_ptr(), file) {
        return core::ptr::null_mut();
    }
    let mut record = M4NetworkRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        network: 0,
    };
    let mut found = false;
    loop {
        let line = m4_ndb_next_line(file);
        if line.is_null() {
            break;
        }
        if !m4_network_record(line, &mut record) {
            continue;
        }
        if let Some(wanted) = network {
            if record.network == wanted {
                found = true;
                break;
            }
        } else if m4_ndb_ascii_equal(record.name, name) {
            found = true;
            break;
        } else {
            let mut index = 0;
            while index < record.alias_count {
                if m4_ndb_ascii_equal(record.aliases[index], name) {
                    found = true;
                    break;
                }
                index += 1;
            }
            if found {
                break;
            }
        }
    }
    let result = if found { m4_network_install(&record) } else { core::ptr::null_mut() };
    if !found {
        m4_ndb_dispose(file);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn getnetbyaddr(network: u32, address_type: c_int) -> *mut M4Netent {
    if address_type != M4_NDB_AF_INET {
        return core::ptr::null_mut();
    }
    m4_network_lookup(core::ptr::null(), Some(network))
}

#[no_mangle]
pub unsafe extern "C" fn getnetbyname(name: *const c_char) -> *mut M4Netent {
    if name.is_null() {
        ERRNO = EINVAL_VAL;
        return core::ptr::null_mut();
    }
    m4_network_lookup(name, None)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn setnetent(stayopen: c_int) {
    let file = core::ptr::addr_of_mut!(M4_NETWORK_ENUM);
    if (*file).data.is_null() {
        if !m4_ndb_load(b"/etc/networks\0".as_ptr(), file) {
            return;
        }
    } else {
        (*file).position = 0;
    }
    (*file).stayopen = stayopen != 0;
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn endnetent() {
    m4_ndb_dispose(core::ptr::addr_of_mut!(M4_NETWORK_ENUM));
}

#[no_mangle]
pub unsafe extern "C" fn getnetent() -> *mut M4Netent {
    let file = core::ptr::addr_of_mut!(M4_NETWORK_ENUM);
    if (*file).data.is_null() {
        setnetent(0);
        if (*file).data.is_null() {
            return core::ptr::null_mut();
        }
    }
    m4_network_next(file)
}

// =============================== protocols ==============================

static mut M4_PROTOCOL_ENUM: M4NdbFile = M4_NDB_EMPTY_FILE;
static mut M4_PROTOCOL_DIRECT: M4NdbFile = M4_NDB_EMPTY_FILE;
static mut M4_PROTOCOL_RESULT: M4Protoent = M4Protoent {
    p_name: core::ptr::null_mut(),
    p_aliases: core::ptr::null_mut(),
    p_proto: 0,
};
static mut M4_PROTOCOL_ALIASES: [*mut c_char; M4_NDB_MAX_ALIASES + 1] = [core::ptr::null_mut(); M4_NDB_MAX_ALIASES + 1];

struct M4ProtocolRecord {
    name: *mut c_char,
    aliases: [*mut c_char; M4_NDB_MAX_ALIASES],
    alias_count: usize,
    number: c_int,
}

unsafe fn m4_protocol_record(line: *mut u8, record: *mut M4ProtocolRecord) -> bool {
    if line.is_null() || record.is_null() {
        return false;
    }
    let mut cursor = line;
    let name = m4_ndb_field(&mut cursor);
    let number = m4_ndb_field(&mut cursor);
    if name.is_null() || number.is_null() {
        return false;
    }
    let number = match m4_ndb_decimal(number) {
        Some(value) => value,
        None => return false,
    };
    let mut parsed = M4ProtocolRecord {
        name,
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        number,
    };
    while parsed.alias_count < M4_NDB_MAX_ALIASES {
        let alias = m4_ndb_field(&mut cursor);
        if alias.is_null() {
            break;
        }
        parsed.aliases[parsed.alias_count] = alias;
        parsed.alias_count += 1;
    }
    *record = parsed;
    true
}

unsafe fn m4_protocol_install(record: *const M4ProtocolRecord) -> *mut M4Protoent {
    let aliases = core::ptr::addr_of_mut!(M4_PROTOCOL_ALIASES);
    let mut index = 0;
    while index < (*record).alias_count {
        (*aliases)[index] = (*record).aliases[index];
        index += 1;
    }
    (*aliases)[(*record).alias_count] = core::ptr::null_mut();
    M4_PROTOCOL_RESULT.p_name = (*record).name;
    M4_PROTOCOL_RESULT.p_aliases = aliases as *mut *mut c_char;
    M4_PROTOCOL_RESULT.p_proto = (*record).number;
    core::ptr::addr_of_mut!(M4_PROTOCOL_RESULT)
}

unsafe fn m4_protocol_next(file: *mut M4NdbFile) -> *mut M4Protoent {
    let mut record = M4ProtocolRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        number: 0,
    };
    loop {
        let line = m4_ndb_next_line(file);
        if line.is_null() {
            return core::ptr::null_mut();
        }
        if m4_protocol_record(line, &mut record) {
            return m4_protocol_install(&record);
        }
    }
}

unsafe fn m4_protocol_lookup(name: *const c_char, number: Option<c_int>) -> *mut M4Protoent {
    let file = core::ptr::addr_of_mut!(M4_PROTOCOL_DIRECT);
    m4_ndb_dispose(file);
    if !m4_ndb_load(b"/etc/protocols\0".as_ptr(), file) {
        return core::ptr::null_mut();
    }
    let mut record = M4ProtocolRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        number: 0,
    };
    let mut found = false;
    loop {
        let line = m4_ndb_next_line(file);
        if line.is_null() {
            break;
        }
        if !m4_protocol_record(line, &mut record) {
            continue;
        }
        if let Some(wanted) = number {
            if record.number == wanted {
                found = true;
                break;
            }
        } else if m4_ndb_ascii_equal(record.name, name) {
            found = true;
            break;
        } else {
            let mut index = 0;
            while index < record.alias_count {
                if m4_ndb_ascii_equal(record.aliases[index], name) {
                    found = true;
                    break;
                }
                index += 1;
            }
            if found {
                break;
            }
        }
    }
    let result = if found { m4_protocol_install(&record) } else { core::ptr::null_mut() };
    if !found {
        m4_ndb_dispose(file);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn getprotobyname(name: *const c_char) -> *mut M4Protoent {
    if name.is_null() {
        ERRNO = EINVAL_VAL;
        return core::ptr::null_mut();
    }
    m4_protocol_lookup(name, None)
}

#[no_mangle]
pub unsafe extern "C" fn getprotobynumber(number: c_int) -> *mut M4Protoent {
    m4_protocol_lookup(core::ptr::null(), Some(number))
}

#[no_mangle]
pub unsafe extern "C" fn setprotoent(stayopen: c_int) {
    let file = core::ptr::addr_of_mut!(M4_PROTOCOL_ENUM);
    if (*file).data.is_null() {
        if !m4_ndb_load(b"/etc/protocols\0".as_ptr(), file) {
            return;
        }
    } else {
        (*file).position = 0;
    }
    (*file).stayopen = stayopen != 0;
}

#[no_mangle]
pub unsafe extern "C" fn endprotoent() {
    m4_ndb_dispose(core::ptr::addr_of_mut!(M4_PROTOCOL_ENUM));
}

#[no_mangle]
pub unsafe extern "C" fn getprotoent() -> *mut M4Protoent {
    let file = core::ptr::addr_of_mut!(M4_PROTOCOL_ENUM);
    if (*file).data.is_null() {
        setprotoent(0);
        if (*file).data.is_null() {
            return core::ptr::null_mut();
        }
    }
    m4_protocol_next(file)
}

// ================================ services ===============================

static mut M4_SERVICE_ENUM: M4NdbFile = M4_NDB_EMPTY_FILE;
static mut M4_SERVICE_DIRECT: M4NdbFile = M4_NDB_EMPTY_FILE;
static mut M4_SERVICE_RESULT: M4Servent = M4Servent {
    s_name: core::ptr::null_mut(),
    s_aliases: core::ptr::null_mut(),
    s_port: 0,
    s_proto: core::ptr::null_mut(),
};
static mut M4_SERVICE_ALIASES: [*mut c_char; M4_NDB_MAX_ALIASES + 1] = [core::ptr::null_mut(); M4_NDB_MAX_ALIASES + 1];

struct M4ServiceRecord {
    name: *mut c_char,
    aliases: [*mut c_char; M4_NDB_MAX_ALIASES],
    alias_count: usize,
    port: u16,
    protocol: *mut c_char,
}

unsafe fn m4_service_record(line: *mut u8, record: *mut M4ServiceRecord) -> bool {
    if line.is_null() || record.is_null() {
        return false;
    }
    let mut cursor = line;
    let name = m4_ndb_field(&mut cursor);
    let port_protocol = m4_ndb_field(&mut cursor);
    if name.is_null() || port_protocol.is_null() {
        return false;
    }
    let mut split = port_protocol as *mut u8;
    while *split != 0 && *split != b'/' {
        split = split.add(1);
    }
    if *split != b'/' {
        return false;
    }
    *split = 0;
    let protocol = split.add(1) as *mut c_char;
    let port = match m4_ndb_decimal(port_protocol) {
        Some(value) if value >= 0 && value <= u16::MAX as c_int => (value as u16).to_be(),
        _ => return false,
    };
    if *protocol as u8 == 0 {
        return false;
    }
    let mut parsed = M4ServiceRecord {
        name,
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        port,
        protocol,
    };
    while parsed.alias_count < M4_NDB_MAX_ALIASES {
        let alias = m4_ndb_field(&mut cursor);
        if alias.is_null() {
            break;
        }
        parsed.aliases[parsed.alias_count] = alias;
        parsed.alias_count += 1;
    }
    *record = parsed;
    true
}

unsafe fn m4_service_install(record: *const M4ServiceRecord) -> *mut M4Servent {
    let aliases = core::ptr::addr_of_mut!(M4_SERVICE_ALIASES);
    let mut index = 0;
    while index < (*record).alias_count {
        (*aliases)[index] = (*record).aliases[index];
        index += 1;
    }
    (*aliases)[(*record).alias_count] = core::ptr::null_mut();
    M4_SERVICE_RESULT.s_name = (*record).name;
    M4_SERVICE_RESULT.s_aliases = aliases as *mut *mut c_char;
    M4_SERVICE_RESULT.s_port = (*record).port as c_int;
    M4_SERVICE_RESULT.s_proto = (*record).protocol;
    core::ptr::addr_of_mut!(M4_SERVICE_RESULT)
}

unsafe fn m4_service_matches(
    record: *const M4ServiceRecord,
    name: *const c_char,
    port: Option<u16>,
    protocol: *const c_char,
) -> bool {
    if let Some(wanted_port) = port {
        if (*record).port != wanted_port {
            return false;
        }
    } else {
        let mut name_match = m4_ndb_ascii_equal((*record).name, name);
        let mut index = 0;
        while !name_match && index < (*record).alias_count {
            name_match = m4_ndb_ascii_equal((*record).aliases[index], name);
            index += 1;
        }
        if !name_match {
            return false;
        }
    }
    protocol.is_null() || m4_ndb_ascii_equal((*record).protocol, protocol)
}

unsafe fn m4_service_next(file: *mut M4NdbFile) -> *mut M4Servent {
    let mut record = M4ServiceRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        port: 0,
        protocol: core::ptr::null_mut(),
    };
    loop {
        let line = m4_ndb_next_line(file);
        if line.is_null() {
            return core::ptr::null_mut();
        }
        if m4_service_record(line, &mut record) {
            return m4_service_install(&record);
        }
    }
}

unsafe fn m4_service_lookup(
    name: *const c_char,
    port: Option<u16>,
    protocol: *const c_char,
) -> *mut M4Servent {
    let file = core::ptr::addr_of_mut!(M4_SERVICE_DIRECT);
    m4_ndb_dispose(file);
    if !m4_ndb_load(b"/etc/services\0".as_ptr(), file) {
        return core::ptr::null_mut();
    }
    let mut record = M4ServiceRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        port: 0,
        protocol: core::ptr::null_mut(),
    };
    let mut found = false;
    loop {
        let line = m4_ndb_next_line(file);
        if line.is_null() {
            break;
        }
        if m4_service_record(line, &mut record)
            && m4_service_matches(&record, name, port, protocol)
        {
            found = true;
            break;
        }
    }
    let result = if found { m4_service_install(&record) } else { core::ptr::null_mut() };
    if !found {
        m4_ndb_dispose(file);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn getservbyname(
    name: *const c_char,
    protocol: *const c_char,
) -> *mut M4Servent {
    if name.is_null() {
        ERRNO = EINVAL_VAL;
        return core::ptr::null_mut();
    }
    m4_service_lookup(name, None, protocol)
}

#[no_mangle]
pub unsafe extern "C" fn getservbyport(
    port: c_int,
    protocol: *const c_char,
) -> *mut M4Servent {
    m4_service_lookup(core::ptr::null(), Some(port as u16), protocol)
}

unsafe fn m4_service_copy_reentrant(
    source: *const M4ServiceRecord,
    destination: *mut M4Servent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Servent,
) -> c_int {
    if source.is_null() || destination.is_null() || result.is_null() {
        if !result.is_null() {
            *result = core::ptr::null_mut();
        }
        return EINVAL_VAL;
    }
    *result = core::ptr::null_mut();
    let pointer_size = core::mem::size_of::<*mut c_char>();
    let alias_bytes = match (*source).alias_count.checked_add(1).and_then(|v| v.checked_mul(pointer_size)) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let base = buffer as usize;
    let aligned = match m4_ndb_align(base, pointer_size) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let pointer_offset = aligned.checked_sub(base).unwrap_or(0);
    if buffer.is_null() || pointer_offset.checked_add(alias_bytes).unwrap_or(usize::MAX) > buffer_size {
        return ERANGE_VAL;
    }
    let aliases = (buffer as *mut u8).add(pointer_offset) as *mut *mut c_char;
    let mut cursor = aliases.add((*source).alias_count + 1) as *mut u8;
    let end = (buffer as *mut u8).add(buffer_size);
    let name = match m4_ndb_copy_string((*source).name, cursor, end) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    cursor = cursor.add(strlen((*source).name) + 1);
    let protocol = match m4_ndb_copy_string((*source).protocol, cursor, end) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    cursor = cursor.add(strlen((*source).protocol) + 1);
    let mut index = 0;
    while index < (*source).alias_count {
        let alias = match m4_ndb_copy_string((*source).aliases[index], cursor, end) {
            Some(value) => value,
            None => return ERANGE_VAL,
        };
        cursor = cursor.add(strlen((*source).aliases[index]) + 1);
        *aliases.add(index) = alias;
        index += 1;
    }
    *aliases.add((*source).alias_count) = core::ptr::null_mut();
    (*destination).s_name = name;
    (*destination).s_aliases = aliases;
    (*destination).s_port = (*source).port as c_int;
    (*destination).s_proto = protocol;
    *result = destination;
    0
}

unsafe fn m4_service_reentrant(
    name: *const c_char,
    port: Option<u16>,
    protocol: *const c_char,
    destination: *mut M4Servent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Servent,
) -> c_int {
    if result.is_null() || destination.is_null() || (name.is_null() && port.is_none()) {
        if !result.is_null() {
            *result = core::ptr::null_mut();
        }
        ERRNO = EINVAL_VAL;
        return EINVAL_VAL;
    }
    *result = core::ptr::null_mut();
    let mut file = M4_NDB_EMPTY_FILE;
    if !m4_ndb_load(b"/etc/services\0".as_ptr(), &mut file) {
        return if ERRNO == 0 { ENOENT_VAL } else { ERRNO };
    }
    let mut record = M4ServiceRecord {
        name: core::ptr::null_mut(),
        aliases: [core::ptr::null_mut(); M4_NDB_MAX_ALIASES],
        alias_count: 0,
        port: 0,
        protocol: core::ptr::null_mut(),
    };
    let mut found = false;
    loop {
        let line = m4_ndb_next_line(&mut file);
        if line.is_null() {
            break;
        }
        if m4_service_record(line, &mut record)
            && m4_service_matches(&record, name, port, protocol)
        {
            found = true;
            break;
        }
    }
    let code = if found {
        m4_service_copy_reentrant(&record, destination, buffer, buffer_size, result)
    } else {
        // The reentrant netdb APIs reserve nonzero returns for an operational
        // failure. A completed lookup with no matching service is represented
        // by success and a NULL result pointer, just like the host variants.
        0
    };
    free(file.data as *mut c_void);
    if code != 0 {
        ERRNO = code;
    }
    code
}

#[no_mangle]
pub unsafe extern "C" fn getservbyname_r(
    name: *const c_char,
    protocol: *const c_char,
    destination: *mut M4Servent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Servent,
) -> c_int {
    m4_service_reentrant(name, None, protocol, destination, buffer, buffer_size, result)
}

#[no_mangle]
pub unsafe extern "C" fn getservbyport_r(
    port: c_int,
    protocol: *const c_char,
    destination: *mut M4Servent,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut M4Servent,
) -> c_int {
    m4_service_reentrant(core::ptr::null(), Some(port as u16), protocol, destination, buffer, buffer_size, result)
}

#[no_mangle]
pub unsafe extern "C" fn getservent() -> *mut M4Servent {
    let file = core::ptr::addr_of_mut!(M4_SERVICE_ENUM);
    if (*file).data.is_null() {
        setservent(0);
        if (*file).data.is_null() {
            return core::ptr::null_mut();
        }
    }
    m4_service_next(file)
}

#[no_mangle]
pub unsafe extern "C" fn setservent(stayopen: c_int) {
    let file = core::ptr::addr_of_mut!(M4_SERVICE_ENUM);
    if (*file).data.is_null() {
        if !m4_ndb_load(b"/etc/services\0".as_ptr(), file) {
            return;
        }
    } else {
        (*file).position = 0;
    }
    (*file).stayopen = stayopen != 0;
}

#[no_mangle]
pub unsafe extern "C" fn endservent() {
    m4_ndb_dispose(core::ptr::addr_of_mut!(M4_SERVICE_ENUM));
}
