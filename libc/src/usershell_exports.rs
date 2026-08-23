// login-shell database access.  musl exposes a process-global cursor over
// the administrator-maintained /etc/shells file; setusershell rewinds that
// cursor and endusershell releases it so a later query observes a replacement
// file rather than retaining an invented cache.

const CABI_USERSHELL_LINE_MAX: usize = 4096;

static mut CABI_USERSHELL_FILE: *mut FILE = core::ptr::null_mut();
static mut CABI_USERSHELL_LINE: [c_char; CABI_USERSHELL_LINE_MAX] = [0; CABI_USERSHELL_LINE_MAX];

#[inline]
unsafe fn cabi_usershell_space(byte: c_char) -> bool {
    matches!(byte as u8, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
}

#[no_mangle]
pub unsafe extern "C" fn getusershell() -> *mut c_char {
    let file_slot = core::ptr::addr_of_mut!(CABI_USERSHELL_FILE);
    if (*file_slot).is_null() {
        *file_slot = fopen(b"/etc/shells\0".as_ptr() as *const c_char, b"r\0".as_ptr() as *const c_char);
        if (*file_slot).is_null() {
            return core::ptr::null_mut();
        }
    }

    let line = core::ptr::addr_of_mut!(CABI_USERSHELL_LINE).cast::<c_char>();
    while !fgets(line, CABI_USERSHELL_LINE_MAX as c_int, *file_slot).is_null() {
        let mut shell = line;
        while cabi_usershell_space(*shell) {
            shell = shell.add(1);
        }
        if *shell == 0 || *shell as u8 == b'#' {
            continue;
        }

        let mut end = shell;
        while *end != 0 && *end as u8 != b'\n' {
            end = end.add(1);
        }
        *end = 0;
        return shell;
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn setusershell() {
    let file = *core::ptr::addr_of_mut!(CABI_USERSHELL_FILE);
    if !file.is_null() {
        rewind(file);
    }
}

#[no_mangle]
pub unsafe extern "C" fn endusershell() {
    let file_slot = core::ptr::addr_of_mut!(CABI_USERSHELL_FILE);
    if !(*file_slot).is_null() {
        let _ = fclose(*file_slot);
        *file_slot = core::ptr::null_mut();
    }
}

// passwd database access.  Keep the source file separate from the shell
// cursor above only conceptually: this file is already part of lib.rs's
// include set, so the passwd ABI can be added without changing that boundary.
// Records come from the administrator-maintained /etc/passwd file; malformed
// lines are skipped as musl does, while I/O and caller-buffer failures retain
// their real error codes.

#[repr(C)]
pub struct CabiPasswd {
    pub pw_name: *mut c_char,
    pub pw_passwd: *mut c_char,
    pub pw_uid: c_uint,
    pub pw_gid: c_uint,
    pub pw_gecos: *mut c_char,
    pub pw_dir: *mut c_char,
    pub pw_shell: *mut c_char,
}

static mut CABI_PASSWD_FILE: *mut FILE = core::ptr::null_mut();
static mut CABI_PASSWD_LINE: *mut c_char = core::ptr::null_mut();
static mut CABI_PASSWD_LINE_SIZE: usize = 0;
static mut CABI_PASSWD_RESULT: CabiPasswd = CabiPasswd {
    pw_name: core::ptr::null_mut(),
    pw_passwd: core::ptr::null_mut(),
    pw_uid: 0,
    pw_gid: 0,
    pw_gecos: core::ptr::null_mut(),
    pw_dir: core::ptr::null_mut(),
    pw_shell: core::ptr::null_mut(),
};

static mut CABI_FGETPWENT_LINE: *mut c_char = core::ptr::null_mut();
static mut CABI_FGETPWENT_LINE_SIZE: usize = 0;
static mut CABI_FGETPWENT_RESULT: CabiPasswd = CabiPasswd {
    pw_name: core::ptr::null_mut(),
    pw_passwd: core::ptr::null_mut(),
    pw_uid: 0,
    pw_gid: 0,
    pw_gecos: core::ptr::null_mut(),
    pw_dir: core::ptr::null_mut(),
    pw_shell: core::ptr::null_mut(),
};

#[inline]
unsafe fn passwd_parse_uint(field: *const c_char) -> Option<c_uint> {
    if field.is_null() || *field == 0 {
        return None;
    }
    let mut cursor = field;
    let mut value = 0u64;
    loop {
        let byte = *cursor as u8;
        if byte == 0 {
            break;
        }
        if byte < b'0' || byte > b'9' {
            return None;
        }
        let digit = (byte - b'0') as u64;
        if value > (c_uint::MAX as u64 - digit) / 10 {
            return None;
        }
        value = value * 10 + digit;
        cursor = cursor.add(1);
    }
    Some(value as c_uint)
}

// Parse in place so all seven public pointers can refer to one line buffer.
// The six separators are replaced with NULs; the final field already ends at
// getline's terminator after an optional trailing newline is removed.
unsafe fn passwd_parse_line(line: *mut c_char, length: usize, pw: *mut CabiPasswd) -> bool {
    if line.is_null() || pw.is_null() || length == 0 {
        return false;
    }
    let mut content_len = length;
    if content_len > 0 && *line.add(content_len - 1) as u8 == b'\n' {
        content_len -= 1;
        *line.add(content_len) = 0;
    }

    let mut fields = [core::ptr::null_mut(); 7];
    let mut cursor = line;
    let end = line.add(content_len);
    let mut field_index = 0;
    while field_index < 6 {
        let mut separator = cursor;
        while separator < end && *separator as u8 != b':' {
            separator = separator.add(1);
        }
        if separator == end {
            return false;
        }
        *separator = 0;
        fields[field_index] = cursor;
        cursor = separator.add(1);
        field_index += 1;
    }
    fields[6] = cursor;

    let uid = match passwd_parse_uint(fields[2]) {
        Some(value) => value,
        None => return false,
    };
    let gid = match passwd_parse_uint(fields[3]) {
        Some(value) => value,
        None => return false,
    };
    (*pw).pw_name = fields[0];
    (*pw).pw_passwd = fields[1];
    (*pw).pw_uid = uid;
    (*pw).pw_gid = gid;
    (*pw).pw_gecos = fields[4];
    (*pw).pw_dir = fields[5];
    (*pw).pw_shell = fields[6];
    true
}

// Return 1 for a parsed record, 0 for EOF, and -1 for a stream error.  EOF
// releases the dynamic line while leaving the FILE open, matching getpwent's
// cursor lifecycle: subsequent calls remain at EOF until setpwent/endpwent.
unsafe fn passwd_next(
    file: *mut FILE,
    line: *mut *mut c_char,
    line_size: *mut usize,
    pw: *mut CabiPasswd,
) -> c_int {
    loop {
        let length = getline(line, line_size, file);
        if length < 0 {
            if ferror(file) != 0 {
                if ERRNO == 0 {
                    ERRNO = EIO_VAL;
                }
                return -1;
            }
            free(*line as *mut c_void);
            *line = core::ptr::null_mut();
            *line_size = 0;
            return 0;
        }
        if passwd_parse_line(*line, length as usize, pw) {
            return 1;
        }
    }
}

unsafe fn passwd_name_matches(left: *const c_char, right: *const c_char) -> bool {
    !left.is_null() && !right.is_null() && strcmp(left as *const u8, right as *const u8) == 0
}

unsafe fn passwd_copy_result(
    source: *const CabiPasswd,
    destination_pw: *mut CabiPasswd,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiPasswd,
) -> c_int {
    *result = core::ptr::null_mut();
    if buffer.is_null() {
        return ERANGE_VAL;
    }
    let fields = [
        (*source).pw_name,
        (*source).pw_passwd,
        (*source).pw_gecos,
        (*source).pw_dir,
        (*source).pw_shell,
    ];
    let mut required = 0usize;
    let mut index = 0usize;
    while index < fields.len() {
        if fields[index].is_null() {
            return EIO_VAL;
        }
        required = match required
            .checked_add(strlen(fields[index]))
            .and_then(|value| value.checked_add(1))
        {
            Some(value) => value,
            None => return ERANGE_VAL,
        };
        index += 1;
    }
    if required > buffer_size {
        return ERANGE_VAL;
    }
    let mut destination = buffer;
    (*destination_pw).pw_name = destination;
    let name_len = strlen((*source).pw_name) + 1;
    core::ptr::copy_nonoverlapping((*source).pw_name as *const u8, destination as *mut u8, name_len);
    destination = destination.add(name_len);
    (*destination_pw).pw_passwd = destination;
    let passwd_len = strlen((*source).pw_passwd) + 1;
    core::ptr::copy_nonoverlapping((*source).pw_passwd as *const u8, destination as *mut u8, passwd_len);
    destination = destination.add(passwd_len);
    (*destination_pw).pw_gecos = destination;
    let gecos_len = strlen((*source).pw_gecos) + 1;
    core::ptr::copy_nonoverlapping((*source).pw_gecos as *const u8, destination as *mut u8, gecos_len);
    destination = destination.add(gecos_len);
    (*destination_pw).pw_dir = destination;
    let dir_len = strlen((*source).pw_dir) + 1;
    core::ptr::copy_nonoverlapping((*source).pw_dir as *const u8, destination as *mut u8, dir_len);
    destination = destination.add(dir_len);
    (*destination_pw).pw_shell = destination;
    let shell_len = strlen((*source).pw_shell) + 1;
    core::ptr::copy_nonoverlapping((*source).pw_shell as *const u8, destination as *mut u8, shell_len);
    (*destination_pw).pw_uid = (*source).pw_uid;
    (*destination_pw).pw_gid = (*source).pw_gid;
    *result = destination_pw;
    0
}

unsafe fn passwd_open() -> *mut FILE {
    fopen(b"/etc/passwd\0".as_ptr() as *const c_char, b"rbe\0".as_ptr() as *const c_char)
}

unsafe fn passwd_scan(
    name: *const c_char,
    uid: Option<c_uint>,
    file: *mut FILE,
    line: *mut *mut c_char,
    line_size: *mut usize,
    pw: *mut CabiPasswd,
) -> c_int {
    loop {
        let status = passwd_next(file, line, line_size, pw);
        if status <= 0 {
            return status;
        }
        if let Some(wanted_uid) = uid {
            if (*pw).pw_uid == wanted_uid {
                return 1;
            }
        } else if passwd_name_matches(name, (*pw).pw_name) {
            return 1;
        }
    }
}

unsafe fn passwd_reentrant(
    name: *const c_char,
    uid: Option<c_uint>,
    pw: *mut CabiPasswd,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiPasswd,
) -> c_int {
    // A zero-sized caller buffer is a valid way to probe the required size;
    // let a matching entry report ERANGE rather than rejecting its pointer.
    if pw.is_null()
        || result.is_null()
        || (buffer.is_null() && buffer_size != 0)
        || (uid.is_none() && name.is_null())
    {
        if !result.is_null() {
            *result = core::ptr::null_mut();
        }
        ERRNO = EINVAL;
        return EINVAL;
    }
    *result = core::ptr::null_mut();
    let file = passwd_open();
    if file.is_null() {
        return ERRNO;
    }
    let mut line = core::ptr::null_mut();
    let mut line_size = 0usize;
    let mut parsed = CabiPasswd {
        pw_name: core::ptr::null_mut(),
        pw_passwd: core::ptr::null_mut(),
        pw_uid: 0,
        pw_gid: 0,
        pw_gecos: core::ptr::null_mut(),
        pw_dir: core::ptr::null_mut(),
        pw_shell: core::ptr::null_mut(),
    };
    let status = passwd_scan(name, uid, file, &mut line, &mut line_size, &mut parsed);
    let result_code = if status > 0 {
        passwd_copy_result(&parsed, pw, buffer, buffer_size, result)
    } else if status < 0 {
        if ERRNO == 0 { EIO_VAL } else { ERRNO }
    } else {
        0
    };
    let _ = fclose(file);
    free(line as *mut c_void);
    if result_code != 0 {
        ERRNO = result_code;
    }
    result_code
}

#[no_mangle]
pub unsafe extern "C" fn getpwnam_r(
    name: *const c_char,
    pw: *mut CabiPasswd,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiPasswd,
) -> c_int {
    passwd_reentrant(name, None, pw, buffer, buffer_size, result)
}

#[no_mangle]
pub unsafe extern "C" fn getpwuid_r(
    uid: c_uint,
    pw: *mut CabiPasswd,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiPasswd,
) -> c_int {
    passwd_reentrant(core::ptr::null(), Some(uid), pw, buffer, buffer_size, result)
}

unsafe fn passwd_global_lookup(name: *const c_char, uid: Option<c_uint>) -> *mut CabiPasswd {
    if uid.is_none() && name.is_null() {
        ERRNO = EINVAL;
        return core::ptr::null_mut();
    }
    let file = passwd_open();
    if file.is_null() {
        return core::ptr::null_mut();
    }
    let line = core::ptr::addr_of_mut!(CABI_PASSWD_LINE);
    let line_size = core::ptr::addr_of_mut!(CABI_PASSWD_LINE_SIZE);
    let result = core::ptr::addr_of_mut!(CABI_PASSWD_RESULT);
    let status = passwd_scan(name, uid, file, line, line_size, result);
    let _ = fclose(file);
    if status > 0 {
        result
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut CabiPasswd {
    passwd_global_lookup(name, None)
}

#[no_mangle]
pub unsafe extern "C" fn getpwuid(uid: c_uint) -> *mut CabiPasswd {
    passwd_global_lookup(core::ptr::null(), Some(uid))
}

#[no_mangle]
pub unsafe extern "C" fn setpwent() {
    let file = core::ptr::addr_of_mut!(CABI_PASSWD_FILE);
    if !(*file).is_null() {
        let _ = fclose(*file);
        *file = core::ptr::null_mut();
    }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn endpwent() {
    setpwent();
}

#[no_mangle]
pub unsafe extern "C" fn getpwent() -> *mut CabiPasswd {
    let file = core::ptr::addr_of_mut!(CABI_PASSWD_FILE);
    if (*file).is_null() {
        *file = passwd_open();
        if (*file).is_null() {
            return core::ptr::null_mut();
        }
    }
    let status = passwd_next(
        *file,
        core::ptr::addr_of_mut!(CABI_PASSWD_LINE),
        core::ptr::addr_of_mut!(CABI_PASSWD_LINE_SIZE),
        core::ptr::addr_of_mut!(CABI_PASSWD_RESULT),
    );
    if status > 0 {
        core::ptr::addr_of_mut!(CABI_PASSWD_RESULT)
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn fgetpwent(file: *mut FILE) -> *mut CabiPasswd {
    if file.is_null() {
        ERRNO = EINVAL;
        return core::ptr::null_mut();
    }
    let status = passwd_next(
        file,
        core::ptr::addr_of_mut!(CABI_FGETPWENT_LINE),
        core::ptr::addr_of_mut!(CABI_FGETPWENT_LINE_SIZE),
        core::ptr::addr_of_mut!(CABI_FGETPWENT_RESULT),
    );
    if status > 0 {
        core::ptr::addr_of_mut!(CABI_FGETPWENT_RESULT)
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn putpwent(pw: *const CabiPasswd, file: *mut FILE) -> c_int {
    if pw.is_null()
        || file.is_null()
        || (*pw).pw_name.is_null()
        || (*pw).pw_passwd.is_null()
        || (*pw).pw_gecos.is_null()
        || (*pw).pw_dir.is_null()
        || (*pw).pw_shell.is_null()
    {
        ERRNO = EINVAL;
        return -1;
    }
    let written = fprintf(
        file,
        b"%s:%s:%u:%u:%s:%s:%s\n\0".as_ptr() as *const c_char,
        (*pw).pw_name,
        (*pw).pw_passwd,
        (*pw).pw_uid,
        (*pw).pw_gid,
        (*pw).pw_gecos,
        (*pw).pw_dir,
        (*pw).pw_shell,
    );
    if written < 0 { -1 } else { 0 }
}

// group database access.  Keep all group records backed by the
// administrator-maintained /etc/group file.  Direct and enumeration results
// own their process-global line/member storage; reentrant results copy both
// the strings and the member-pointer vector into the caller's buffer.

#[repr(C)]
pub struct CabiGroup {
    pub gr_name: *mut c_char,
    pub gr_passwd: *mut c_char,
    pub gr_gid: c_uint,
    pub gr_mem: *mut *mut c_char,
}

static mut CABI_GROUP_FILE: *mut FILE = core::ptr::null_mut();
static mut CABI_GROUP_LINE: *mut c_char = core::ptr::null_mut();
static mut CABI_GROUP_LINE_SIZE: usize = 0;
static mut CABI_GROUP_MEMBERS: *mut *mut c_char = core::ptr::null_mut();
static mut CABI_GROUP_RESULT: CabiGroup = CabiGroup {
    gr_name: core::ptr::null_mut(),
    gr_passwd: core::ptr::null_mut(),
    gr_gid: 0,
    gr_mem: core::ptr::null_mut(),
};

static mut CABI_FGETGRENT_LINE: *mut c_char = core::ptr::null_mut();
static mut CABI_FGETGRENT_LINE_SIZE: usize = 0;
static mut CABI_FGETGRENT_MEMBERS: *mut *mut c_char = core::ptr::null_mut();
static mut CABI_FGETGRENT_RESULT: CabiGroup = CabiGroup {
    gr_name: core::ptr::null_mut(),
    gr_passwd: core::ptr::null_mut(),
    gr_gid: 0,
    gr_mem: core::ptr::null_mut(),
};

unsafe fn group_release_members(slot: *mut *mut *mut c_char) {
    if !slot.is_null() && !(*slot).is_null() {
        free(*slot as *mut c_void);
        *slot = core::ptr::null_mut();
    }
}

// Return 1 for a valid record, 0 for a malformed record, and -1 for a local
// allocation failure.  The member list is split in place and represented by
// one separately allocated, NULL-terminated pointer vector.
unsafe fn group_parse_line(
    line: *mut c_char,
    length: usize,
    group: *mut CabiGroup,
    members_out: *mut *mut *mut c_char,
) -> c_int {
    if line.is_null() || group.is_null() || members_out.is_null() || length == 0 {
        return 0;
    }
    let mut content_len = length;
    if content_len > 0 && *line.add(content_len - 1) as u8 == b'\n' {
        content_len -= 1;
        *line.add(content_len) = 0;
    }

    let mut fields = [core::ptr::null_mut(); 4];
    let mut cursor = line;
    let end = line.add(content_len);
    let mut field_index = 0usize;
    while field_index < 3 {
        let mut separator = cursor;
        while separator < end && *separator as u8 != b':' {
            separator = separator.add(1);
        }
        if separator == end {
            return 0;
        }
        *separator = 0;
        fields[field_index] = cursor;
        cursor = separator.add(1);
        field_index += 1;
    }
    fields[3] = cursor;

    let gid = match passwd_parse_uint(fields[2]) {
        Some(value) => value,
        None => return 0,
    };

    let mut member_count = 0usize;
    let mut scan = fields[3];
    while scan < end {
        let member_start = scan;
        while scan < end && *scan as u8 != b',' {
            scan = scan.add(1);
        }
        if scan != member_start {
            member_count = match member_count.checked_add(1) {
                Some(value) => value,
                None => {
                    ERRNO = EOVERFLOW;
                    return -1;
                }
            };
        }
        if scan == end {
            break;
        }
        scan = scan.add(1);
    }

    let member_slots = match member_count.checked_add(1) {
        Some(value) => value,
        None => {
            ERRNO = EOVERFLOW;
            return -1;
        }
    };
    let member_bytes = match member_slots.checked_mul(core::mem::size_of::<*mut c_char>()) {
        Some(value) => value,
        None => {
            ERRNO = EOVERFLOW;
            return -1;
        }
    };
    let member_vector = malloc(member_bytes) as *mut *mut c_char;
    if member_vector.is_null() {
        ERRNO = ENOMEM;
        return -1;
    }

    let mut member_index = 0usize;
    let mut scan = fields[3];
    while scan < end {
        let member_start = scan;
        while scan < end && *scan as u8 != b',' {
            scan = scan.add(1);
        }
        if scan != member_start {
            *member_vector.add(member_index) = member_start;
            member_index += 1;
        }
        if scan == end {
            break;
        }
        *scan = 0;
        scan = scan.add(1);
    }
    *member_vector.add(member_count) = core::ptr::null_mut();

    (*group).gr_name = fields[0];
    (*group).gr_passwd = fields[1];
    (*group).gr_gid = gid;
    (*group).gr_mem = member_vector;
    *members_out = member_vector;
    1
}

unsafe fn group_next(
    file: *mut FILE,
    line: *mut *mut c_char,
    line_size: *mut usize,
    members: *mut *mut *mut c_char,
    group: *mut CabiGroup,
) -> c_int {
    loop {
        let length = getline(line, line_size, file);
        if length < 0 {
            group_release_members(members);
            if ferror(file) != 0 {
                if ERRNO == 0 {
                    ERRNO = EIO_VAL;
                }
                return -1;
            }
            free(*line as *mut c_void);
            *line = core::ptr::null_mut();
            *line_size = 0;
            return 0;
        }
        group_release_members(members);
        let status = group_parse_line(*line, length as usize, group, members);
        if status != 0 {
            return status;
        }
    }
}

unsafe fn group_name_matches(left: *const c_char, right: *const c_char) -> bool {
    !left.is_null() && !right.is_null() && strcmp(left as *const u8, right as *const u8) == 0
}

unsafe fn group_scan(
    name: *const c_char,
    gid: Option<c_uint>,
    file: *mut FILE,
    line: *mut *mut c_char,
    line_size: *mut usize,
    members: *mut *mut *mut c_char,
    group: *mut CabiGroup,
) -> c_int {
    loop {
        let status = group_next(file, line, line_size, members, group);
        if status <= 0 {
            return status;
        }
        if let Some(wanted_gid) = gid {
            if (*group).gr_gid == wanted_gid {
                return 1;
            }
        } else if group_name_matches(name, (*group).gr_name) {
            return 1;
        }
    }
}

unsafe fn group_copy_result(
    source: *const CabiGroup,
    destination: *mut CabiGroup,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiGroup,
) -> c_int {
    *result = core::ptr::null_mut();
    if buffer.is_null() {
        return ERANGE_VAL;
    }
    let mut member_count = 0usize;
    let source_members = (*source).gr_mem;
    if source_members.is_null() {
        return EIO_VAL;
    }
    while !(*source_members.add(member_count)).is_null() {
        member_count = match member_count.checked_add(1) {
            Some(value) => value,
            None => return ERANGE_VAL,
        };
    }
    let name_len = match strlen((*source).gr_name).checked_add(1) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let passwd_len = match strlen((*source).gr_passwd).checked_add(1) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let mut string_bytes = match name_len.checked_add(passwd_len) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let mut member_index = 0usize;
    while member_index < member_count {
        let member_len = match strlen(*source_members.add(member_index)).checked_add(1) {
            Some(value) => value,
            None => return ERANGE_VAL,
        };
        string_bytes = match string_bytes.checked_add(member_len) {
            Some(value) => value,
            None => return ERANGE_VAL,
        };
        member_index += 1;
    }
    let alignment = core::mem::align_of::<*mut c_char>();
    let base = buffer as usize;
    let aligned = match base.checked_add(alignment - 1) {
        Some(value) => value & !(alignment - 1),
        None => return ERANGE_VAL,
    };
    let padding = aligned - base;
    let member_bytes = match member_count
        .checked_add(1)
        .and_then(|value| value.checked_mul(core::mem::size_of::<*mut c_char>()))
    {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let string_offset = match padding.checked_add(member_bytes) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    let required = match string_offset.checked_add(string_bytes) {
        Some(value) => value,
        None => return ERANGE_VAL,
    };
    if required > buffer_size {
        return ERANGE_VAL;
    }

    let destination_members = buffer.add(padding) as *mut *mut c_char;
    let mut destination_line = buffer.add(string_offset);
    (*destination).gr_name = destination_line;
    core::ptr::copy_nonoverlapping(
        (*source).gr_name as *const u8,
        destination_line as *mut u8,
        name_len,
    );
    destination_line = destination_line.add(name_len);
    (*destination).gr_passwd = destination_line;
    core::ptr::copy_nonoverlapping(
        (*source).gr_passwd as *const u8,
        destination_line as *mut u8,
        passwd_len,
    );
    destination_line = destination_line.add(passwd_len);
    (*destination).gr_gid = (*source).gr_gid;
    member_index = 0;
    while member_index < member_count {
        *destination_members.add(member_index) = destination_line;
        let member_len = strlen(*source_members.add(member_index)) + 1;
        core::ptr::copy_nonoverlapping(
            *source_members.add(member_index) as *const u8,
            destination_line as *mut u8,
            member_len,
        );
        destination_line = destination_line.add(member_len);
        member_index += 1;
    }
    *destination_members.add(member_count) = core::ptr::null_mut();
    (*destination).gr_mem = destination_members;
    *result = destination;
    0
}

unsafe fn group_open() -> *mut FILE {
    fopen(b"/etc/group\0".as_ptr() as *const c_char, b"rbe\0".as_ptr() as *const c_char)
}

unsafe fn group_reentrant(
    name: *const c_char,
    gid: Option<c_uint>,
    group: *mut CabiGroup,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiGroup,
) -> c_int {
    if group.is_null()
        || result.is_null()
        || (buffer.is_null() && buffer_size != 0)
        || (gid.is_none() && name.is_null())
    {
        if !result.is_null() {
            *result = core::ptr::null_mut();
        }
        ERRNO = EINVAL;
        return EINVAL;
    }
    *result = core::ptr::null_mut();
    let file = group_open();
    if file.is_null() {
        return ERRNO;
    }
    let mut line = core::ptr::null_mut();
    let mut line_size = 0usize;
    let mut members = core::ptr::null_mut();
    let mut parsed = CabiGroup {
        gr_name: core::ptr::null_mut(),
        gr_passwd: core::ptr::null_mut(),
        gr_gid: 0,
        gr_mem: core::ptr::null_mut(),
    };
    ERRNO = 0;
    let status = group_scan(
        name,
        gid,
        file,
        &mut line,
        &mut line_size,
        &mut members,
        &mut parsed,
    );
    let result_code = if status > 0 {
        group_copy_result(
            &parsed,
            group,
            buffer,
            buffer_size,
            result,
        )
    } else if status < 0 {
        if ERRNO == 0 { EIO_VAL } else { ERRNO }
    } else {
        0
    };
    let _ = fclose(file);
    free(line as *mut c_void);
    group_release_members(&mut members);
    if result_code != 0 {
        ERRNO = result_code;
    }
    result_code
}

#[no_mangle]
pub unsafe extern "C" fn getgrnam_r(
    name: *const c_char,
    group: *mut CabiGroup,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiGroup,
) -> c_int {
    group_reentrant(name, None, group, buffer, buffer_size, result)
}

#[no_mangle]
pub unsafe extern "C" fn getgrgid_r(
    gid: c_uint,
    group: *mut CabiGroup,
    buffer: *mut c_char,
    buffer_size: usize,
    result: *mut *mut CabiGroup,
) -> c_int {
    group_reentrant(core::ptr::null(), Some(gid), group, buffer, buffer_size, result)
}

unsafe fn group_global_lookup(name: *const c_char, gid: Option<c_uint>) -> *mut CabiGroup {
    if gid.is_none() && name.is_null() {
        ERRNO = EINVAL;
        return core::ptr::null_mut();
    }
    let file = group_open();
    if file.is_null() {
        return core::ptr::null_mut();
    }
    let status = group_scan(
        name,
        gid,
        file,
        core::ptr::addr_of_mut!(CABI_GROUP_LINE),
        core::ptr::addr_of_mut!(CABI_GROUP_LINE_SIZE),
        core::ptr::addr_of_mut!(CABI_GROUP_MEMBERS),
        core::ptr::addr_of_mut!(CABI_GROUP_RESULT),
    );
    let _ = fclose(file);
    if status > 0 {
        core::ptr::addr_of_mut!(CABI_GROUP_RESULT)
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut CabiGroup {
    group_global_lookup(name, None)
}

#[no_mangle]
pub unsafe extern "C" fn getgrgid(gid: c_uint) -> *mut CabiGroup {
    group_global_lookup(core::ptr::null(), Some(gid))
}

#[no_mangle]
pub unsafe extern "C" fn setgrent() {
    let file = core::ptr::addr_of_mut!(CABI_GROUP_FILE);
    if !(*file).is_null() {
        let _ = fclose(*file);
        *file = core::ptr::null_mut();
    }
    group_release_members(core::ptr::addr_of_mut!(CABI_GROUP_MEMBERS));
    free(CABI_GROUP_LINE as *mut c_void);
    CABI_GROUP_LINE = core::ptr::null_mut();
    CABI_GROUP_LINE_SIZE = 0;
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn endgrent() {
    setgrent();
}

#[no_mangle]
pub unsafe extern "C" fn getgrent() -> *mut CabiGroup {
    let file = core::ptr::addr_of_mut!(CABI_GROUP_FILE);
    if (*file).is_null() {
        *file = group_open();
        if (*file).is_null() {
            return core::ptr::null_mut();
        }
    }
    let status = group_next(
        *file,
        core::ptr::addr_of_mut!(CABI_GROUP_LINE),
        core::ptr::addr_of_mut!(CABI_GROUP_LINE_SIZE),
        core::ptr::addr_of_mut!(CABI_GROUP_MEMBERS),
        core::ptr::addr_of_mut!(CABI_GROUP_RESULT),
    );
    if status > 0 {
        core::ptr::addr_of_mut!(CABI_GROUP_RESULT)
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn fgetgrent(file: *mut FILE) -> *mut CabiGroup {
    if file.is_null() {
        ERRNO = EINVAL;
        return core::ptr::null_mut();
    }
    let status = group_next(
        file,
        core::ptr::addr_of_mut!(CABI_FGETGRENT_LINE),
        core::ptr::addr_of_mut!(CABI_FGETGRENT_LINE_SIZE),
        core::ptr::addr_of_mut!(CABI_FGETGRENT_MEMBERS),
        core::ptr::addr_of_mut!(CABI_FGETGRENT_RESULT),
    );
    if status > 0 {
        core::ptr::addr_of_mut!(CABI_FGETGRENT_RESULT)
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn putgrent(group: *const CabiGroup, file: *mut FILE) -> c_int {
    if group.is_null()
        || file.is_null()
        || (*group).gr_name.is_null()
        || (*group).gr_passwd.is_null()
        || (*group).gr_mem.is_null()
    {
        ERRNO = EINVAL;
        return -1;
    }
    if fprintf(
        file,
        b"%s:%s:%u:\0".as_ptr() as *const c_char,
        (*group).gr_name,
        (*group).gr_passwd,
        (*group).gr_gid,
    ) < 0 {
        return -1;
    }
    let mut index = 0usize;
    while !(*(*group).gr_mem.add(index)).is_null() {
        if index != 0 && fputc(b',' as c_int, file) < 0 {
            return -1;
        }
        if fputs(*(*group).gr_mem.add(index), file) < 0 {
            return -1;
        }
        index += 1;
    }
    if fputc(b'\n' as c_int, file) < 0 {
        return -1;
    }
    0
}

unsafe fn group_seen_add(
    seen: *mut *mut c_uint,
    seen_count: *mut usize,
    seen_capacity: *mut usize,
    gid: c_uint,
) -> c_int {
    let mut index = 0usize;
    while index < *seen_count {
        if *(*seen).add(index) == gid {
            return 0;
        }
        index += 1;
    }
    if *seen_count == *seen_capacity {
        let new_capacity = if *seen_capacity == 0 {
            8usize
        } else {
            match (*seen_capacity).checked_mul(2) {
                Some(value) => value,
                None => {
                    ERRNO = EOVERFLOW;
                    return -1;
                }
            }
        };
        let bytes = match new_capacity.checked_mul(core::mem::size_of::<c_uint>()) {
            Some(value) => value,
            None => {
                ERRNO = EOVERFLOW;
                return -1;
            }
        };
        let replacement = realloc(*seen as *mut c_void, bytes) as *mut c_uint;
        if replacement.is_null() {
            ERRNO = ENOMEM;
            return -1;
        }
        *seen = replacement;
        *seen_capacity = new_capacity;
    }
    *(*seen).add(*seen_count) = gid;
    *seen_count += 1;
    1
}

#[no_mangle]
pub unsafe extern "C" fn getgrouplist(
    user: *const c_char,
    group: c_uint,
    groups: *mut c_uint,
    ngroups: *mut c_int,
) -> c_int {
    if user.is_null() || ngroups.is_null() || *ngroups < 0 || (*ngroups > 0 && groups.is_null()) {
        ERRNO = EINVAL;
        return -1;
    }
    ERRNO = 0;
    let capacity = *ngroups as usize;
    let mut seen: *mut c_uint = core::ptr::null_mut();
    let mut seen_count = 0usize;
    let mut seen_capacity = 0usize;
    if group_seen_add(&mut seen, &mut seen_count, &mut seen_capacity, group) < 0 {
        return -1;
    }
    if capacity > 0 {
        *groups = group;
    }

    let file = group_open();
    if file.is_null() {
        free(seen as *mut c_void);
        return -1;
    }
    let mut line = core::ptr::null_mut();
    let mut line_size = 0usize;
    let mut members = core::ptr::null_mut();
    let mut parsed = CabiGroup {
        gr_name: core::ptr::null_mut(),
        gr_passwd: core::ptr::null_mut(),
        gr_gid: 0,
        gr_mem: core::ptr::null_mut(),
    };
    let mut status;
    loop {
        status = group_next(
            file,
            &mut line,
            &mut line_size,
            &mut members,
            &mut parsed,
        );
        if status <= 0 {
            break;
        }
        let mut member_index = 0usize;
        let mut matches = false;
        while !(*members.add(member_index)).is_null() {
            if group_name_matches(user, *members.add(member_index)) {
                matches = true;
                break;
            }
            member_index += 1;
        }
        if matches {
            let added = group_seen_add(
                &mut seen,
                &mut seen_count,
                &mut seen_capacity,
                parsed.gr_gid,
            );
            if added < 0 {
                status = -1;
                break;
            }
            if added > 0 && seen_count - 1 < capacity {
                *groups.add(seen_count - 1) = parsed.gr_gid;
            }
        }
    }
    let scan_error = if status < 0 { ERRNO } else { 0 };
    let _ = fclose(file);
    free(line as *mut c_void);
    group_release_members(&mut members);
    free(seen as *mut c_void);
    if status < 0 {
        if scan_error == 0 {
            ERRNO = EIO_VAL;
        }
        return -1;
    }
    if seen_count > c_int::MAX as usize {
        ERRNO = EOVERFLOW;
        return -1;
    }
    *ngroups = seen_count as c_int;
    if seen_count > capacity { -1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn initgroups(user: *const c_char, group: c_uint) -> c_int {
    if user.is_null() {
        ERRNO = EINVAL;
        return -1;
    }
    let mut capacity = 16usize;
    let mut groups = malloc(capacity * core::mem::size_of::<c_uint>()) as *mut c_uint;
    if groups.is_null() {
        ERRNO = ENOMEM;
        return -1;
    }
    loop {
        let mut count = capacity as c_int;
        ERRNO = 0;
        let status = getgrouplist(user, group, groups, &mut count);
        if status == 0 {
            let result = setgroups(count as usize, groups);
            free(groups as *mut c_void);
            return result;
        }
        if ERRNO != 0 {
            free(groups as *mut c_void);
            return -1;
        }
        if count < 0 {
            free(groups as *mut c_void);
            ERRNO = EOVERFLOW;
            return -1;
        }
        let required = count as usize;
        let new_capacity = if required > capacity {
            required
        } else {
            match capacity.checked_mul(2) {
                Some(value) => value,
                None => {
                    free(groups as *mut c_void);
                    ERRNO = EOVERFLOW;
                    return -1;
                }
            }
        };
        let bytes = match new_capacity.checked_mul(core::mem::size_of::<c_uint>()) {
            Some(value) => value,
            None => {
                free(groups as *mut c_void);
                ERRNO = EOVERFLOW;
                return -1;
            }
        };
        let replacement = realloc(groups as *mut c_void, bytes) as *mut c_uint;
        if replacement.is_null() {
            free(groups as *mut c_void);
            ERRNO = ENOMEM;
            return -1;
        }
        groups = replacement;
        capacity = new_capacity;
    }
}
