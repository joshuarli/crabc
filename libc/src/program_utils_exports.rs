// program and utility interfaces.
//
// This slice follows musl's implementations for path/environment helpers,
// temporary files, and word/byte I/O.
// The functions use the existing libc allocator and raw Linux syscall layer;
// no success path is manufactured when the kernel or allocator reports an
// error.

const CABI_PATH_MAX: usize = 4096;
const CABI_SYMLOOP_MAX: usize = 40;
const CABI_INT_MAX: u64 = 0x7fff_ffff;

const CABI_EEXIST: c_int = 17;
const CABI_EINVAL: c_int = 22;
const CABI_PROGRAM_ENOENT: c_int = 2;
const CABI_ENAMETOOLONG: c_int = 36;
const CABI_ELOOP: c_int = 40;

const CABI_AT_SECURE: c_ulong = 23;

const CABI_O_NOCTTY: i32 = 0x100;
const CABI_O_CLOEXEC: i32 = 0x80000;
const CABI_O_RDWR: i32 = 2;
const CABI_O_CREAT: i32 = 64;
const CABI_O_EXCL: i32 = 128;
const CABI_O_ACCMODE: i32 = 3;
const CABI_F_GETFD: i32 = 1;

#[no_mangle]
pub unsafe extern "C" fn ctermid(s: *mut c_char) -> *mut c_char {
    let source = b"/dev/tty\0";
    if s.is_null() {
        return source.as_ptr() as *mut c_char;
    }
    core::ptr::copy_nonoverlapping(source.as_ptr(), s as *mut u8, source.len());
    s
}

#[no_mangle]
pub unsafe extern "C" fn get_current_dir_name() -> *mut c_char {
    // musl trusts PWD only when it names the same directory as ".".  This
    // preserves a logical, symlink-containing working directory when valid.
    let pwd = getenv(b"PWD\0".as_ptr() as *const c_char);
    if !pwd.is_null() && *pwd != 0 {
        let mut from_pwd: Stat = core::mem::zeroed();
        let mut from_dot: Stat = core::mem::zeroed();
        if stat(pwd, &mut from_pwd) == 0
            && stat(b".\0".as_ptr() as *const c_char, &mut from_dot) == 0
            && from_pwd.st_dev == from_dot.st_dev
            && from_pwd.st_ino == from_dot.st_ino
        {
            return strdup(pwd);
        }
    }

    // getcwd(NULL, 0) is the natural interface, but the existing getcwd
    // implementation starts with a bounded allocation.  Retry with growing
    // buffers so this GNU extension remains useful for long working paths.
    let mut size = 256usize;
    loop {
        let buffer = malloc(size) as *mut c_char;
        if buffer.is_null() {
            return core::ptr::null_mut();
        }
        let result = sys_getcwd(buffer as *mut u8, size);
        if result >= 0 {
            return buffer;
        }
        let error = (-result) as c_int;
        free(buffer as *mut c_void);
        if error != ENAMETOOLONG_VAL || size >= CABI_PATH_MAX {
            ERRNO = error;
            return core::ptr::null_mut();
        }
        size = match size.checked_mul(2) {
            Some(next) if next <= CABI_PATH_MAX => next,
            _ => CABI_PATH_MAX,
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn getdtablesize() -> c_int {
    let mut limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    if getrlimit(RLIMIT_NOFILE, &mut limit) < 0 {
        return -1;
    }
    if limit.rlim_cur < CABI_INT_MAX {
        limit.rlim_cur as c_int
    } else {
        CABI_INT_MAX as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    if getauxval(CABI_AT_SECURE) != 0 {
        core::ptr::null_mut()
    } else {
        getenv(name)
    }
}

#[no_mangle]
pub unsafe extern "C" fn getsubopt(
    optionp: *mut *mut c_char,
    keylist: *const *mut c_char,
    valuep: *mut *mut c_char,
) -> c_int {
    if optionp.is_null() || (*optionp).is_null() || keylist.is_null() || valuep.is_null() {
        ERRNO = CABI_EINVAL;
        return -1;
    }

    let start = *optionp;
    *valuep = core::ptr::null_mut();

    // Split one comma-delimited token in place.  Empty tokens are valid input
    // and simply produce the required "unknown option" result.
    let mut end = start;
    while *end != 0 && *end != b',' as c_char {
        end = end.add(1);
    }
    if *end == b',' as c_char {
        *end = 0;
        *optionp = end.add(1);
    } else {
        *optionp = end;
    }

    let token_len = strlen(start as *const c_char);
    let mut index = 0usize;
    while !(*keylist.add(index)).is_null() {
        let key = *keylist.add(index);
        let key_len = strlen(key as *const c_char);
        if token_len >= key_len
            && strncmp(start as *const u8, key as *const u8, key_len) == 0
        {
            let suffix = *start.add(key_len) as u8;
            if suffix == 0 {
                return index as c_int;
            }
            if suffix == b'=' {
                *valuep = start.add(key_len + 1);
                return index as c_int;
            }
        }
        index += 1;
    }
    -1
}

#[no_mangle]
pub unsafe extern "C" fn realpath(
    filename: *const c_char,
    resolved: *mut c_char,
) -> *mut c_char {
    // This is musl's bounded stack/output algorithm.  It resolves every
    // component with readlink, handles absolute links and .. cancellation,
    // and rejects overlong paths and symlink loops.
    let mut stack = [0u8; CABI_PATH_MAX + 1];
    let mut output = [0u8; CABI_PATH_MAX];
    let mut p: usize;
    let mut q = 0usize;
    let mut l: usize;
    let mut l0: usize;
    let mut links = 0usize;
    let mut nup = 0usize;
    let mut check_dir = false;

    if filename.is_null() {
        ERRNO = CABI_EINVAL;
        return core::ptr::null_mut();
    }
    l = strnlen(filename as *const u8, stack.len());
    if l == 0 {
        ERRNO = CABI_PROGRAM_ENOENT;
        return core::ptr::null_mut();
    }
    if l >= CABI_PATH_MAX {
        ERRNO = CABI_ENAMETOOLONG;
        return core::ptr::null_mut();
    }
    p = stack.len() - l - 1;
    core::ptr::copy_nonoverlapping(filename as *const u8, stack.as_mut_ptr().add(p), l + 1);

    'restart: loop {
        loop {
            if *stack.as_ptr().add(p) == b'/' {
                check_dir = false;
                nup = 0;
                q = 0;
                output[q] = b'/';
                q += 1;
                p += 1;
                if *stack.as_ptr().add(p) == b'/' && *stack.as_ptr().add(p + 1) != b'/' {
                    output[q] = b'/';
                    q += 1;
                }
                while *stack.as_ptr().add(p) == b'/' {
                    p += 1;
                }
            }

            let mut z = p;
            while *stack.as_ptr().add(z) != 0 && *stack.as_ptr().add(z) != b'/' {
                z += 1;
            }
            l0 = z - p;
            l = l0;

            if l == 0 && !check_dir {
                break;
            }
            if l == 1 && *stack.as_ptr().add(p) == b'.' {
                p += l;
                while *stack.as_ptr().add(p) == b'/' {
                    p += 1;
                }
                continue;
            }

            if q != 0 && output[q - 1] != b'/' {
                if p == 0 {
                    ERRNO = CABI_ENAMETOOLONG;
                    return core::ptr::null_mut();
                }
                p -= 1;
                stack[p] = b'/';
                l += 1;
            }
            if q + l >= CABI_PATH_MAX {
                ERRNO = CABI_ENAMETOOLONG;
                return core::ptr::null_mut();
            }
            core::ptr::copy_nonoverlapping(stack.as_ptr().add(p), output.as_mut_ptr().add(q), l);
            output[q + l] = 0;
            p += l;

            let mut up = false;
            if l0 == 2
                && *stack.as_ptr().add(p - 2) == b'.'
                && *stack.as_ptr().add(p - 1) == b'.'
            {
                up = true;
                    if q <= 3 * nup {
                        nup += 1;
                        q += l;
                        while *stack.as_ptr().add(p) == b'/' {
                            p += 1;
                        }
                        continue;
                }
                if !check_dir {
                    // Skip readlink for .. when all prior components are
                    // known directories.
                    check_dir = false;
                    while q != 0 && output[q - 1] != b'/' {
                        q -= 1;
                    }
                    if q > 1 && (q > 2 || output[0] != b'/') {
                        q -= 1;
                    }
                    while *stack.as_ptr().add(p) == b'/' {
                        p += 1;
                    }
                    continue;
                }
            }

            let k = sys_readlinkat(
                AT_FDCWD,
                output.as_ptr(),
                stack.as_mut_ptr(),
                p,
            );
            if k == p as i64 {
                ERRNO = CABI_ENAMETOOLONG;
                return core::ptr::null_mut();
            }
            if k == 0 {
                ERRNO = CABI_PROGRAM_ENOENT;
                return core::ptr::null_mut();
            }
            if k < 0 {
                let error = (-k) as c_int;
                if error != 22 {
                    ERRNO = error;
                    return core::ptr::null_mut();
                }
                check_dir = false;
                if up {
                    while q != 0 && output[q - 1] != b'/' {
                        q -= 1;
                    }
                    if q > 1 && (q > 2 || output[0] != b'/') {
                        q -= 1;
                    }
                    while *stack.as_ptr().add(p) == b'/' {
                        p += 1;
                    }
                    continue;
                }
                if l0 != 0 {
                    q += l;
                }
                check_dir = *stack.as_ptr().add(p) != 0;
                while *stack.as_ptr().add(p) == b'/' {
                    p += 1;
                }
                continue;
            }

            links += 1;
            if links == CABI_SYMLOOP_MAX {
                ERRNO = CABI_ELOOP;
                return core::ptr::null_mut();
            }
            let link_len = k as usize;
            if *stack.as_ptr().add(link_len - 1) == b'/' {
                while *stack.as_ptr().add(p) == b'/' {
                    p += 1;
                }
            }
            p -= link_len;
            core::ptr::copy(stack.as_ptr(), stack.as_mut_ptr().add(p), link_len);
            continue 'restart;
        }
        break;
    }

    output[q] = 0;
    if output[0] != b'/' {
        if getcwd(stack.as_mut_ptr() as *mut c_char, stack.len()).is_null() {
            return core::ptr::null_mut();
        }
        l = strlen(stack.as_ptr() as *const c_char);
        p = 0;
        while nup != 0 {
            while l > 1 && stack[l - 1] != b'/' {
                l -= 1;
            }
            if l > 1 {
                l -= 1;
            }
            nup -= 1;
            p += 2;
            if p < q {
                p += 1;
            }
        }
        if q - p != 0 && stack[l - 1] != b'/' {
            stack[l] = b'/';
            l += 1;
        }
        if l + (q - p) + 1 >= CABI_PATH_MAX {
            ERRNO = CABI_ENAMETOOLONG;
            return core::ptr::null_mut();
        }
        core::ptr::copy(output.as_ptr().add(p), output.as_mut_ptr().add(l), q - p + 1);
        core::ptr::copy_nonoverlapping(stack.as_ptr(), output.as_mut_ptr(), l);
        q = l + q - p;
    }

    if !resolved.is_null() {
        core::ptr::copy_nonoverlapping(output.as_ptr(), resolved as *mut u8, q + 1);
        resolved
    } else {
        strdup(output.as_ptr() as *const c_char)
    }
}

static mut CABI_TEMP_COUNTER: usize = 0;

unsafe fn cabi_temp_name(template: *mut c_char, suffix_len: usize, flags: c_int) -> c_int {
    if template.is_null() {
        ERRNO = CABI_EINVAL;
        return -1;
    }
    let total = strlen(template as *const c_char);
    if total < 6 || suffix_len > total - 6 {
        ERRNO = CABI_EINVAL;
        return -1;
    }
    let start = total - suffix_len - 6;
    for i in 0..6 {
        if *template.add(start + i) != b'X' as c_char {
            ERRNO = CABI_EINVAL;
            return -1;
        }
    }

    let mut ts: timespec = core::mem::zeroed();
    let clock = sys_clock_gettime(CLOCK_REALTIME, &mut ts);
    let mut seed = (if clock >= 0 { ts.tv_nsec as usize } else { 0 })
        ^ (sys_getpid() as usize)
        ^ CABI_TEMP_COUNTER;
    CABI_TEMP_COUNTER = CABI_TEMP_COUNTER.wrapping_add(1);
    let alphabet = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";

    let open_flags = (flags & !CABI_O_ACCMODE) | CABI_O_RDWR | CABI_O_CREAT | CABI_O_EXCL;
    for _ in 0..100 {
        // A fresh LCG value per character is enough to vary names; O_EXCL is
        // the security boundary that makes a successful name race-free.
        for i in 0..6 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *template.add(start + i) = alphabet[(seed >> 58) as usize & 63] as c_char;
        }
        let fd = sys_open(template as *const u8, open_flags as i64, 0o600);
        if fd >= 0 {
            return fd as c_int;
        }
        let error = (-fd) as c_int;
        if error != CABI_EEXIST {
            ERRNO = error;
            for i in 0..6 {
                *template.add(start + i) = b'X' as c_char;
            }
            return -1;
        }
    }
    for i in 0..6 {
        *template.add(start + i) = b'X' as c_char;
    }
    ERRNO = CABI_EEXIST;
    -1
}

#[no_mangle]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    cabi_temp_name(template, 0, flags)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn mkostemps(
    template: *mut c_char,
    suffix_len: c_int,
    flags: c_int,
) -> c_int {
    if suffix_len < 0 {
        ERRNO = CABI_EINVAL;
        return -1;
    }
    cabi_temp_name(template, suffix_len as usize, flags)
}

#[no_mangle]
pub unsafe extern "C" fn mkstemps(template: *mut c_char, suffix_len: c_int) -> c_int {
    if suffix_len < 0 {
        ERRNO = CABI_EINVAL;
        return -1;
    }
    cabi_temp_name(template, suffix_len as usize, 0)
}

// tempnam intentionally creates and immediately unlinks an exclusive file to
// obtain a pathname that was unused at the instant it was returned.  Like musl
// and POSIX, this remains inherently racy after return; callers that need an
// open race-free file must use mkstemp instead.
#[no_mangle]
pub unsafe extern "C" fn tempnam(dir: *const c_char, pfx: *const c_char) -> *mut c_char {
    let fallback = b"/tmp\0".as_ptr() as *const c_char;
    let tmpdir = getenv(b"TMPDIR\0".as_ptr() as *const c_char);
    let directory = if !dir.is_null() && *dir != 0 && access(dir, 2) == 0 {
        dir
    } else if !tmpdir.is_null() && *tmpdir != 0 && access(tmpdir, 2) == 0 {
        tmpdir
    } else {
        fallback
    };
    let prefix = if pfx.is_null() || *pfx == 0 {
        b"file\0".as_ptr() as *const c_char
    } else {
        pfx
    };

    let directory_len = strnlen(directory as *const u8, CABI_PATH_MAX);
    if directory_len == CABI_PATH_MAX {
        ERRNO = CABI_ENAMETOOLONG;
        return core::ptr::null_mut();
    }
    // musl retains only the first five prefix characters, keeping the result
    // inside traditional tmpnam-sized expectations while preserving a useful
    // caller-selected stem.
    let prefix_len = strnlen(prefix as *const u8, 6).min(5);
    let separator = if directory_len != 0 && *directory.add(directory_len - 1) as u8 != b'/' {
        1usize
    } else {
        0usize
    };
    let allocation_len = match directory_len
        .checked_add(separator)
        .and_then(|value| value.checked_add(prefix_len))
        .and_then(|value| value.checked_add(7))
    {
        Some(value) if value <= CABI_PATH_MAX => value,
        _ => {
            ERRNO = CABI_ENAMETOOLONG;
            return core::ptr::null_mut();
        }
    };
    let result = malloc(allocation_len) as *mut c_char;
    if result.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(directory, result, directory_len);
    let mut offset = directory_len;
    if separator != 0 {
        *result.add(offset) = b'/' as c_char;
        offset += 1;
    }
    core::ptr::copy_nonoverlapping(prefix, result.add(offset), prefix_len);
    offset += prefix_len;
    for index in 0..6 {
        *result.add(offset + index) = b'X' as c_char;
    }
    *result.add(offset + 6) = 0;

    let fd = cabi_temp_name(result, 0, CABI_O_CLOEXEC);
    if fd < 0 {
        free(result as *mut c_void);
        return core::ptr::null_mut();
    }
    let close_result = close(fd);
    if close_result != 0 {
        let error = ERRNO;
        let _ = unlink(result);
        free(result as *mut c_void);
        ERRNO = error;
        return core::ptr::null_mut();
    }
    if unlink(result) != 0 {
        let error = ERRNO;
        free(result as *mut c_void);
        ERRNO = error;
        return core::ptr::null_mut();
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn swab(src: *const c_void, dst: *mut c_void, n: isize) {
    let mut remaining = n;
    let mut source = src as *const u8;
    let mut target = dst as *mut u8;
    while remaining > 1 {
        let first = *source;
        let second = *source.add(1);
        *target = second;
        *target.add(1) = first;
        source = source.add(2);
        target = target.add(2);
        remaining -= 2;
    }
}

#[no_mangle]
pub unsafe extern "C" fn putw(value: c_int, stream: *mut FILE) -> c_int {
    if fwrite(
        &value as *const c_int as *const c_void,
        core::mem::size_of::<c_int>(),
        1,
        stream,
    ) == 1 {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn getw(stream: *mut FILE) -> c_int {
    let mut value = 0 as c_int;
    if fread(
        &mut value as *mut c_int as *mut c_void,
        core::mem::size_of::<c_int>(),
        1,
        stream,
    ) == 1 {
        value
    } else {
        -1
    }
}

// Linux's tty ioctl layout is the same for the supported 64-bit targets and
// matches the public termios header already used by terminal_exports.rs.
#[repr(C)]
#[derive(Clone, Copy)]
struct CabiPassTermios {
    c_iflag: c_uint,
    c_oflag: c_uint,
    c_cflag: c_uint,
    c_lflag: c_uint,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: c_uint,
    c_ospeed: c_uint,
}

const CABI_PROGRAM_TCGETS: u32 = 0x5401;
const CABI_PROGRAM_TCSETSF: u32 = 0x5404;
const CABI_TCSAFLUSH: c_int = 2;
const CABI_ECHO: c_uint = 0o10;
const CABI_ISIG: c_uint = 0o1;
const CABI_ICRNL: c_uint = 0o400;
const CABI_INLCR: c_uint = 0o100;
const CABI_IGNCR: c_uint = 0o200;
const CABI_ICANON: c_uint = 0o2;

static mut CABI_PASSWORD: [u8; 128] = [0; 128];
const CABI_PASSWORD_CAPACITY: usize = 128;

#[no_mangle]
pub unsafe extern "C" fn getpass(prompt: *const c_char) -> *mut c_char {
    let fd = sys_open(
        b"/dev/tty\0".as_ptr(),
        (CABI_O_RDWR | CABI_O_NOCTTY | CABI_O_CLOEXEC) as i64,
        0,
    );
    if fd < 0 {
        ERRNO = (-fd) as c_int;
        return core::ptr::null_mut();
    }
    let fd = fd as c_int;

    let mut saved: CabiPassTermios = core::mem::zeroed();
    let mut modified: CabiPassTermios;
    let got = sys_ioctl(fd, CABI_PROGRAM_TCGETS, &mut saved as *mut CabiPassTermios as *mut u8);
    if got < 0 {
        let error = (-got) as c_int;
        ERRNO = error;
        let _ = sys_close(fd as i64);
        return core::ptr::null_mut();
    }
    modified = saved;
    modified.c_lflag &= !(CABI_ECHO | CABI_ISIG);
    modified.c_lflag |= CABI_ICANON;
    modified.c_iflag &= !(CABI_INLCR | CABI_IGNCR);
    modified.c_iflag |= CABI_ICRNL;
    let changed = sys_ioctl(fd, CABI_PROGRAM_TCSETSF, &mut modified as *mut CabiPassTermios as *mut u8);
    if changed < 0 {
        ERRNO = (-changed) as c_int;
        let _ = sys_close(fd as i64);
        return core::ptr::null_mut();
    }

    if !prompt.is_null() {
        let prompt_len = strlen(prompt);
        let _ = sys_write(fd as i64, prompt as *const u8, prompt_len);
    }
    let read_len = sys_read(
        fd as i64,
        core::ptr::addr_of_mut!(CABI_PASSWORD).cast::<u8>(),
        CABI_PASSWORD_CAPACITY,
    );
    let restore = sys_ioctl(fd, CABI_PROGRAM_TCSETSF, &mut saved as *mut CabiPassTermios as *mut u8);
    if restore < 0 {
        ERRNO = (-restore) as c_int;
    }
    let _ = sys_write(fd as i64, b"\n".as_ptr(), 1);
    let _ = sys_close(fd as i64);

    if read_len < 0 {
        ERRNO = (-read_len) as c_int;
        return core::ptr::null_mut();
    }
    let mut length = read_len as usize;
    if (length > 0 && CABI_PASSWORD[length - 1] == b'\n') || length == CABI_PASSWORD_CAPACITY {
        length -= 1;
    }
    CABI_PASSWORD[length] = 0;
    core::ptr::addr_of_mut!(CABI_PASSWORD).cast::<c_char>()
}

// exec* process entry points.  The path search mirrors musl's __execvpe:
// PATH is taken from the caller's environment (even for execvpe's replacement
// environment), empty PATH components name the current directory, and a
// failed search reports EACCES only when at least one candidate was denied.
// The shell retry for ENOEXEC is kept bounded so malformed argv cannot turn
// this no_std wrapper into an unbounded stack walk.
const CABI_EXEC_PATH_MAX: usize = 4096;
const CABI_EXEC_NAME_MAX: usize = 255;
const CABI_EXEC_ARGV_MAX: usize = 256;
const CABI_EXEC_ENOENT: c_int = 2;
const CABI_EXEC_E2BIG: c_int = 7;
const CABI_EXEC_ENOEXEC: c_int = 8;
const CABI_EXEC_EBADF: c_int = 9;
const CABI_EXEC_EACCES: c_int = 13;
const CABI_EXEC_EFAULT: c_int = 14;
const CABI_EXEC_ENOTDIR: c_int = 20;
const CABI_EXEC_ENAMETOOLONG: c_int = 36;
const CABI_EXEC_ENOSYS: c_int = 38;
const CABI_EXEC_EINVAL: c_int = 22;
const CABI_EXEC_AT_EMPTY_PATH: i64 = 0x1000;


const CABI_EXEC_SYS_EXECVEAT: i64 = 281;

#[inline]
unsafe fn cabi_exec_attempt(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let result = sys_execve(path, argv, envp);
    let error = if result < 0 {
        (-result) as c_int
    } else {
        // execve only returns on failure.  Keep a valid errno if a broken
        // syscall boundary ever violates that contract.
        CABI_EXEC_EINVAL
    };
    ERRNO = error;
    error
}

unsafe fn cabi_exec_shell(
    candidate: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let shell = b"/bin/sh\0";
    // Two leading entries (/bin/sh and the script), followed by argv[1..].
    // The extra slots leave room for the terminating null and the bounded
    // overflow probe below.
    let mut shell_argv: [*const c_char; CABI_EXEC_ARGV_MAX + 4] =
        [core::ptr::null(); CABI_EXEC_ARGV_MAX + 4];
    shell_argv[0] = shell.as_ptr() as *const c_char;
    shell_argv[1] = candidate;

    let mut source = 1usize;
    let mut destination = 2usize;
    if !argv.is_null() {
        while source <= CABI_EXEC_ARGV_MAX {
            let item = *argv.add(source);
            if item.is_null() {
                break;
            }
            shell_argv[destination] = item;
            destination += 1;
            source += 1;
        }
        if source == CABI_EXEC_ARGV_MAX + 1 && !(*argv.add(source)).is_null() {
            ERRNO = CABI_EXEC_E2BIG;
            return -1;
        }
    }
    shell_argv[destination] = core::ptr::null();

    cabi_exec_attempt(shell.as_ptr() as *const c_char, shell_argv.as_ptr(), envp);
    -1
}

unsafe fn cabi_execvpe_impl(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if file.is_null() {
        ERRNO = CABI_EXEC_EFAULT;
        return -1;
    }

    if *file as u8 == 0 {
        ERRNO = CABI_EXEC_ENOENT;
        return -1;
    }

    // Musl takes the direct path branch before applying NAME_MAX to a PATH
    // search name.  Keep that ordering so a long pathname containing '/' is
    // reported by the kernel rather than by the search wrapper.
    let has_slash = !strchr(file as *const u8, b'/' as c_int).is_null();

    if has_slash {
        let error = cabi_exec_attempt(file, argv, envp);
        if error == CABI_EXEC_ENOEXEC {
            return cabi_exec_shell(file, argv, envp);
        }
        return -1;
    }

    let file_len = strnlen(file as *const u8, CABI_EXEC_NAME_MAX + 1);
    if file_len > CABI_EXEC_NAME_MAX {
        ERRNO = CABI_EXEC_ENAMETOOLONG;
        return -1;
    }

    // Like musl, execvpe searches the caller's PATH rather than a PATH entry
    // in envp.  This matters when the replacement environment is deliberate.
    let default_path = b"/usr/local/bin:/bin:/usr/bin\0";
    let path = getenv(b"PATH\0".as_ptr() as *const c_char);
    let path = if path.is_null() {
        default_path.as_ptr()
    } else {
        path as *const u8
    };
    let path_len = strnlen(path, CABI_EXEC_PATH_MAX - 1);
    let mut candidate = [0u8; CABI_EXEC_PATH_MAX];
    let mut start = 0usize;
    let mut seen_eacces = false;

    loop {
        let mut end = start;
        while end < path_len && *path.add(end) != b':' {
            end += 1;
        }
        let directory_len = end - start;
        let candidate_len = if directory_len == 0 {
            file_len
        } else {
            directory_len + 1 + file_len
        };

        // Overlong PATH components are skipped in the same way as musl's
        // bounded candidate construction; a later candidate can still win.
        if candidate_len < CABI_EXEC_PATH_MAX {
            if directory_len == 0 {
                core::ptr::copy_nonoverlapping(
                    file as *const u8,
                    candidate.as_mut_ptr(),
                    file_len + 1,
                );
            } else {
                core::ptr::copy_nonoverlapping(
                    path.add(start),
                    candidate.as_mut_ptr(),
                    directory_len,
                );
                *candidate.as_mut_ptr().add(directory_len) = b'/';
                core::ptr::copy_nonoverlapping(
                    file as *const u8,
                    candidate.as_mut_ptr().add(directory_len + 1),
                    file_len + 1,
                );
            }

            let error = cabi_exec_attempt(
                candidate.as_ptr() as *const c_char,
                argv,
                envp,
            );
            match error {
                CABI_EXEC_EACCES => seen_eacces = true,
                CABI_EXEC_ENOENT | CABI_EXEC_ENOTDIR => {}
                CABI_EXEC_ENOEXEC => {
                    return cabi_exec_shell(candidate.as_ptr() as *const c_char, argv, envp);
                }
                _ => return -1,
            }
        }

        if end == path_len {
            break;
        }
        start = end + 1;
    }

    ERRNO = if seen_eacces {
        CABI_EXEC_EACCES
    } else {
        CABI_EXEC_ENOENT
    };
    -1
}

#[no_mangle]
pub unsafe extern "C" fn execv(
    path: *const c_char,
    argv: *const *const c_char,
) -> c_int {
    cabi_exec_attempt(path, argv, __environ as *const *const c_char);
    -1
}

#[no_mangle]
pub unsafe extern "C" fn execvp(
    file: *const c_char,
    argv: *const *const c_char,
) -> c_int {
    cabi_execvpe_impl(file, argv, __environ as *const *const c_char)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    cabi_execvpe_impl(file, argv, envp)
}

#[no_mangle]
pub unsafe extern "C" fn execlp(
    file: *const c_char,
    arg: *const c_char,
    mut args: ...,
) -> c_int {
    let mut argv: [*const c_char; CABI_EXEC_ARGV_MAX + 1] =
        [core::ptr::null(); CABI_EXEC_ARGV_MAX + 1];
    argv[0] = arg;
    let mut count = 1usize;
    loop {
        let item: *const c_char = args.next_arg();
        if item.is_null() {
            break;
        }
        if count >= CABI_EXEC_ARGV_MAX {
            ERRNO = CABI_EXEC_E2BIG;
            return -1;
        }
        argv[count] = item;
        count += 1;
    }
    argv[count] = core::ptr::null();
    cabi_execvpe_impl(file, argv.as_ptr(), __environ as *const *const c_char)
}

unsafe fn cabi_execveat(
    fd: c_int,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> i64 {
    aarch64::syscall::syscall5(
        CABI_EXEC_SYS_EXECVEAT,
        fd as i64,
        b"\0".as_ptr() as i64,
        argv as i64,
        envp as i64,
        CABI_EXEC_AT_EMPTY_PATH,
    )
}

unsafe fn cabi_exec_procfd(fd: c_int, out: &mut [u8; 32]) -> *const c_char {
    let prefix = b"/proc/self/fd/";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    let mut value = if fd < 0 { (-(fd as i64)) as u32 } else { fd as u32 };
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut i = 0usize;
    while i < count {
        out[prefix.len() + i] = digits[count - i - 1];
        i += 1;
    }
    out[prefix.len() + count] = 0;
    out.as_ptr() as *const c_char
}

#[no_mangle]
pub unsafe extern "C" fn fexecve(
    fd: c_int,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let result = cabi_execveat(fd, argv, envp);
    if result != -CABI_EXEC_ENOSYS as i64 {
        if result < 0 {
            ERRNO = (-result) as c_int;
        } else {
            ERRNO = CABI_EXEC_EINVAL;
        }
        return -1;
    }

    let mut procfd = [0u8; 32];
    let path = cabi_exec_procfd(fd, &mut procfd);
    let error = cabi_exec_attempt(path, argv, envp);
    if error == CABI_EXEC_ENOENT {
        ERRNO = CABI_EXEC_EBADF;
    }
    -1
}
