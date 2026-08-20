// M4 filesystem traversal and pathname expansion.
//
// These entry points deliberately build on the existing opendir/readdir,
// stat/lstat, allocator, and fnmatch implementations.  The ownership rules
// are kept at the C boundary: scandir returns individually allocated dirents,
// glob returns individually allocated path strings, and globfree releases
// every allocation made by glob.

const M4_TRAVERSAL_PATH_MAX: usize = 4096;
const M4_TRAVERSAL_IO_PATH_MAX: usize = M4_TRAVERSAL_PATH_MAX * 2 + 2;
const M4_TRAVERSAL_ENOMEM: c_int = 12;
const M4_TRAVERSAL_EINVAL: c_int = 22;
const M4_TRAVERSAL_ENOENT: c_int = 2;
const M4_TRAVERSAL_EACCES: c_int = 13;
const M4_TRAVERSAL_ENAMETOOLONG: c_int = 36;
const M4_TRAVERSAL_EOVERFLOW: c_int = 75;
const M4_TRAVERSAL_O_DIRECTORY: c_int = 0x4000;

// ============================================================
// dirent.h: scandir
// ============================================================

type M4DirentSelector = unsafe extern "C" fn(*const M4Dirent) -> c_int;
type M4DirentComparator =
    unsafe extern "C" fn(*const *const M4Dirent, *const *const M4Dirent) -> c_int;

unsafe fn m4_scandir_free(names: *mut *mut M4Dirent, count: usize) {
    if names.is_null() {
        return;
    }
    for index in 0..count {
        let entry = *names.add(index);
        if !entry.is_null() {
            free(entry as *mut c_void);
        }
    }
    free(names as *mut c_void);
}

#[no_mangle]
pub unsafe extern "C" fn scandir(
    path: *const c_char,
    result: *mut *mut *mut M4Dirent,
    selector: Option<M4DirentSelector>,
    comparator: Option<M4DirentComparator>,
) -> c_int {
    if path.is_null() || result.is_null() {
        ERRNO = M4_TRAVERSAL_EINVAL;
        return -1;
    }

    let dir = opendir(path);
    if dir.is_null() {
        return -1;
    }

    let saved_errno = ERRNO;
    let mut names: *mut *mut M4Dirent = core::ptr::null_mut();
    let mut count = 0usize;
    let mut capacity = 0usize;
    let scan_errno = loop {
        ERRNO = 0;
        let entry = readdir(dir);
        if entry.is_null() {
            break ERRNO;
        }
        if let Some(select) = selector {
            if select(entry as *const M4Dirent) == 0 {
                continue;
            }
        }

        if count == capacity {
            let next = match capacity.checked_mul(2).and_then(|n| n.checked_add(1)) {
                Some(value) => value,
                None => {
                    break M4_TRAVERSAL_EOVERFLOW;
                }
            };
            let bytes = match next.checked_mul(core::mem::size_of::<*mut M4Dirent>()) {
                Some(value) => value,
                None => {
                    break M4_TRAVERSAL_EOVERFLOW;
                }
            };
            let grown = realloc(names as *mut c_void, bytes) as *mut *mut M4Dirent;
            if grown.is_null() {
                break if ERRNO != 0 { ERRNO } else { M4_TRAVERSAL_ENOMEM };
            }
            names = grown;
            capacity = next;
        }

        let copy_size = (*entry).d_reclen as usize;
        let copy = malloc(copy_size) as *mut M4Dirent;
        if copy.is_null() {
            break if ERRNO != 0 { ERRNO } else { M4_TRAVERSAL_ENOMEM };
        }
        core::ptr::copy_nonoverlapping(entry as *const u8, copy as *mut u8, copy_size);
        *names.add(count) = copy;
        count += 1;
    };

    let close_result = closedir(dir);
    if scan_errno != 0 || close_result != 0 {
        let error = if scan_errno != 0 { scan_errno } else { ERRNO };
        m4_scandir_free(names, count);
        ERRNO = if error != 0 { error } else { M4_TRAVERSAL_EINVAL };
        return -1;
    }
    ERRNO = saved_errno;

    // An insertion sort keeps the callback ABI exact without casting it to
    // qsort's void-pointer comparator type, and directory results are small
    // enough that the bounded implementation remains predictable.
    if let Some(compare) = comparator {
        let mut index = 1usize;
        while index < count {
            let mut current = index;
            while current > 0 {
                let left = names.add(current - 1) as *const *const M4Dirent;
                let right = names.add(current) as *const *const M4Dirent;
                if compare(left, right) <= 0 {
                    break;
                }
                core::ptr::swap(names.add(current - 1), names.add(current));
                current -= 1;
            }
            index += 1;
        }
    }

    if count > c_int::MAX as usize {
        m4_scandir_free(names, count);
        ERRNO = M4_TRAVERSAL_EOVERFLOW;
        return -1;
    }
    *result = names;
    count as c_int
}

// ============================================================
// glob.h: pathname expansion
// ============================================================

const M4_GLOB_ERR: c_int = 0x01;
const M4_GLOB_MARK: c_int = 0x02;
const M4_GLOB_NOSORT: c_int = 0x04;
const M4_GLOB_DOOFFS: c_int = 0x08;
const M4_GLOB_NOCHECK: c_int = 0x10;
const M4_GLOB_APPEND: c_int = 0x20;
const M4_GLOB_NOESCAPE: c_int = 0x40;
const M4_GLOB_PERIOD: c_int = 0x80;
const M4_GLOB_TILDE: c_int = 0x1000;
const M4_GLOB_TILDE_CHECK: c_int = 0x4000;
const M4_GLOB_NOSPACE: c_int = 1;
const M4_GLOB_ABORTED: c_int = 2;
const M4_GLOB_NOMATCH: c_int = 3;

#[repr(C)]
struct M4GlobMatch {
    next: *mut M4GlobMatch,
    path: *mut c_char,
}

type M4GlobError = unsafe extern "C" fn(*const c_char, c_int) -> c_int;

unsafe fn m4_glob_copy_string(source: *const c_char, length: usize) -> *mut c_char {
    let copy = malloc(length + 1) as *mut c_char;
    if copy.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(source as *const u8, copy as *mut u8, length);
    *copy.add(length) = 0;
    copy
}

// Expand one leading '~' using the same real sources as musl: HOME is used
// for an unnamed tilde, and the passwd database is consulted for a named
// user or when HOME is absent.  An absent passwd record is a genuine
// GLOB_NOMATCH condition; no synthetic home directory is ever invented.
unsafe fn m4_glob_expand_tilde(
    pattern: *mut u8,
    path: *mut u8,
    position: *mut usize,
) -> Result<*mut u8, c_int> {
    let mut name_end = pattern.add(1);
    while *name_end != 0 && *name_end != b'/' {
        name_end = name_end.add(1);
    }
    let slash = if *name_end == b'/' {
        Some(name_end)
    } else {
        None
    };
    let named = name_end != pattern.add(1);
    if named {
        // getpwnam_r consumes a NUL-terminated name.  The original pattern
        // copy is disposable, so replacing the separator is safe.
        *name_end = 0;
    }

    let home = if !named {
        getenv(b"HOME\0".as_ptr() as *const c_char)
    } else {
        core::ptr::null_mut()
    };
    let home = if !home.is_null() {
        home
    } else {
        let passwd = if named {
            getpwnam(pattern.add(1) as *const c_char)
        } else {
            getpwuid(getuid())
        };
        if passwd.is_null() || (*passwd).pw_dir.is_null() {
            return Err(M4_GLOB_NOMATCH);
        }
        (*passwd).pw_dir
    };

    let mut home_length = 0usize;
    while *home.add(home_length) != 0 {
        home_length += 1;
    }
    let suffix = if slash.is_some() { 1 } else { 0 };
    if home_length
        .checked_add(suffix)
        .and_then(|n| n.checked_add(1))
        .map_or(true, |n| n >= M4_TRAVERSAL_PATH_MAX)
    {
        return Err(M4_GLOB_NOMATCH);
    }
    core::ptr::copy_nonoverlapping(home as *const u8, path, home_length);
    let mut output = home_length;
    if slash.is_some() {
        *path.add(output) = b'/';
        output += 1;
    }
    *path.add(output) = 0;
    *position = output;
    Ok(slash.map_or(name_end, |separator| separator.add(1)))
}

unsafe fn m4_glob_append_match(
    tail: &mut *mut M4GlobMatch,
    path: *const u8,
    length: usize,
    mark_directory: bool,
) -> c_int {
    let suffix = if mark_directory && length != 0 && *path.add(length - 1) != b'/' {
        1
    } else {
        0
    };
    let copy = malloc(length + suffix + 1) as *mut c_char;
    if copy.is_null() {
        return M4_GLOB_NOSPACE;
    }
    core::ptr::copy_nonoverlapping(path, copy as *mut u8, length);
    if suffix != 0 {
        *copy.add(length) = b'/' as c_char;
    }
    *copy.add(length + suffix) = 0;

    let node = malloc(core::mem::size_of::<M4GlobMatch>()) as *mut M4GlobMatch;
    if node.is_null() {
        free(copy as *mut c_void);
        return M4_GLOB_NOSPACE;
    }
    (*node).next = core::ptr::null_mut();
    (*node).path = copy;
    (**tail).next = node;
    *tail = node;
    0
}

unsafe fn m4_glob_free_matches(mut node: *mut M4GlobMatch) {
    while !node.is_null() {
        let next = (*node).next;
        free((*node).path as *mut c_void);
        free(node as *mut c_void);
        node = next;
    }
}

#[inline]
unsafe fn m4_glob_magic(pattern: *const u8, flags: c_int) -> bool {
    let mut cursor = pattern;
    while *cursor != 0 {
        if *cursor == b'\\' && flags & M4_GLOB_NOESCAPE == 0 {
            if *cursor.add(1) == 0 {
                return false;
            }
            cursor = cursor.add(2);
            continue;
        }
        if *cursor == b'*' || *cursor == b'?' || *cursor == b'[' {
            return true;
        }
        cursor = cursor.add(1);
    }
    false
}

// Return the first unescaped slash in one pattern component.  The caller may
// temporarily replace it with NUL while recursing into the component.
unsafe fn m4_glob_component_end(pattern: *mut u8, flags: c_int) -> *mut u8 {
    let mut cursor = pattern;
    while *cursor != 0 {
        if *cursor == b'\\' && flags & M4_GLOB_NOESCAPE == 0 {
            if *cursor.add(1) == 0 {
                return core::ptr::null_mut();
            }
            cursor = cursor.add(2);
        } else if *cursor == b'/' {
            return cursor;
        } else {
            cursor = cursor.add(1);
        }
    }
    core::ptr::null_mut()
}

unsafe fn m4_glob_copy_literal(
    pattern: *const u8,
    flags: c_int,
    path: *mut u8,
    position: usize,
) -> Option<usize> {
    let mut cursor = pattern;
    let mut output = position;
    while *cursor != 0 {
        let byte = *cursor;
        if byte == b'\\' && flags & M4_GLOB_NOESCAPE == 0 {
            cursor = cursor.add(1);
            if *cursor == 0 {
                return None;
            }
            if output + 1 >= M4_TRAVERSAL_PATH_MAX {
                return None;
            }
            *path.add(output) = *cursor;
            output += 1;
            cursor = cursor.add(1);
        } else {
            if output + 1 >= M4_TRAVERSAL_PATH_MAX {
                return None;
            }
            *path.add(output) = byte;
            output += 1;
            cursor = cursor.add(1);
        }
    }
    *path.add(output) = 0;
    Some(output)
}

unsafe fn m4_glob_report_error(
    error: Option<M4GlobError>,
    path: *const c_char,
    code: c_int,
    flags: c_int,
) -> bool {
    if let Some(report) = error {
        if report(path, code) != 0 {
            return true;
        }
    }
    flags & M4_GLOB_ERR != 0
}

unsafe fn m4_glob_emit(
    path: *mut u8,
    position: usize,
    flags: c_int,
    error: Option<M4GlobError>,
    tail: &mut *mut M4GlobMatch,
) -> c_int {
    let mut st: Stat = core::mem::zeroed();
    let mut is_directory = false;
    let stat_result = stat(path as *const c_char, &mut st);
    if stat_result == 0 {
        is_directory = st.st_mode & S_IFMT == S_IFDIR;
    } else {
        let stat_errno = ERRNO;
        if lstat(path as *const c_char, &mut st) != 0 {
            let lstat_errno = ERRNO;
            if lstat_errno != M4_TRAVERSAL_ENOENT
                && m4_glob_report_error(error, path as *const c_char, lstat_errno, flags)
            {
                return M4_GLOB_ABORTED;
            }
            return 0;
        }
        // A broken symlink exists for glob purposes, even when stat failed
        // with ENOENT.  Keep stat_errno observed so non-ENOENT diagnostics are
        // not silently replaced by the lstat result.
        if stat_errno != M4_TRAVERSAL_ENOENT && stat_errno != 0 {
            ERRNO = stat_errno;
        }
    }
    m4_glob_append_match(tail, path, position, flags & M4_GLOB_MARK != 0 && is_directory)
}

unsafe fn m4_glob_walk(
    path: *mut u8,
    position: usize,
    mut pattern: *mut u8,
    flags: c_int,
    error: Option<M4GlobError>,
    tail: &mut *mut M4GlobMatch,
) -> c_int {
    if *pattern == 0 {
        return m4_glob_emit(path, position, flags, error, tail);
    }

    // Collapse repeated separators while retaining an initial root slash.
    while *pattern == b'/' {
        pattern = pattern.add(1);
    }
    if *pattern == 0 {
        if position > 0 && *path.add(position - 1) != b'/' {
            if position + 1 >= M4_TRAVERSAL_PATH_MAX {
                ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
                return M4_GLOB_ABORTED;
            }
            *path.add(position) = b'/';
            *path.add(position + 1) = 0;
            return m4_glob_emit(path, position + 1, flags, error, tail);
        }
        return m4_glob_emit(path, position, flags, error, tail);
    }

    let separator = m4_glob_component_end(pattern, flags);
    let rest = if separator.is_null() {
        core::ptr::null_mut()
    } else {
        *separator = 0;
        separator.add(1)
    };
    let component_magic = m4_glob_magic(pattern, flags);
    let base_position = position;

    if component_magic {
        if position >= M4_TRAVERSAL_PATH_MAX {
            if !separator.is_null() {
                *separator = b'/';
            }
            ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
            return M4_GLOB_ABORTED;
        }
        *path.add(position) = 0;
        let directory = if position == 0 {
            b".\0".as_ptr() as *const c_char
        } else {
            path as *const c_char
        };
        let dir = opendir(directory);
        if dir.is_null() {
            let code = ERRNO;
            let aborted = m4_glob_report_error(error, directory, code, flags);
            if !separator.is_null() {
                *separator = b'/';
            }
            return if aborted { M4_GLOB_ABORTED } else { 0 };
        }
        let old_errno = ERRNO;
        let read_error = loop {
            ERRNO = 0;
            let entry = readdir(dir);
            if entry.is_null() {
                break ERRNO;
            }
            let name = (*entry).d_name.as_ptr() as *const u8;
            let name_len = strlen(name as *const c_char);
            if name_len >= M4_TRAVERSAL_PATH_MAX.saturating_sub(base_position) {
                continue;
            }
            let fnm_flags = if flags & M4_GLOB_NOESCAPE != 0 {
                FNM_NOESCAPE
            } else {
                0
            } | if flags & M4_GLOB_PERIOD == 0 {
                FNM_PERIOD
            } else {
                0
            };
            if fnmatch(pattern as *const c_char, name as *const c_char, fnm_flags) != 0 {
                continue;
            }
            if flags & M4_GLOB_PERIOD != 0
                && (*name == b'.')
                && (*name.add(1) == 0
                    || (*name.add(1) == b'.' && *name.add(2) == 0))
            {
                continue;
            }
            let mut child_position = base_position;
            if child_position > 0 && *path.add(child_position - 1) != b'/' {
                *path.add(child_position) = b'/';
                child_position += 1;
            }
            core::ptr::copy_nonoverlapping(name, path.add(child_position), name_len + 1);
            let child_result = if separator.is_null() {
                m4_glob_walk(path, child_position + name_len, b"\0".as_ptr() as *mut u8, flags, error, tail)
            } else if *rest == 0 {
                // A trailing slash is a directory requirement.  Let stat(2)
                // enforce it by emitting the candidate with the slash still
                // present (regular files then fail with ENOTDIR).
                if child_position + name_len + 1 >= M4_TRAVERSAL_PATH_MAX {
                    ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
                    M4_GLOB_ABORTED
                } else {
                    *path.add(child_position + name_len) = b'/';
                    *path.add(child_position + name_len + 1) = 0;
                    m4_glob_emit(
                        path,
                        child_position + name_len + 1,
                        flags,
                        error,
                        tail,
                    )
                }
            } else {
                m4_glob_walk(path, child_position + name_len, rest, flags, error, tail)
            };
            if child_result != 0 {
                let _ = closedir(dir);
                if !separator.is_null() {
                    *separator = b'/';
                }
                return child_result;
            }
        };
        let close_result = closedir(dir);
        if !separator.is_null() {
            *separator = b'/';
        }
        if read_error != 0 {
            let aborted = m4_glob_report_error(error, path as *const c_char, read_error, flags);
            if aborted {
                return M4_GLOB_ABORTED;
            }
        } else if close_result != 0 {
            let code = ERRNO;
            if m4_glob_report_error(error, path as *const c_char, code, flags) {
                return M4_GLOB_ABORTED;
            }
        }
        ERRNO = old_errno;
        return 0;
    }

    let next_position = match m4_glob_copy_literal(pattern, flags, path, position) {
        Some(value) => value,
        None => {
            if !separator.is_null() {
                *separator = b'/';
            }
            ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
            return M4_GLOB_ABORTED;
        }
    };
    let child_result = if separator.is_null() {
        m4_glob_emit(path, next_position, flags, error, tail)
    } else if *rest == 0 {
        if next_position + 1 >= M4_TRAVERSAL_PATH_MAX {
            ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
            M4_GLOB_ABORTED
        } else {
            *path.add(next_position) = b'/';
            *path.add(next_position + 1) = 0;
            m4_glob_emit(path, next_position + 1, flags, error, tail)
        }
    } else {
        let mut child_position = next_position;
        if child_position > 0 && *path.add(child_position - 1) != b'/' {
            if child_position + 1 >= M4_TRAVERSAL_PATH_MAX {
                ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
                M4_GLOB_ABORTED
            } else {
                *path.add(child_position) = b'/';
                child_position += 1;
                m4_glob_walk(path, child_position, rest, flags, error, tail)
            }
        } else {
            m4_glob_walk(path, child_position, rest, flags, error, tail)
        }
    };
    if !separator.is_null() {
        *separator = b'/';
    }
    let _ = base_position;
    child_result
}

unsafe fn m4_glob_string_compare(left: *const c_char, right: *const c_char) -> c_int {
    strcmp(left as *const u8, right as *const u8)
}

unsafe fn m4_glob_free_vector(g: *mut glob_t) {
    if g.is_null() || (*g).gl_pathv.is_null() {
        return;
    }
    let start = (*g).gl_offs;
    for index in 0..(*g).gl_pathc {
        let path = *(*g).gl_pathv.add(start + index);
        if !path.is_null() {
            free(path as *mut c_void);
        }
    }
    free((*g).gl_pathv as *mut c_void);
    (*g).gl_pathv = core::ptr::null_mut();
    (*g).gl_pathc = 0;
    (*g).gl_offs = 0;
}

// Public glob_t is declared in the header; this private mirror only exists to
// keep the no_std implementation independent of C parser definitions.
#[repr(C)]
pub struct glob_t {
    pub gl_pathc: usize,
    pub gl_pathv: *mut *mut c_char,
    pub gl_offs: usize,
    pub __dummy1: c_int,
    pub __dummy2: [*mut c_void; 5],
}

#[no_mangle]
pub unsafe extern "C" fn glob(
    pattern: *const c_char,
    flags: c_int,
    error: Option<M4GlobError>,
    result: *mut glob_t,
) -> c_int {
    if pattern.is_null() || result.is_null() {
        ERRNO = M4_TRAVERSAL_EINVAL;
        return M4_GLOB_ABORTED;
    }

    let requested_offsets = if flags & M4_GLOB_APPEND == 0 {
        if flags & M4_GLOB_DOOFFS != 0 {
            (*result).gl_offs
        } else {
            0
        }
    } else {
        (*result).gl_offs
    };
    if flags & M4_GLOB_APPEND == 0 {
        m4_glob_free_vector(result);
        (*result).gl_offs = requested_offsets;
    }

    let pattern_len = strlen(pattern as *const c_char);
    if pattern_len >= M4_TRAVERSAL_PATH_MAX {
        ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
        return M4_GLOB_ABORTED;
    }
    let pattern_copy = m4_glob_copy_string(pattern, pattern_len) as *mut u8;
    if pattern_copy.is_null() {
        return M4_GLOB_NOSPACE;
    }

    let mut path = [0u8; M4_TRAVERSAL_PATH_MAX];
    let mut position = 0usize;
    let mut walk_pattern = pattern_copy;
    if *walk_pattern == b'/' {
        path[0] = b'/';
        path[1] = 0;
        position = 1;
        walk_pattern = walk_pattern.add(1);
    }

    let mut head = M4GlobMatch {
        next: core::ptr::null_mut(),
        path: core::ptr::null_mut(),
    };
    let mut tail: *mut M4GlobMatch = &mut head;
    let mut walk_error = 0;
    if flags & (M4_GLOB_TILDE | M4_GLOB_TILDE_CHECK) != 0 && *walk_pattern == b'~' {
        match m4_glob_expand_tilde(walk_pattern, path.as_mut_ptr(), &mut position) {
            Ok(rest) => walk_pattern = rest,
            Err(error_code) => walk_error = error_code,
        }
    }
    if walk_error == 0 && (*walk_pattern != 0 || position != 0) {
        walk_error = m4_glob_walk(
            path.as_mut_ptr(),
            position,
            walk_pattern,
            flags,
            error,
            &mut tail,
        );
    }
    free(pattern_copy as *mut c_void);

    let mut match_count = 0usize;
    let mut node = head.next;
    while !node.is_null() {
        match_count += 1;
        node = (*node).next;
    }
    if walk_error == M4_GLOB_NOSPACE {
        m4_glob_free_matches(head.next);
        return M4_GLOB_NOSPACE;
    }
    if match_count == 0 && flags & M4_GLOB_NOCHECK != 0 {
        if m4_glob_append_match(&mut tail, pattern as *const u8, pattern_len, false) != 0 {
            m4_glob_free_matches(head.next);
            return M4_GLOB_NOSPACE;
        }
        match_count = 1;
    }
    if match_count == 0 {
        m4_glob_free_matches(head.next);
        return if walk_error != 0 {
            walk_error
        } else {
            M4_GLOB_NOMATCH
        };
    }
    if match_count > c_int::MAX as usize {
        m4_glob_free_matches(head.next);
        return M4_GLOB_NOSPACE;
    }

    let old_count = if flags & M4_GLOB_APPEND != 0 {
        (*result).gl_pathc
    } else {
        0
    };
    let offsets = if flags & M4_GLOB_DOOFFS != 0 || flags & M4_GLOB_APPEND != 0 {
        requested_offsets
    } else {
        0
    };
    let total = match offsets
        .checked_add(old_count)
        .and_then(|n| n.checked_add(match_count))
        .and_then(|n| n.checked_add(1))
    {
        Some(value) => value,
        None => {
            m4_glob_free_matches(head.next);
            return M4_GLOB_NOSPACE;
        }
    };
    let vector = if flags & M4_GLOB_APPEND != 0 {
        realloc((*result).gl_pathv as *mut c_void, total * core::mem::size_of::<*mut c_char>())
            as *mut *mut c_char
    } else {
        malloc(total * core::mem::size_of::<*mut c_char>()) as *mut *mut c_char
    };
    if vector.is_null() {
        m4_glob_free_matches(head.next);
        return M4_GLOB_NOSPACE;
    }
    (*result).gl_pathv = vector;
    (*result).gl_offs = offsets;
    if flags & M4_GLOB_APPEND == 0 {
        (*result).gl_pathc = 0;
        for index in 0..offsets {
            *vector.add(index) = core::ptr::null_mut();
        }
    }

    let target_start = offsets + old_count;
    node = head.next;
    let mut index = 0usize;
    while !node.is_null() {
        let next = (*node).next;
        *vector.add(target_start + index) = (*node).path;
        free(node as *mut c_void);
        index += 1;
        node = next;
    }
    *vector.add(target_start + match_count) = core::ptr::null_mut();
    (*result).gl_pathc = old_count + match_count;

    if flags & M4_GLOB_NOSORT == 0 && match_count > 1 {
        let start = target_start;
        for outer in 1..match_count {
            let mut inner = outer;
            while inner > 0 {
                let left = *vector.add(start + inner - 1);
                let right = *vector.add(start + inner);
                if m4_glob_string_compare(left, right) <= 0 {
                    break;
                }
                core::ptr::swap(vector.add(start + inner - 1), vector.add(start + inner));
                inner -= 1;
            }
        }
    }
    if walk_error != 0 {
        walk_error
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn globfree(result: *mut glob_t) {
    if result.is_null() {
        return;
    }
    m4_glob_free_vector(result);
}

// ============================================================
// ftw.h: file tree traversal
// ============================================================

const M4_FTW_F: c_int = 1;
const M4_FTW_D: c_int = 2;
const M4_FTW_DNR: c_int = 3;
const M4_FTW_NS: c_int = 4;
const M4_FTW_SL: c_int = 5;
const M4_FTW_SLN: c_int = 7;
const M4_FTW_DP: c_int = 6;
const M4_FTW_PHYS: c_int = 1;
const M4_FTW_MOUNT: c_int = 2;
const M4_FTW_CHDIR: c_int = 4;
const M4_FTW_DEPTH: c_int = 8;

#[repr(C)]
pub struct M4FTW {
    pub base: c_int,
    pub level: c_int,
}

#[repr(C)]
struct M4FtwHistory {
    chain: *const M4FtwHistory,
    dev: u64,
    ino: u64,
    level: c_int,
    base: c_int,
}

type M4FtwCallback = unsafe extern "C" fn(*const c_char, *const Stat, c_int) -> c_int;
type M4NftwCallback =
    unsafe extern "C" fn(*const c_char, *const Stat, c_int, *mut M4FTW) -> c_int;

struct M4FtwCallbacks {
    ftw: Option<M4FtwCallback>,
    nftw: Option<M4NftwCallback>,
}

unsafe fn m4_ftw_call(
    callbacks: &M4FtwCallbacks,
    path: *const c_char,
    st: *const Stat,
    kind: c_int,
    base: c_int,
    level: c_int,
) -> c_int {
    if let Some(callback) = callbacks.nftw {
        let mut info = M4FTW { base, level };
        callback(path, st, kind, &mut info)
    } else if let Some(callback) = callbacks.ftw {
        callback(path, st, kind)
    } else {
        M4_TRAVERSAL_EINVAL
    }
}

// FTW_CHDIR changes process state, so every exit path (including callback
// aborts and traversal errors) restores the descriptor saved on entry.
unsafe fn m4_ftw_restore_cwd(saved_fd: c_int, callback_result: c_int) -> c_int {
    if saved_fd < 0 {
        return callback_result;
    }
    let restored = fchdir(saved_fd);
    let closed = sys_close(saved_fd as i64);
    if restored != 0 {
        if callback_result != 0 {
            return callback_result;
        }
        return -1;
    }
    if closed < 0 {
        if callback_result != 0 {
            return callback_result;
        }
        ERRNO = (-closed) as c_int;
        return -1;
    }
    callback_result
}

unsafe fn m4_nftw_walk(
    path: *mut u8,
    io_path: *mut u8,
    callbacks: &M4FtwCallbacks,
    fd_limit: c_int,
    flags: c_int,
    history: *const M4FtwHistory,
) -> c_int {
    let length = strlen(path as *const c_char);
    let last = if length != 0 && *path.add(length - 1) == b'/' {
        length - 1
    } else {
        length
    };
    let io_length = strlen(io_path as *const c_char);
    let io_last = if io_length != 0 && *io_path.add(io_length - 1) == b'/' {
        io_length - 1
    } else {
        io_length
    };
    let mut st: Stat = core::mem::zeroed();
    let mut kind;
    let mut stat_errno = 0;
    let stat_result = if flags & M4_FTW_PHYS != 0 {
        lstat(io_path as *const c_char, &mut st)
    } else {
        stat(io_path as *const c_char, &mut st)
    };
    if stat_result != 0 {
        stat_errno = ERRNO;
        if flags & M4_FTW_PHYS == 0
            && stat_errno == M4_TRAVERSAL_ENOENT
            && lstat(io_path as *const c_char, &mut st) == 0
        {
            kind = M4_FTW_SLN;
        } else if stat_errno == M4_TRAVERSAL_EACCES {
            kind = M4_FTW_NS;
            st = core::mem::zeroed();
        } else {
            ERRNO = stat_errno;
            return -1;
        }
    } else if st.st_mode & S_IFMT == S_IFDIR {
        kind = if flags & M4_FTW_DEPTH != 0 {
            M4_FTW_DP
        } else {
            M4_FTW_D
        };
    } else if st.st_mode & S_IFMT == S_IFLNK {
        kind = if flags & M4_FTW_PHYS != 0 {
            M4_FTW_SL
        } else {
            M4_FTW_SLN
        };
    } else {
        kind = M4_FTW_F;
    }

    if flags & M4_FTW_MOUNT != 0
        && !history.is_null()
        && kind != M4_FTW_NS
        && st.st_dev != (*history).dev
    {
        return 0;
    }

    // musl keeps the root component's base offset for every callback in the
    // walk.  This is observable for relative roots and differs from the
    // offset of each child's final component.
    let base = if !history.is_null() {
        (*history).base
    } else {
        let mut base_cursor = last;
        while base_cursor != 0 && *path.add(base_cursor) == b'/' {
            base_cursor -= 1;
        }
        while base_cursor != 0 && *path.add(base_cursor - 1) != b'/' {
            base_cursor -= 1;
        }
        base_cursor as c_int
    };
    let level = if history.is_null() {
        0
    } else {
        (*history).level + 1
    };
    let current = M4FtwHistory {
        chain: history,
        dev: st.st_dev,
        ino: st.st_ino,
        level,
        base,
    };

    let mut saved_cwd: c_int = -1;
    if flags & M4_FTW_CHDIR != 0 && (kind == M4_FTW_D || kind == M4_FTW_DP) {
        let opened = sys_open(
            b".\0".as_ptr(),
            (O_RDONLY | M4_TRAVERSAL_O_DIRECTORY | O_CLOEXEC) as i64,
            0,
        );
        if opened < 0 {
            ERRNO = (-opened) as c_int;
            return -1;
        }
        saved_cwd = opened as c_int;
    }

    let mut directory_error = 0;
    if kind == M4_FTW_D || kind == M4_FTW_DP {
        // Probe readability before the pre-order callback.  The actual
        // entries are collected with scandir below, after the callback, so a
        // low fd_limit still traverses correctly without retaining a parent
        // directory descriptor across recursive calls.
        let directory = opendir(io_path as *const c_char);
        if directory.is_null() {
            directory_error = ERRNO;
            if directory_error == M4_TRAVERSAL_EACCES {
                kind = M4_FTW_DNR;
            }
        } else {
            if closedir(directory) != 0 {
                directory_error = ERRNO;
            }
        }
    }

    if saved_cwd >= 0 && (kind == M4_FTW_D || kind == M4_FTW_DP) && directory_error == 0 {
        if chdir(io_path as *const c_char) != 0 {
            return m4_ftw_restore_cwd(saved_cwd, -1);
        }
    }

    if flags & M4_FTW_DEPTH == 0 {
        let callback_result = m4_ftw_call(
            callbacks,
            path as *const c_char,
            &st,
            kind,
            base,
            level,
        );
        if callback_result != 0 {
            return m4_ftw_restore_cwd(saved_cwd, callback_result);
        }
        if saved_cwd >= 0 && (kind == M4_FTW_D || kind == M4_FTW_DP) {
            // A callback is allowed to change cwd.  Re-enter this directory
            // before reading its children, as FTW_CHDIR promises.
            if chdir(io_path as *const c_char) != 0 {
                return m4_ftw_restore_cwd(saved_cwd, -1);
            }
        }
    }

    let mut cursor = history;
    while !cursor.is_null() {
        if (*cursor).dev == st.st_dev && (*cursor).ino == st.st_ino {
            return m4_ftw_restore_cwd(saved_cwd, 0);
        }
        cursor = (*cursor).chain;
    }

    if (kind == M4_FTW_D || kind == M4_FTW_DP) && fd_limit > 0 {
        if directory_error != 0 {
            ERRNO = directory_error;
            return m4_ftw_restore_cwd(saved_cwd, -1);
        }
        let mut entries: *mut *mut M4Dirent = core::ptr::null_mut();
        let entry_count = scandir(
            io_path as *const c_char,
            &mut entries,
            None,
            None,
        );
        if entry_count < 0 {
            return m4_ftw_restore_cwd(saved_cwd, -1);
        }
        let mut entry_index = 0usize;
        while entry_index < entry_count as usize {
            let entry = *entries.add(entry_index);
            let name = (*entry).d_name.as_ptr() as *const u8;
            let skip = *name == b'.'
                && (*name.add(1) == 0
                    || (*name.add(1) == b'.' && *name.add(2) == 0));
            if !skip {
                let name_length = strlen(name as *const c_char);
                if name_length >= M4_TRAVERSAL_PATH_MAX.saturating_sub(length)
                    || name_length >= M4_TRAVERSAL_PATH_MAX.saturating_sub(io_length)
                {
                    m4_scandir_free(entries, entry_count as usize);
                    ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
                    return m4_ftw_restore_cwd(saved_cwd, -1);
                }
                if saved_cwd >= 0 && chdir(io_path as *const c_char) != 0 {
                    m4_scandir_free(entries, entry_count as usize);
                    return m4_ftw_restore_cwd(saved_cwd, -1);
                }
                *path.add(last) = b'/';
                core::ptr::copy_nonoverlapping(name, path.add(last + 1), name_length + 1);
                *io_path.add(io_last) = b'/';
                core::ptr::copy_nonoverlapping(
                    name,
                    io_path.add(io_last + 1),
                    name_length + 1,
                );
                let child_result = m4_nftw_walk(
                    path,
                    io_path,
                    callbacks,
                    fd_limit,
                    flags,
                    &current,
                );
                *path.add(length) = 0;
                *io_path.add(io_length) = 0;
                if child_result != 0 {
                    m4_scandir_free(entries, entry_count as usize);
                    return m4_ftw_restore_cwd(saved_cwd, child_result);
                }
            }
            entry_index += 1;
        }
        m4_scandir_free(entries, entry_count as usize);
    }

    *path.add(length) = 0;
    if flags & M4_FTW_DEPTH != 0 {
        if saved_cwd >= 0 && (kind == M4_FTW_D || kind == M4_FTW_DP)
            && chdir(io_path as *const c_char) != 0
        {
            return m4_ftw_restore_cwd(saved_cwd, -1);
        }
        let callback_result = m4_ftw_call(
            callbacks,
            path as *const c_char,
            &st,
            kind,
            base,
            level,
        );
        if callback_result != 0 {
            return m4_ftw_restore_cwd(saved_cwd, callback_result);
        }
    }
    let _ = stat_errno;
    m4_ftw_restore_cwd(saved_cwd, 0)
}

// With FTW_CHDIR, filesystem operations must remain independent of the
// process cwd that the walk changes.  Relative caller paths therefore get an
// absolute I/O spelling while the original relative spelling remains the
// callback argument.
unsafe fn m4_ftw_prepare_io_path(
    path: *const c_char,
    output: *mut u8,
) -> Result<(), c_int> {
    let length = strlen(path);
    if *path as u8 == b'/' || length == 0 {
        if length + 1 > M4_TRAVERSAL_IO_PATH_MAX {
            return Err(M4_TRAVERSAL_ENAMETOOLONG);
        }
        core::ptr::copy_nonoverlapping(path as *const u8, output, length + 1);
        return Ok(());
    }

    let mut cwd = [0u8; M4_TRAVERSAL_PATH_MAX + 1];
    if getcwd(cwd.as_mut_ptr() as *mut c_char, cwd.len()).is_null() {
        return Err(if ERRNO != 0 { ERRNO } else { M4_TRAVERSAL_EINVAL });
    }
    let cwd_length = strlen(cwd.as_ptr() as *const c_char);
    if cwd_length
        .checked_add(1)
        .and_then(|n| n.checked_add(length))
        .and_then(|n| n.checked_add(1))
        .map_or(true, |n| n > M4_TRAVERSAL_IO_PATH_MAX)
    {
        return Err(M4_TRAVERSAL_ENAMETOOLONG);
    }
    core::ptr::copy_nonoverlapping(cwd.as_ptr(), output, cwd_length);
    *output.add(cwd_length) = b'/';
    core::ptr::copy_nonoverlapping(
        path as *const u8,
        output.add(cwd_length + 1),
        length + 1,
    );
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn nftw(
    path: *const c_char,
    callback: Option<M4NftwCallback>,
    fd_limit: c_int,
    flags: c_int,
) -> c_int {
    if path.is_null() || callback.is_none() {
        ERRNO = M4_TRAVERSAL_EINVAL;
        return -1;
    }
    if fd_limit <= 0 {
        return 0;
    }
    let length = strlen(path);
    if length > M4_TRAVERSAL_PATH_MAX {
        ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
        return -1;
    }
    let mut pathbuf = [0u8; M4_TRAVERSAL_PATH_MAX + 1];
    core::ptr::copy_nonoverlapping(path as *const u8, pathbuf.as_mut_ptr(), length + 1);
    let mut io_pathbuf = [0u8; M4_TRAVERSAL_IO_PATH_MAX];
    let io_path = if flags & M4_FTW_CHDIR != 0 {
        if let Err(error) = m4_ftw_prepare_io_path(path, io_pathbuf.as_mut_ptr()) {
            ERRNO = error;
            return -1;
        }
        io_pathbuf.as_mut_ptr()
    } else {
        pathbuf.as_mut_ptr()
    };
    let callbacks = M4FtwCallbacks {
        ftw: None,
        nftw: callback,
    };
    m4_nftw_walk(
        pathbuf.as_mut_ptr(),
        io_path,
        &callbacks,
        fd_limit,
        flags,
        core::ptr::null(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn ftw(
    path: *const c_char,
    callback: Option<M4FtwCallback>,
    fd_limit: c_int,
) -> c_int {
    if path.is_null() || callback.is_none() {
        ERRNO = M4_TRAVERSAL_EINVAL;
        return -1;
    }
    if fd_limit <= 0 {
        return 0;
    }
    let length = strlen(path);
    if length > M4_TRAVERSAL_PATH_MAX {
        ERRNO = M4_TRAVERSAL_ENAMETOOLONG;
        return -1;
    }
    let mut pathbuf = [0u8; M4_TRAVERSAL_PATH_MAX + 1];
    core::ptr::copy_nonoverlapping(path as *const u8, pathbuf.as_mut_ptr(), length + 1);
    let callbacks = M4FtwCallbacks {
        ftw: callback,
        nftw: None,
    };
    m4_nftw_walk(
        pathbuf.as_mut_ptr(),
        pathbuf.as_mut_ptr(),
        &callbacks,
        fd_limit,
        M4_FTW_PHYS,
        core::ptr::null(),
    )
}
