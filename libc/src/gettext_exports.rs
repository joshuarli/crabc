// gettext/libintl interfaces.
//
// musl's gettext implementation has two useful properties even when no
// message catalog is available: the non-plural forms return their msgid, and
// the plural forms select msgid1 only for n == 1.  Keep the domain and
// directory state real so callers can configure and query it; catalog parsing
// remains outside this bounded slice because crabc currently exposes only its
// built-in C/POSIX locale data.

const CABI_GETTEXT_NAME_MAX: usize = 255;
const CABI_GETTEXT_PATH_MAX: usize = 4096;

static CABI_GETTEXT_MESSAGES: [u8; 9] = *b"messages\0";
static CABI_GETTEXT_UTF8: [u8; 6] = *b"UTF-8\0";

#[repr(C)]
struct CabiGettextBinding {
    next: *mut CabiGettextBinding,
    domainname: *mut c_char,
    dirname: *mut c_char,
    active: c_int,
}

static CABI_GETTEXT_LOCK: AtomicI32 = AtomicI32::new(0);
static mut CABI_GETTEXT_BINDINGS: *mut CabiGettextBinding = null_mut();
static mut CABI_GETTEXT_CURRENT_DOMAIN: *mut c_char = null_mut();

unsafe fn cabi_gettext_lock() {
    while CABI_GETTEXT_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

fn cabi_gettext_unlock() {
    CABI_GETTEXT_LOCK.store(0, Ordering::Release);
}

unsafe fn cabi_gettext_bounded_len(s: *const c_char, limit: usize) -> usize {
    let mut len = 0;
    while len < limit && *s.add(len) != 0 {
        len += 1;
    }
    len
}

unsafe fn cabi_gettext_equal(left: *const c_char, right: *const c_char) -> bool {
    let mut i = 0;
    loop {
        let l = *left.add(i);
        let r = *right.add(i);
        if l != r {
            return false;
        }
        if l == 0 {
            return true;
        }
        i += 1;
    }
}

unsafe fn cabi_gettext_domain() -> *mut c_char {
    if CABI_GETTEXT_CURRENT_DOMAIN.is_null() {
        CABI_GETTEXT_MESSAGES.as_ptr() as *mut c_char
    } else {
        CABI_GETTEXT_CURRENT_DOMAIN
    }
}

unsafe fn cabi_gettext_binding(
    domainname: *const c_char,
    dirname: Option<*const c_char>,
) -> *mut CabiGettextBinding {
    let mut binding = CABI_GETTEXT_BINDINGS;
    while !binding.is_null() {
        if cabi_gettext_equal((*binding).domainname, domainname) {
            match dirname {
                Some(dir) if cabi_gettext_equal((*binding).dirname, dir) => return binding,
                None if (*binding).active != 0 => return binding,
                _ => {}
            }
        }
        binding = (*binding).next;
    }
    null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn textdomain(domainname: *const c_char) -> *mut c_char {
    if domainname.is_null() {
        return cabi_gettext_domain();
    }

    // musl accepts the empty domain and rejects names longer than NAME_MAX.
    let domain_len = cabi_gettext_bounded_len(domainname, CABI_GETTEXT_NAME_MAX + 1);
    if domain_len > CABI_GETTEXT_NAME_MAX {
        ERRNO = EINVAL;
        return null_mut();
    }

    cabi_gettext_lock();
    if CABI_GETTEXT_CURRENT_DOMAIN.is_null() {
        CABI_GETTEXT_CURRENT_DOMAIN = malloc(CABI_GETTEXT_NAME_MAX + 1) as *mut c_char;
        if CABI_GETTEXT_CURRENT_DOMAIN.is_null() {
            cabi_gettext_unlock();
            return null_mut();
        }
    }
    core::ptr::copy_nonoverlapping(
        domainname as *const u8,
        CABI_GETTEXT_CURRENT_DOMAIN as *mut u8,
        domain_len + 1,
    );
    let result = CABI_GETTEXT_CURRENT_DOMAIN;
    cabi_gettext_unlock();
    result
}

#[no_mangle]
pub unsafe extern "C" fn bindtextdomain(
    domainname: *const c_char,
    dirname: *const c_char,
) -> *mut c_char {
    if domainname.is_null() {
        return null_mut();
    }

    cabi_gettext_lock();

    // A null directory is the musl query form and must not create a binding.
    if dirname.is_null() {
        let binding = cabi_gettext_binding(domainname, None);
        let result = if !binding.is_null() && (*binding).active != 0 {
            (*binding).dirname
        } else {
            null_mut()
        };
        cabi_gettext_unlock();
        return result;
    }

    let domain_len = cabi_gettext_bounded_len(domainname, CABI_GETTEXT_NAME_MAX + 1);
    let dir_len = cabi_gettext_bounded_len(dirname, CABI_GETTEXT_PATH_MAX);
    if domain_len > CABI_GETTEXT_NAME_MAX || dir_len >= CABI_GETTEXT_PATH_MAX {
        ERRNO = EINVAL;
        cabi_gettext_unlock();
        return null_mut();
    }

    let binding = cabi_gettext_binding(domainname, Some(dirname));
    let binding = if binding.is_null() {
        let header_size = core::mem::size_of::<CabiGettextBinding>();
        let bytes = header_size + domain_len + dir_len + 2;
        let fresh = malloc(bytes) as *mut CabiGettextBinding;
        if fresh.is_null() {
            cabi_gettext_unlock();
            return null_mut();
        }
        let strings = (fresh as *mut u8).add(header_size);
        let fresh_domain = strings as *mut c_char;
        let fresh_dirname = strings.add(domain_len + 1) as *mut c_char;
        fresh.write(CabiGettextBinding {
            next: CABI_GETTEXT_BINDINGS,
            domainname: fresh_domain,
            dirname: fresh_dirname,
            active: 1,
        });
        core::ptr::copy_nonoverlapping(
            domainname as *const u8,
            fresh_domain as *mut u8,
            domain_len + 1,
        );
        core::ptr::copy_nonoverlapping(
            dirname as *const u8,
            fresh_dirname as *mut u8,
            dir_len + 1,
        );
        CABI_GETTEXT_BINDINGS = fresh;
        fresh
    } else {
        binding
    };

    // Rebinding a domain makes its previous directory inactive while keeping
    // old allocations alive, just as musl does for pointers returned earlier.
    let mut current = CABI_GETTEXT_BINDINGS;
    while !current.is_null() {
        if cabi_gettext_equal((*current).domainname, domainname) {
            (*current).active = if current == binding { 1 } else { 0 };
        }
        current = (*current).next;
    }

    let result = (*binding).dirname;
    cabi_gettext_unlock();
    result
}

#[no_mangle]
pub unsafe extern "C" fn bind_textdomain_codeset(
    _domainname: *const c_char,
    codeset: *const c_char,
) -> *mut c_char {
    // musl's locale data is UTF-8.  Its implementation accepts a null
    // codeset (query) and any case spelling of UTF-8, returning this static
    // string; other encodings are rejected with EINVAL.
    if !codeset.is_null()
        && strcasecmp(codeset as *const u8, CABI_GETTEXT_UTF8.as_ptr()) != 0
    {
        ERRNO = EINVAL;
        return null_mut();
    }
    CABI_GETTEXT_UTF8.as_ptr() as *mut c_char
}

unsafe fn cabi_gettext_plural_fallback(
    msgid1: *const c_char,
    msgid2: *const c_char,
    n: c_ulong,
) -> *mut c_char {
    if n == 1 {
        msgid1 as *mut c_char
    } else {
        msgid2 as *mut c_char
    }
}

#[no_mangle]
pub unsafe extern "C" fn dcngettext(
    domainname: *const c_char,
    msgid1: *const c_char,
    msgid2: *const c_char,
    n: c_ulong,
    category: c_int,
) -> *mut c_char {
    // The identity fallback is also the exact musl result when no catalog is
    // found.  Validate the same inputs before taking that path and preserve
    // errno across all gettext lookups.
    let old_errno = ERRNO;
    if msgid1.is_null() || (category as c_uint) >= LC_ALL as c_uint {
        let result = cabi_gettext_plural_fallback(msgid1, msgid2, n);
        ERRNO = old_errno;
        return result;
    }

    let domain = if domainname.is_null() {
        cabi_gettext_domain()
    } else {
        domainname as *mut c_char
    };
    if cabi_gettext_bounded_len(domain, CABI_GETTEXT_NAME_MAX + 1) > CABI_GETTEXT_NAME_MAX {
        let result = cabi_gettext_plural_fallback(msgid1, msgid2, n);
        ERRNO = old_errno;
        return result;
    }

    // Catalog loading is intentionally deferred, so both the bound and
    // unbound paths use musl's identity fallback.
    let result = cabi_gettext_plural_fallback(msgid1, msgid2, n);
    ERRNO = old_errno;
    result
}

#[no_mangle]
pub unsafe extern "C" fn dcgettext(
    domainname: *const c_char,
    msgid: *const c_char,
    category: c_int,
) -> *mut c_char {
    dcngettext(domainname, msgid, null_mut(), 1, category)
}

#[no_mangle]
pub unsafe extern "C" fn dgettext(
    domainname: *const c_char,
    msgid: *const c_char,
) -> *mut c_char {
    dcngettext(domainname, msgid, null_mut(), 1, LC_MESSAGES)
}

#[no_mangle]
pub unsafe extern "C" fn dngettext(
    domainname: *const c_char,
    msgid1: *const c_char,
    msgid2: *const c_char,
    n: c_ulong,
) -> *mut c_char {
    dcngettext(domainname, msgid1, msgid2, n, LC_MESSAGES)
}

#[no_mangle]
pub unsafe extern "C" fn gettext(msgid: *const c_char) -> *mut c_char {
    dgettext(null_mut(), msgid)
}

#[no_mangle]
pub unsafe extern "C" fn ngettext(
    msgid1: *const c_char,
    msgid2: *const c_char,
    n: c_ulong,
) -> *mut c_char {
    dngettext(null_mut(), msgid1, msgid2, n)
}
