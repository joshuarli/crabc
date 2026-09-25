//! Bounded static Linux/x86-64 gettext and message-catalog ABI boundary.
//!
//! This leaf owns the installed `<libintl.h>` and `<nl_types.h>` entry points,
//! but not a general localization subsystem. `gettext` and its domain/plural
//! variants preserve musl's no-catalog identity fallback; the codeset entry
//! accepts only UTF-8; and the message-catalog entry points are an explicit
//! no-catalog profile. `catopen` always reports `ENOENT`, `catgets` returns
//! its caller default, and `catclose` owns no mapping.
//!
//! Domain and binding state has two storage owners selected at build time:
//!
//! - Installed owned products (`crabc_x86_owned_runtime`) keep musl's
//!   ownership exactly. `textdomain` obtains its NAME_MAX+1 current-domain
//!   buffer from public `malloc` once, and `bindtextdomain` prepends unbounded
//!   permanent records from the private `__libc_calloc`-shaped seam, so an
//!   executable's malloc-family replacement observes the same calls as musl.
//! - The frozen dependency-free selected-static archive has no C allocator.
//!   It retains one fixed current-domain buffer and at most four permanent
//!   binding records.
//!
//! The local lock serializes calls through this selected leaf. It does not
//! make direct use of a returned domain/directory pointer concurrent with a
//! later selected mutation, recover a lock across fork, or make these APIs
//! async-signal-safe. Callers must externally serialize those cases. Binding
//! records are never reused, so a directory pointer returned by a successful
//! binding remains backed by this archive until process exit.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/locale/dcngettext.c` supplies the identity fallback, singular
//!   selection, errno preservation, and domain/binding shape.
//! - `src/locale/textdomain.c` supplies the default `messages` domain and
//!   NAME_MAX validation.
//! - `src/locale/bind_textdomain_codeset.c` supplies UTF-8-only codeset
//!   behavior, and `dcngettext.c` supplies binding activation.
//! - `src/locale/{catopen,catgets,catclose}.c` supplies the public catalog
//!   signatures and ordinary error/default conventions.
//!
//! Musl's full path also consults locale and environment state, loads/mmap's
//! `.mo` and message-catalog files, and parses plural expressions. This leaf
//! deliberately selects none of those mechanisms: there is no
//! catalog-file/NLSPATH/LANG lookup, locale database, plural parser, mmap,
//! dynamic TLS, loader, or general gettext framework. The supported locales
//! name no message catalog, so musl's own lookup would also reach its
//! identity fallback. In the allocator-free archive the fixed four-binding
//! capacity reports `ENOMEM` before state changes. This is not general
//! gettext/catalog parity, family completion, promotion, or public x86
//! support.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 static gettext/catalog leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::hint::spin_loop;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use super::errno;

const EINVAL: c_int = 22;
#[cfg(not(crabc_x86_owned_runtime))]
const ENOMEM: c_int = 12;
const ENOENT: c_int = 2;
const DOMAIN_CAPACITY: usize = 256;
const MAX_DOMAIN_LENGTH: usize = DOMAIN_CAPACITY - 1;
const DIRECTORY_CAPACITY: usize = 4_096;
// musl calls strnlen(dirname, PATH_MAX) then rejects a result >= PATH_MAX.
const MAX_DIRECTORY_LENGTH: usize = DIRECTORY_CAPACITY - 1;
static DEFAULT_DOMAIN: [u8; 9] = *b"messages\0";
static UTF8_CODESET: [u8; 6] = *b"UTF-8\0";

static CATALOG_LOCK: AtomicBool = AtomicBool::new(false);

/// Artifact-local state lock.
///
/// All selected state accesses happen while this guard is live. Direct C
/// users of returned mutable pointers remain outside that narrow guarantee.
struct CatalogLock;

impl CatalogLock {
    #[inline]
    fn acquire() -> Self {
        while CATALOG_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        Self
    }
}

impl Drop for CatalogLock {
    #[inline]
    fn drop(&mut self) {
        CATALOG_LOCK.store(false, Ordering::Release);
    }
}

#[inline]
unsafe fn bytes_at_most(value: *const c_char, maximum: usize) -> Option<usize> {
    if value.is_null() {
        return None;
    }
    for length in 0..=maximum {
        // SAFETY: the ordinary C ABI requires a readable NUL-terminated
        // string. The bounded scan avoids accepting a string beyond this
        // selected static record capacity.
        if unsafe { value.cast::<u8>().add(length).read() } == 0 {
            return Some(length);
        }
    }
    None
}

#[inline]
unsafe fn copy_c_string(destination: *mut u8, source: *const c_char, length: usize) {
    // `textdomain` may receive its own retained buffer. Preserve that exact
    // self-copy without selecting a compiler-lowered memcpy/memmove seam.
    if source.cast::<u8>() == destination {
        return;
    }
    for index in 0..=length {
        // The public C contract supplies a valid NUL-terminated source; all
        // selected destinations have the checked inclusive capacity above.
        unsafe { destination.add(index).write(source.cast::<u8>().add(index).read()) };
    }
}

#[inline]
unsafe fn string_matches(
    stored: *const u8,
    stored_length: usize,
    value: *const c_char,
    value_length: usize,
) -> bool {
    if stored_length != value_length {
        return false;
    }
    for index in 0..=stored_length {
        // SAFETY: both byte sequences have a checked trailing NUL at this
        // exact inclusive bound.
        if unsafe { stored.add(index).read() } != unsafe { value.cast::<u8>().add(index).read() }
        {
            return false;
        }
    }
    true
}

/// Musl-owned domain and binding storage for installed owned products.
///
/// Every function requires the caller to hold [`CatalogLock`].
#[cfg(crabc_x86_owned_runtime)]
mod state {
    use core::ffi::{c_char, c_int, c_void};
    use core::mem::size_of;
    use core::ptr::{self, null_mut};

    use super::{copy_c_string, string_matches, DEFAULT_DOMAIN, DOMAIN_CAPACITY};

    // Pinned `textdomain.c` calls public `malloc`, which musl keeps
    // preemptible in libc.so. Keep the call at the ELF lookup boundary so LTO
    // cannot bind it directly to this crate's allocator definition.
    core::arch::global_asm!(
        r#"
    .text
    .p2align 4
    .globl __crabc_x86_textdomain_cabi_malloc
    .hidden __crabc_x86_textdomain_cabi_malloc
    .type __crabc_x86_textdomain_cabi_malloc,@function
__crabc_x86_textdomain_cabi_malloc:
    jmp malloc
    .size __crabc_x86_textdomain_cabi_malloc, .-__crabc_x86_textdomain_cabi_malloc
"#
    );

    unsafe extern "C" {
        #[link_name = "__crabc_x86_textdomain_cabi_malloc"]
        fn domain_malloc(size: usize) -> *mut c_void;
    }

    /// Musl's `struct binding` header; the domain and directory bytes follow.
    #[repr(C)]
    struct Binding {
        next: *mut Binding,
        directory_length: c_int,
        active: c_int,
        domain: *mut c_char,
        directory: *mut c_char,
    }

    const _: () = assert!(size_of::<Binding>() == 32);

    static mut CURRENT_DOMAIN: *mut c_char = null_mut();
    static mut BINDINGS: *mut Binding = null_mut();

    #[inline]
    unsafe fn c_length(value: *const c_char) -> usize {
        let mut length = 0usize;
        // SAFETY: stored records hold NUL-terminated strings they own.
        while unsafe { value.cast::<u8>().add(length).read() } != 0 {
            length += 1;
        }
        length
    }

    #[inline]
    unsafe fn same(stored: *const c_char, value: *const c_char, length: usize) -> bool {
        unsafe { string_matches(stored.cast::<u8>(), c_length(stored), value, length) }
    }

    pub(super) unsafe fn current_domain() -> *mut c_char {
        let current = unsafe { ptr::addr_of!(CURRENT_DOMAIN).read() };
        if current.is_null() {
            DEFAULT_DOMAIN.as_ptr().cast_mut().cast::<c_char>()
        } else {
            current
        }
    }

    /// Copy one validated domain into musl's lazily allocated buffer.
    ///
    /// A failed first allocation returns null with the allocator's errno.
    pub(super) unsafe fn set_current_domain(domain: *const c_char, length: usize) -> *mut c_char {
        let mut current = unsafe { ptr::addr_of!(CURRENT_DOMAIN).read() };
        if current.is_null() {
            // SAFETY: the tail forwards musl's NAME_MAX+1 request to `malloc`.
            current = unsafe { domain_malloc(DOMAIN_CAPACITY) }.cast::<c_char>();
            if current.is_null() {
                return null_mut();
            }
            unsafe { ptr::addr_of_mut!(CURRENT_DOMAIN).write(current) };
        }
        // SAFETY: `length` is at most NAME_MAX, so the inclusive NUL fits.
        unsafe { copy_c_string(current.cast::<u8>(), domain, length) };
        current
    }

    pub(super) unsafe fn active_directory(domain: *const c_char, length: usize) -> *mut c_char {
        let mut binding = unsafe { ptr::addr_of!(BINDINGS).read() };
        while !binding.is_null() {
            // SAFETY: records are permanent and only mutated under the lock.
            unsafe {
                if (*binding).active != 0 && same((*binding).domain, domain, length) {
                    return (*binding).directory;
                }
                binding = (*binding).next;
            }
        }
        null_mut()
    }

    /// Find or prepend one permanent binding, then make it the domain's sole
    /// active record, exactly as musl's `bindtextdomain`.
    pub(super) unsafe fn bind(
        domain: *const c_char,
        domain_length: usize,
        directory: *const c_char,
        directory_length: usize,
    ) -> *mut c_char {
        let mut selected = unsafe { ptr::addr_of!(BINDINGS).read() };
        while !selected.is_null() {
            unsafe {
                if same((*selected).domain, domain, domain_length)
                    && same((*selected).directory, directory, directory_length)
                {
                    break;
                }
                selected = (*selected).next;
            }
        }
        if selected.is_null() {
            let bytes = size_of::<Binding>() + domain_length + directory_length + 2;
            // SAFETY: musl's `__libc_calloc` seam; records are never freed.
            selected = unsafe { super::super::allocator::allocate_zeroed_internal(bytes) }.cast::<Binding>();
            if selected.is_null() {
                return null_mut();
            }
            unsafe {
                let strings = selected.cast::<u8>().add(size_of::<Binding>());
                let stored_domain = strings.cast::<c_char>();
                let stored_directory = strings.add(domain_length + 1).cast::<c_char>();
                copy_c_string(stored_domain.cast::<u8>(), domain, domain_length);
                copy_c_string(stored_directory.cast::<u8>(), directory, directory_length);
                selected.write(Binding {
                    next: ptr::addr_of!(BINDINGS).read(),
                    directory_length: directory_length as c_int,
                    active: 0,
                    domain: stored_domain,
                    directory: stored_directory,
                });
                ptr::addr_of_mut!(BINDINGS).write(selected);
            }
        }
        unsafe { (*selected).active = 1 };
        let mut other = unsafe { ptr::addr_of!(BINDINGS).read() };
        while !other.is_null() {
            unsafe {
                if other != selected && same((*other).domain, domain, domain_length) {
                    (*other).active = 0;
                }
                other = (*other).next;
            }
        }
        unsafe { (*selected).directory }
    }
}

/// Fixed domain and binding storage for the allocator-free selected archive.
///
/// Every function requires the caller to hold [`CatalogLock`].
#[cfg(not(crabc_x86_owned_runtime))]
mod state {
    use core::ffi::c_char;
    use core::ptr::{self, null_mut};

    use super::{copy_c_string, errno, string_matches, DEFAULT_DOMAIN, DIRECTORY_CAPACITY, DOMAIN_CAPACITY, ENOMEM};

    pub(super) const BINDING_CAPACITY: usize = 4;

    static mut CURRENT_DOMAIN_SET: bool = false;
    static mut CURRENT_DOMAIN: [u8; DOMAIN_CAPACITY] = [0; DOMAIN_CAPACITY];

    #[derive(Clone, Copy)]
    struct Binding {
        used: bool,
        active: bool,
        domain_length: usize,
        directory_length: usize,
        domain: [u8; DOMAIN_CAPACITY],
        directory: [u8; DIRECTORY_CAPACITY],
    }

    const EMPTY_BINDING: Binding = Binding {
        used: false,
        active: false,
        domain_length: 0,
        directory_length: 0,
        domain: [0; DOMAIN_CAPACITY],
        directory: [0; DIRECTORY_CAPACITY],
    };

    static mut BINDINGS: [Binding; BINDING_CAPACITY] = [EMPTY_BINDING; BINDING_CAPACITY];

    #[inline]
    unsafe fn binding_at(index: usize) -> *mut Binding {
        debug_assert!(index < BINDING_CAPACITY);
        // SAFETY: callers retain the checked fixed array index and the state lock.
        unsafe { ptr::addr_of_mut!(BINDINGS).cast::<Binding>().add(index) }
    }

    #[inline]
    unsafe fn binding_domain_matches(
        binding: *mut Binding,
        domain: *const c_char,
        domain_length: usize,
    ) -> bool {
        // SAFETY: callers hold the state lock and `binding` addresses this fixed
        // array. A non-used record has no matching domain.
        if !unsafe { ptr::addr_of!((*binding).used).read() } {
            return false;
        }
        let stored_length = unsafe { ptr::addr_of!((*binding).domain_length).read() };
        let stored = ptr::addr_of!((*binding).domain).cast::<u8>();
        unsafe { string_matches(stored, stored_length, domain, domain_length) }
    }

    #[inline]
    unsafe fn binding_pair_matches(
        binding: *mut Binding,
        domain: *const c_char,
        domain_length: usize,
        directory: *const c_char,
        directory_length: usize,
    ) -> bool {
        if !unsafe { binding_domain_matches(binding, domain, domain_length) } {
            return false;
        }
        let stored_length = unsafe { ptr::addr_of!((*binding).directory_length).read() };
        let stored = ptr::addr_of!((*binding).directory).cast::<u8>();
        unsafe { string_matches(stored, stored_length, directory, directory_length) }
    }

    #[inline]
    unsafe fn binding_directory_pointer(binding: *mut Binding) -> *mut c_char {
        unsafe { ptr::addr_of_mut!((*binding).directory).cast::<c_char>() }
    }

    pub(super) unsafe fn current_domain() -> *mut c_char {
        if unsafe { ptr::addr_of!(CURRENT_DOMAIN_SET).read() } {
            ptr::addr_of_mut!(CURRENT_DOMAIN).cast::<c_char>()
        } else {
            DEFAULT_DOMAIN.as_ptr().cast_mut().cast::<c_char>()
        }
    }

    pub(super) unsafe fn set_current_domain(domain: *const c_char, length: usize) -> *mut c_char {
        unsafe {
            copy_c_string(ptr::addr_of_mut!(CURRENT_DOMAIN).cast::<u8>(), domain, length);
            ptr::addr_of_mut!(CURRENT_DOMAIN_SET).write(true);
            current_domain()
        }
    }

    pub(super) unsafe fn active_directory(domain: *const c_char, length: usize) -> *mut c_char {
        for index in 0..BINDING_CAPACITY {
            let binding = unsafe { binding_at(index) };
            if unsafe { binding_domain_matches(binding, domain, length) }
                && unsafe { ptr::addr_of!((*binding).active).read() }
            {
                return unsafe { binding_directory_pointer(binding) };
            }
        }
        null_mut()
    }

    pub(super) unsafe fn bind(
        domainname: *const c_char,
        domain_length: usize,
        dirname: *const c_char,
        directory_length: usize,
    ) -> *mut c_char {
        let mut matched = None;
        let mut vacant = None;
        for index in 0..BINDING_CAPACITY {
            let binding = unsafe { binding_at(index) };
            if unsafe { !ptr::addr_of!((*binding).used).read() } {
                if vacant.is_none() {
                    vacant = Some(index);
                }
                continue;
            }
            if unsafe {
                binding_pair_matches(
                    binding,
                    domainname,
                    domain_length,
                    dirname,
                    directory_length,
                )
            } {
                matched = Some(index);
                break;
            }
        }

        let selected = if let Some(index) = matched {
            index
        } else if let Some(index) = vacant {
            let binding = unsafe { binding_at(index) };
            unsafe {
                copy_c_string(
                    ptr::addr_of_mut!((*binding).domain).cast::<u8>(),
                    domainname,
                    domain_length,
                );
                copy_c_string(
                    ptr::addr_of_mut!((*binding).directory).cast::<u8>(),
                    dirname,
                    directory_length,
                );
                ptr::addr_of_mut!((*binding).domain_length).write(domain_length);
                ptr::addr_of_mut!((*binding).directory_length).write(directory_length);
                ptr::addr_of_mut!((*binding).used).write(true);
            }
            index
        } else {
            unsafe { errno::set_errno(ENOMEM) };
            return null_mut();
        };

        for index in 0..BINDING_CAPACITY {
            let binding = unsafe { binding_at(index) };
            if index != selected
                && unsafe { binding_domain_matches(binding, domainname, domain_length) }
            {
                unsafe { ptr::addr_of_mut!((*binding).active).write(false) };
            }
        }
        let binding = unsafe { binding_at(selected) };
        unsafe {
            ptr::addr_of_mut!((*binding).active).write(true);
            binding_directory_pointer(binding)
        }
    }
}

#[inline]
unsafe fn ascii_case_equal_utf8(codeset: *const c_char) -> bool {
    if codeset.is_null() {
        return true;
    }
    for (index, expected) in UTF8_CODESET.iter().enumerate() {
        let actual = unsafe { codeset.cast::<u8>().add(index).read() };
        let folded = if actual.is_ascii_uppercase() {
            actual + (b'a' - b'A')
        } else {
            actual
        };
        let expected = if expected.is_ascii_uppercase() {
            *expected + (b'a' - b'A')
        } else {
            *expected
        };
        if folded != expected {
            return false;
        }
    }
    true
}

// Musl's `src/locale/textdomain.c` object.
static_archive_member! { textdomain_source {
    /// Select or query the process's bounded gettext domain.
    #[no_mangle]
    pub unsafe extern "C" fn textdomain(domainname: *const c_char) -> *mut c_char {
        let Some(length) = (if domainname.is_null() {
            Some(0)
        } else {
            unsafe { bytes_at_most(domainname, MAX_DOMAIN_LENGTH) }
        }) else {
            unsafe { errno::set_errno(EINVAL) };
            return null_mut();
        };
        let _lock = CatalogLock::acquire();
        if domainname.is_null() {
            return unsafe { state::current_domain() };
        }
        unsafe { state::set_current_domain(domainname, length) }
    }

    /// Return an identity translation for the current domain.
    #[no_mangle]
    pub unsafe extern "C" fn gettext(msgid: *const c_char) -> *mut c_char {
        unsafe { dcngettext(null_mut(), msgid, null_mut(), 1, 5) }
    }

    /// Return the no-catalog singular/plural fallback for the current domain.
    #[no_mangle]
    pub unsafe extern "C" fn ngettext(
        msgid1: *const c_char,
        msgid2: *const c_char,
        number: c_ulong,
    ) -> *mut c_char {
        unsafe { dcngettext(null_mut(), msgid1, msgid2, number, 5) }
    }
}}

// Musl's `src/locale/dcngettext.c` object.
static_archive_member! { dcngettext_source {
    /// Set or query one bounded permanent gettext domain binding.
    #[no_mangle]
    pub unsafe extern "C" fn bindtextdomain(
        domainname: *const c_char,
        dirname: *const c_char,
    ) -> *mut c_char {
        if domainname.is_null() {
            return null_mut();
        }

        // A null dirname is musl's query path. A domain longer than any record can
        // never match, but unlike the mutation path it does not publish EINVAL.
        if dirname.is_null() {
            let Some(domain_length) = (unsafe { bytes_at_most(domainname, MAX_DOMAIN_LENGTH) }) else {
                return null_mut();
            };
            let _lock = CatalogLock::acquire();
            return unsafe { state::active_directory(domainname, domain_length) };
        }

        let Some(domain_length) = (unsafe { bytes_at_most(domainname, MAX_DOMAIN_LENGTH) }) else {
            unsafe { errno::set_errno(EINVAL) };
            return null_mut();
        };
        let Some(directory_length) = (unsafe { bytes_at_most(dirname, MAX_DIRECTORY_LENGTH) }) else {
            unsafe { errno::set_errno(EINVAL) };
            return null_mut();
        };

        let _lock = CatalogLock::acquire();
        unsafe { state::bind(domainname, domain_length, dirname, directory_length) }
    }

    /// Return the no-catalog singular/plural fallback without changing errno.
    #[no_mangle]
    pub unsafe extern "C" fn dcngettext(
        _domainname: *const c_char,
        msgid1: *const c_char,
        msgid2: *const c_char,
        number: c_ulong,
        _category: c_int,
    ) -> *mut c_char {
        if number == 1 {
            msgid1.cast_mut()
        } else {
            msgid2.cast_mut()
        }
    }

    /// Return an identity translation for one explicit domain.
    #[no_mangle]
    pub unsafe extern "C" fn dgettext(
        domainname: *const c_char,
        msgid: *const c_char,
    ) -> *mut c_char {
        unsafe { dcngettext(domainname, msgid, null_mut(), 1, 5) }
    }

    /// Return an identity translation for one explicit category.
    #[no_mangle]
    pub unsafe extern "C" fn dcgettext(
        domainname: *const c_char,
        msgid: *const c_char,
        category: c_int,
    ) -> *mut c_char {
        unsafe { dcngettext(domainname, msgid, null_mut(), 1, category) }
    }

    /// Return the no-catalog singular/plural fallback for one explicit domain.
    #[no_mangle]
    pub unsafe extern "C" fn dngettext(
        domainname: *const c_char,
        msgid1: *const c_char,
        msgid2: *const c_char,
        number: c_ulong,
    ) -> *mut c_char {
        unsafe { dcngettext(domainname, msgid1, msgid2, number, 5) }
    }
}}

// Musl's `src/locale/bind_textdomain_codeset.c` object.
static_archive_member! { bind_textdomain_codeset_source {
    /// Query or select musl's UTF-8-only gettext codeset spelling.
    #[no_mangle]
    pub unsafe extern "C" fn bind_textdomain_codeset(
        _domainname: *const c_char,
        codeset: *const c_char,
    ) -> *mut c_char {
        if !unsafe { ascii_case_equal_utf8(codeset) } {
            unsafe { errno::set_errno(EINVAL) };
            return null_mut();
        }
        UTF8_CODESET.as_ptr().cast_mut().cast::<c_char>()
    }
}}







// Musl's `src/locale/catopen.c` object.
static_archive_member! { catopen_source {
    /// This selected profile intentionally owns no catalog lookup or mapping.
    #[no_mangle]
    pub unsafe extern "C" fn catopen(_name: *const c_char, _oflag: c_int) -> *mut c_void {
        unsafe { errno::set_errno(ENOENT) };
        usize::MAX as *mut c_void
    }
}}

// Musl's `src/locale/catgets.c` object.
static_archive_member! { catgets_source {
    /// Return the caller default because this profile loads no message catalogs.
    #[no_mangle]
    pub unsafe extern "C" fn catgets(
        _catalog: *mut c_void,
        _set_id: c_int,
        _message_id: c_int,
        default_string: *const c_char,
    ) -> *mut c_char {
        default_string.cast_mut()
    }
}}

// Musl's `src/locale/catclose.c` object.
static_archive_member! { catclose_source {
    /// Close no mapping because this profile never opens one.
    #[no_mangle]
    pub extern "C" fn catclose(_catalog: *mut c_void) -> c_int {
        0
    }
}}
