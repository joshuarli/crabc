//! Opt-in static Linux/x86-64 frozen `legacy.misc` C ABI additions.
//!
//! This target-local owner supplies exactly three spellings:
//! [`fmtmsg`], [`setkey`], and [`encrypt`].  The frozen aggregate's other
//! five names—`get_avphys_pages`, `get_nprocs`, `get_nprocs_conf`,
//! `get_phys_pages`, and `issetugid`—remain independently evidenced default
//! selected-static prerequisites in [`super::system_information`] and
//! [`super::issetugid`].  Keeping this module behind `x86-legacy-misc` makes
//! that boundary explicit: the default x86 `libc.a` export contract does not
//! silently widen into a legacy runtime.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/legacy/fmtmsg.c::fmtmsg` maps to [`fmtmsg`].  Upstream source-tree
//!   placement is represented by this frozen source mapping; its observable
//!   contract is `MSGVERB` component selection, fd-2 `MM_PRINT`,
//!   `/dev/console` `MM_CONSOLE`, and `MM_NOMSG`/`MM_NOCON`/`MM_NOTOK` result
//!   composition.
//! - `src/legacy/encrypt.c::setkey` maps to [`setkey`] and
//!   `src/legacy/encrypt.c::encrypt` maps to [`encrypt`].
//!
//! `fmtmsg` composes only the existing selected static environment lookup,
//! C-string scan, descriptor entry, descriptor I/O, and initial-TLS errno
//! leaves.  Musl wraps its implementation in cancellation-state changes and
//! uses `dprintf`; this static artifact has no general cancellation runtime or
//! stdio formatter.  The local piece writer instead preserves the relevant
//! observable output and retry-on-short-write behavior without selecting those
//! wider subsystems.
//!
//! The DES functions intentionally diverge from musl.  They retain the
//! frozen project inert-DES observable contract also owned by
//! `libc/src/legacy_des_exports.rs`: neither function reads, stores, mutates,
//! encrypts, decrypts, nor otherwise interprets its caller buffer.  This
//! intentional divergence preserves link compatibility while complying with
//! the no-hand-rolled-cryptography boundary; it is not a cipher, PRNG,
//! allocator, dynamic libc, CRT, sysroot, loader, public-support, capability,
//! or family-promotion claim.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 legacy.misc requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr::null_mut;

use super::{byte_strings, descriptor_entry, descriptor_io, environment};

const MM_PRINT: c_int = 256;
const MM_CONSOLE: c_int = 512;
const MM_NOTOK: c_int = -1;
const MM_NOMSG: c_int = 1;
const MM_NOCON: c_int = 4;

const MM_HALT: c_int = 1;
const MM_ERROR: c_int = 2;
const MM_WARNING: c_int = 3;
const MM_INFO: c_int = 4;

const O_WRONLY: c_int = 1;

#[inline]
fn empty() -> *const c_char {
    c"".as_ptr()
}

/// Determine whether one MSGVERB component is not an exact colon-delimited
/// spelling of the component requested by musl's legacy parser.
///
/// # Safety
///
/// Both pointers must name readable NUL-terminated C strings. `actual` may
/// point at a suffix of `MSGVERB`, whose first following delimiter is `:`.
unsafe fn component_mismatch(wanted: *const u8, actual: *const u8) -> bool {
    let mut index = 0usize;
    loop {
        let wanted_byte = unsafe { wanted.add(index).read() };
        let actual_byte = unsafe { actual.add(index).read() };
        if wanted_byte == 0 || actual_byte == 0 || actual_byte != wanted_byte {
            break;
        }
        index += 1;
    }
    let wanted_byte = unsafe { wanted.add(index).read() };
    let actual_byte = unsafe { actual.add(index).read() };
    wanted_byte != 0 || (actual_byte != 0 && actual_byte != b':')
}

/// Parse musl's colon-delimited MSGVERB component selector.
///
/// The caller needs the existing environment leaf to have received a valid
/// initial `envp` before any application mutation. The static startup owner
/// supplies that precondition for normal selected-static use; a freestanding
/// test may equivalently install a valid environment vector first.
unsafe fn msgverb_mask() -> c_int {
    static COMPONENTS: [&[u8]; 5] = [
        b"label\0",
        b"severity\0",
        b"text\0",
        b"action\0",
        b"tag\0",
    ];

    let mut mask = 0;
    // SAFETY: the selected environment leaf returns either null or a pointer
    // into a valid inherited/mutated NUL-terminated environment string.
    let mut cursor = unsafe { environment::getenv(c"MSGVERB".as_ptr()) };
    while !cursor.is_null() && unsafe { cursor.read() } != 0 {
        let mut component = 0usize;
        while component < COMPONENTS.len()
            && unsafe {
                component_mismatch(COMPONENTS[component].as_ptr(), cursor.cast::<u8>())
            }
        {
            component += 1;
        }
        if component == COMPONENTS.len() {
            // This is musl's documented compatibility behavior: an unknown
            // component selects every piece rather than discarding a message.
            return 0xff;
        }
        mask |= 1 << component;
        // SAFETY: `cursor` names a valid C string from getenv, and the
        // byte-string leaf returns either null or a pointer into that string.
        let colon = unsafe { byte_strings::strchr(cursor, b':' as c_int) };
        cursor = if colon.is_null() {
            null_mut()
        } else {
            // SAFETY: a non-null `strchr` result points at the delimiter,
            // hence its following byte remains inside the NUL-terminated
            // MSGVERB string.
            unsafe { colon.add(1) }
        };
    }
    if mask == 0 { 0xff } else { mask }
}

/// Write every string piece, retrying only positive short writes.
///
/// `dprintf` has no separately selected x86 formatter contract. This direct
/// piece writer is therefore deliberately small, but preserves fmtmsg's
/// externally meaningful result distinction: a zero/negative descriptor
/// write makes the containing route fail and leaves the selected descriptor
/// leaf's exact errno intact.
///
/// # Safety
///
/// Every piece must point at a readable NUL-terminated C string for this
/// call. The descriptor's lifetime, write ordering, blocking mode, SIGPIPE
/// policy, and concurrent offset behavior remain the C caller's obligations.
unsafe fn write_pieces(file_descriptor: c_int, pieces: [*const c_char; 9]) -> c_int {
    for piece in pieces {
        // SAFETY: the caller's per-piece C-string contract gives the existing
        // byte-string leaf its exact readable terminating sequence.
        let length = unsafe { byte_strings::strlen(piece) };
        let mut offset = 0usize;
        while offset < length {
            // SAFETY: `offset < length` keeps the address inside the caller's
            // valid C string; only the remaining readable bytes are offered
            // to the selected raw descriptor-I/O boundary.
            let written = unsafe {
                descriptor_io::write(
                    file_descriptor,
                    piece.add(offset).cast::<c_void>(),
                    length - offset,
                )
            };
            if written <= 0 {
                return -1;
            }
            offset += written as usize;
        }
    }
    1
}

/// Emit one historical SysV/XSI format message.
///
/// This preserves musl's label/severity/text/action/tag rendering and
/// MSGVERB selection for the `MM_PRINT` fd-2 route, plus the independent
/// `/dev/console` route. Unsupported classification bits are inert exactly as
/// in musl's source; neither route causes a no-route call to fail.
///
/// # Safety
///
/// Every non-null string pointer must designate a readable NUL-terminated C
/// string for the duration of the call. The environment owner must have a
/// valid inherited or caller-installed `MSGVERB` vector before use. Callers
/// retain descriptor lifetime, stderr/console routing, SIGPIPE, and
/// concurrency obligations; this bounded leaf has no pthread cancellation or
/// general stdio synchronization behavior.
#[no_mangle]
pub unsafe extern "C" fn fmtmsg(
    classification: c_long,
    label: *const c_char,
    severity: c_int,
    text: *const c_char,
    action: *const c_char,
    tag: *const c_char,
) -> c_int {
    let mut result = 0;
    let severity_text = match severity {
        MM_HALT => c"HALT: ".as_ptr(),
        MM_ERROR => c"ERROR: ".as_ptr(),
        MM_WARNING => c"WARNING: ".as_ptr(),
        MM_INFO => c"INFO: ".as_ptr(),
        _ => empty(),
    };

    if classification & c_long::from(MM_CONSOLE) != 0 {
        // `open`'s fixed Rust ABI keeps an ignored third mode word even when
        // O_CREAT is absent; the selected x86 leaf follows musl's zero-mode
        // path in that case.
        let console = unsafe {
            descriptor_entry::open(c"/dev/console".as_ptr(), O_WRONLY, 0)
        };
        if console < 0 {
            result = MM_NOCON;
        } else {
            // SAFETY: every non-null caller pointer has fmtmsg's documented
            // C-string obligation; every null alternative selects our static
            // empty C string. The selected descriptor leaf retains errno.
            let wrote = unsafe {
                write_pieces(
                    console,
                    [
                        if label.is_null() { empty() } else { label },
                        if label.is_null() { empty() } else { c": ".as_ptr() },
                        if severity == 0 { empty() } else { severity_text },
                        if text.is_null() { empty() } else { text },
                        if action.is_null() { empty() } else { c"\nTO FIX: ".as_ptr() },
                        if action.is_null() { empty() } else { action },
                        if action.is_null() { empty() } else { c" ".as_ptr() },
                        if tag.is_null() { empty() } else { tag },
                        c"\n".as_ptr(),
                    ],
                )
            };
            if wrote < 1 {
                result = MM_NOCON;
            }
            // Match musl: close errors do not alter fmtmsg's result. The
            // selected direct close leaf nevertheless retains normal errno
            // publication for callers that observe it.
            let _ = descriptor_io::close(console);
        }
    }

    if classification & c_long::from(MM_PRINT) != 0 {
        // SAFETY: msgverb_mask only reads the selected inherited/mutated C
        // environment vector, whose publication is documented above.
        let verb = unsafe { msgverb_mask() };
        // SAFETY: this has write_pieces' exact C-string and descriptor caller
        // obligations, with static empty literals substituted for nulls.
        let wrote = unsafe {
            write_pieces(
                2,
                [
                    if verb & 1 != 0 && !label.is_null() { label } else { empty() },
                    if verb & 1 != 0 && !label.is_null() { c": ".as_ptr() } else { empty() },
                    if verb & 2 != 0 && severity != 0 { severity_text } else { empty() },
                    if verb & 4 != 0 && !text.is_null() { text } else { empty() },
                    if verb & 8 != 0 && !action.is_null() { c"\nTO FIX: ".as_ptr() } else { empty() },
                    if verb & 8 != 0 && !action.is_null() { action } else { empty() },
                    if verb & 8 != 0 && !action.is_null() { c" ".as_ptr() } else { empty() },
                    if verb & 16 != 0 && !tag.is_null() { tag } else { empty() },
                    c"\n".as_ptr(),
                ],
            )
        };
        if wrote < 1 {
            result |= MM_NOMSG;
        }
    }

    if result == (MM_NOCON | MM_NOMSG) {
        MM_NOTOK
    } else {
        result
    }
}

/// Retain the historical `setkey` link spelling as a deliberately inert ABI
/// compatibility function.
///
/// The caller buffer is intentionally neither dereferenced nor retained, so
/// there is no Rust pointer-validity obligation. This no-op is the documented
/// intentional divergence from musl's DES key-schedule state; it must not be
/// replaced with a local cipher implementation.
#[no_mangle]
pub extern "C" fn setkey(_key: *const c_char) {}

/// Retain the historical `encrypt` link spelling as a deliberately inert ABI
/// compatibility function.
///
/// The caller block is intentionally neither read nor modified for either
/// `edflag` direction. There is therefore no Rust pointer-validity obligation:
/// this function has no DES algorithm, state, allocation, or crypto behavior.
#[no_mangle]
pub extern "C" fn encrypt(_block: *mut c_char, _edflag: c_int) {}
