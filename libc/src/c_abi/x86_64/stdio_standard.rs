//! Bounded standard and pathname-stream C stdio core for Linux/x86-64.
//!
//! This target-local leaf owns the three process-lifetime stream objects
//! exported as `stdin`, `stdout`, and `stderr`, plus one separately selected
//! fixed pathname/tmpfile stream slot. The permanent streams expose their selected
//! byte/block operations: `fgetc`/`getc`/`getchar`, `ungetc`, `fread`,
//! `fputc`/`putc`/`putchar`, `fwrite`, `fflush`, `feof`, `ferror`,
//! `clearerr`, `fileno`, and GNU/BSD-only `fileno_unlocked` plus
//! `feof_unlocked`. A separate
//! permanent-only line-I/O leaf adds
//! `fgets`, `fputs`, and `puts`; it deliberately does not admit the fixed
//! pathname/tmpfile slot. The only valid non-null `FILE *` arguments for that
//! permanent-standard-stream block are those three exported pointers.
//! The focused permanent-byte-I/O evidence leaf rechecks the byte aliases and
//! one `ungetc` transition only through those permanent pointers; it neither
//! changes nor claims the pathname sibling's independently selected byte routes.
//! The focused permanent-status evidence leaf likewise observes only `stdin`:
//! its `fgetc` calls create EOF and descriptor-error markers solely as setup
//! for `feof`/`ferror`/`clearerr` zero-versus-nonzero transitions, without
//! selecting byte I/O, pathname state, musl locks, or a general `FILE` model.
//! Its GNU/BSD `feof_unlocked` sibling preserves musl's weak, same-address
//! alias of `feof` for permanent `stdin` observation only. The alias is not a
//! lock-free claim and does not select other status aliases or `FILE` state.
//! The focused permanent-fileno evidence leaf reads only the three permanent
//! descriptor adapters and their fixed `0`/`1`/`2` numbers; it neither opens,
//! mutates, nor claims a pathname stream or arbitrary `FILE` behavior.
//! Its separate GNU/BSD `fileno_unlocked` sibling preserves musl's weak,
//! same-address alias solely for those three permanent pointers; it does not
//! select a broader unlocked or lock-free stream API.
//! The sibling pathname/tmpfile block admits only one active `fopen("r")`,
//! `fopen("w+")`, or `tmpfile` stream at a time, its exact `fclose`, pre-I/O
//! caller-buffered `_IOFBF` configuration, and its selected
//! `fseek`/`fseeko`/`ftell`/`ftello`/`rewind`/`fgetpos`/`fsetpos` routes. It is
//! a deliberately lock-free, externally-serialized state machine: it does
//! not select concurrent stream access, `flockfile`, unlocked entry points
//! other than the separately selected GNU/BSD `fileno_unlocked` and
//! `feof_unlocked` aliases,
//! `fdopen`, `freopen`, append modes, dynamic stream allocation, a general
//! stream registry, formatters/scanners, line or unbuffered configuration,
//! wide streams, callbacks, memory/tmp/popen streams other than this single
//! private tmpfile lifecycle, or an open-file registry.
//!
//! ## Fixed source and license provenance
//!
//! The behavior map is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the release archive whose
//! SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! Those sources carry musl's MIT license; `compat/upstreams.toml` records
//! the authoritative repository pin and provenance.
//!
//! | Pinned musl source | Owned bounded x86 translation |
//! | --- | --- |
//! | `src/internal/stdio_impl.h` | private flags, `UNGET = 8`, static backing-state contract |
//! | `src/stdio/{stdin,stdout,stderr}.c` | permanent stream data symbols and static buffers |
//! | `src/stdio/{__stdio_read,__uflow,__toread}.c` | read lookahead/refill, EOF/error, and byte/block input state |
//! | `src/stdio/{__stdio_write,__overflow,__towrite}.c` | buffered/direct output and musl-shaped error/discard state |
//! | `src/stdio/{fgetc,getc,getchar,fputc,putc,putchar,ungetc}.c` | selected permanent-byte entries; focused evidence calls only the three permanent objects |
//! | `src/stdio/{fread,fwrite}.c` | selected public block entries |
//! | `src/stdio/{fgets,fputs,puts}.c` | selected permanent-standard-stream line I/O |
//! | `src/stdio/{feof,ferror,clearerr}.c` | selected permanent-status predicates and marker reset; focused evidence observes only stdin; `feof_unlocked` is musl's weak same-address alias of `feof` |
//! | `src/stdio/fileno.c` | selected descriptor adapter plus musl-shaped weak `fileno_unlocked` alias; focused evidence observes only permanent stdin/stdout/stderr |
//! | `src/stdio/fflush.c` | selected explicit-flush entry |
//! | `src/stdio/{fopen,fclose,setvbuf,fseek,ftell,fgetpos,fsetpos,rewind}.c` | one fixed pathname-stream lifecycle, caller-buffered full buffering, and logical-position routes |
//! | `src/stdio/tmpfile.c`, `src/temp/__randname.c` | one exclusive pathname created below `/tmp` with requested mode `0600`, immediately unlinked, and adopted as a `w+` fixed stream; Linux `getrandom` plus hex encoding replaces musl's noncryptographic name generator without adding a PRNG |
//!
//! The intentional boundaries are explicit. Musl's private x86 `FILE` record
//! is a 232-byte internal layout tied to its full stream list, lock state,
//! allocator, cancellation, and locale owners. This leaf instead keeps one
//! target-private typed state record for each permanently allocated stream;
//! public `FILE` remains opaque. It retains the observable `UNGET` headroom,
//! input lookahead, musl-shaped buffered-output discard-on-error behavior,
//! error/EOF state, and selected C entry contracts without importing those
//! unselected owners. The pathname sibling deliberately reuses one static
//! state record and one static `BUFSIZ + UNGET` backing object rather than
//! importing musl's allocation-backed open-file list. It is therefore one
//! regular-file pathname/tmpfile stream, not a generic `FILE` implementation.
//! The temporary-name spelling is deliberately unobservable through the API;
//! this translation uses 96 kernel-random bits and musl's 100-attempt bound, then
//! fails closed if immediate unlinking fails rather than returning a named
//! object. Those are implementation-strengthening differences from musl's
//! `__randname` loop, not an expansion of the public stream contract. `stdout`
//! remains buffered until explicit `fflush` except for the separately selected
//! `puts` newline-publication transition; terminal-sensitive automatic newline
//! flushing is not selected. The existing static `exit` lifecycle
//! deliberately does not call this module, so ordinary-exit flushing is also
//! outside this artifact and must be added as a separately evidenced lifecycle
//! transition after the relevant `atexit` ordering is specified.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 standard-stream core requires little-endian Linux/x86-64");

use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

use super::{c_off_status, c_ssize_status, c_status, errno, raw_syscall};

const BUFSIZ: usize = 1024;
const UNGET: usize = 8;
const STREAM_STORAGE: usize = BUFSIZ + UNGET;
const EOF: c_int = -1;
const EINTR: c_int = 4;
const EIO: c_int = 5;
const EOVERFLOW: c_int = 75;
const EINVAL: c_int = 22;
const EMFILE: c_int = 24;
const TMPFILE_RANDOM_BYTES: usize = 12;
// `src/stdio/tmpfile.c` fixes this retry count at `MAXTRIES = 100`.
const TMPFILE_MAX_ATTEMPTS: usize = 100;
const TMPFILE_SUFFIX_OFFSET: usize = b"/tmp/tmpfile_".len();

// These are the selected musl stdio flags. Keeping their source values makes
// the public nonzero `feof`/`ferror` results and internal direction checks
// auditable without exposing musl's private FILE layout.
const F_PERM: u32 = 1;
const F_NORD: u32 = 4;
const F_NOWR: u32 = 8;
const F_EOF: u32 = 16;
const F_ERR: u32 = 32;
const F_PATH: u32 = 64;
const F_ACTIVE: u32 = 128;
const F_EXTERNAL_BUFFER: u32 = 256;
const F_IO_STARTED: u32 = 512;

const O_RDONLY: c_int = 0;
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
const O_TRUNC: c_int = 0o1000;
const O_LARGEFILE: c_int = 0o100000;

const SEEK_SET: c_int = 0;
const SEEK_CUR: c_int = 1;
const SEEK_END: c_int = 2;
const _IOFBF: c_int = 0;

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    length: usize,
}

const _: [(); 16] = [(); core::mem::size_of::<IoVec>()];
const _: [(); 8] = [(); core::mem::align_of::<IoVec>()];

/// Private state of one owned permanent or fixed pathname stream.
///
/// The public C `FILE` spelling is intentionally opaque. This representation
/// is therefore target-local implementation state, not an installed layout or
/// a valid caller-constructible object.
#[repr(C)]
pub struct StandardStream {
    flags: u32,
    file_descriptor: c_int,
    buffer: *mut u8,
    capacity: usize,
    read_position: *mut u8,
    read_end: *mut u8,
    write_position: *mut u8,
}

impl StandardStream {
    const fn new(file_descriptor: c_int, flags: u32) -> Self {
        Self {
            flags,
            file_descriptor,
            buffer: ptr::null_mut(),
            capacity: 0,
            read_position: ptr::null_mut(),
            read_end: ptr::null_mut(),
            write_position: ptr::null_mut(),
        }
    }
}

static mut STDIN_STORAGE: [u8; STREAM_STORAGE] = [0; STREAM_STORAGE];
static mut STDOUT_STORAGE: [u8; STREAM_STORAGE] = [0; STREAM_STORAGE];
// Musl's permanent stderr record is unbuffered, but it still reserves the
// eight-byte pushback prefix in its static data shape.
static mut STDERR_STORAGE: [u8; UNGET] = [0; UNGET];
// The pathname vertical deliberately has exactly one owned stream record and
// one static backing object. This is a fixed lifecycle slot, not a general
// stream allocator or registry.
static mut PATH_STREAM_STORAGE: [u8; STREAM_STORAGE] = [0; STREAM_STORAGE];

static mut STDIN_STREAM: StandardStream = StandardStream::new(0, F_PERM | F_NOWR);
static mut STDOUT_STREAM: StandardStream = StandardStream::new(1, F_PERM | F_NORD);
static mut STDERR_STREAM: StandardStream = StandardStream::new(2, F_PERM | F_NORD);
static mut PATH_STREAM: StandardStream = StandardStream::new(-1, F_PATH);
static mut STANDARD_STREAMS_READY: bool = false;

/// C's permanent input stream data symbol.
#[no_mangle]
pub static mut stdin: *mut StandardStream = ptr::addr_of_mut!(STDIN_STREAM);

/// C's permanent standard-output stream data symbol.
#[no_mangle]
pub static mut stdout: *mut StandardStream = ptr::addr_of_mut!(STDOUT_STREAM);

/// C's permanent standard-error stream data symbol.
#[no_mangle]
pub static mut stderr: *mut StandardStream = ptr::addr_of_mut!(STDERR_STREAM);

/// Initialize the three permanent stream records without heap or startup
/// ownership. The first selected stream call performs this once; the artifact
/// is intentionally externally serialized, so it does not claim a concurrent
/// one-time initialization protocol.
unsafe fn ensure_standard_streams() {
    // SAFETY: this private state is touched only by the selected stream
    // boundary, whose documented first artifact requires external serialization.
    if unsafe { STANDARD_STREAMS_READY } {
        return;
    }

    // SAFETY: every static backing object outlives the process. Its first
    // UNGET bytes are reserved so successful ungetc calls can move before the
    // active input buffer without allocation.
    unsafe {
        let stdin_buffer = ptr::addr_of_mut!(STDIN_STORAGE).cast::<u8>().add(UNGET);
        STDIN_STREAM.buffer = stdin_buffer;
        STDIN_STREAM.capacity = BUFSIZ;
        STDIN_STREAM.read_position = stdin_buffer;
        STDIN_STREAM.read_end = stdin_buffer;

        let stdout_buffer = ptr::addr_of_mut!(STDOUT_STORAGE).cast::<u8>().add(UNGET);
        STDOUT_STREAM.buffer = stdout_buffer;
        STDOUT_STREAM.capacity = BUFSIZ;
        STDOUT_STREAM.write_position = stdout_buffer;

        let stderr_buffer = ptr::addr_of_mut!(STDERR_STORAGE).cast::<u8>().add(UNGET);
        STDERR_STREAM.buffer = stderr_buffer;
        STDERR_STREAM.capacity = 0;
        STDERR_STREAM.write_position = stderr_buffer;

        STANDARD_STREAMS_READY = true;
    }
}

#[inline]
fn is_permanent_stream(stream: *const StandardStream) -> bool {
    stream == ptr::addr_of!(STDIN_STREAM)
        || stream == ptr::addr_of!(STDOUT_STREAM)
        || stream == ptr::addr_of!(STDERR_STREAM)
}

#[inline]
unsafe fn is_active_path_stream(stream: *const StandardStream) -> bool {
    stream == ptr::addr_of!(PATH_STREAM)
        // SAFETY: pointer equality above proves the record is the one static
        // pathname slot before its flags are inspected.
        && unsafe { (*stream).flags & (F_PATH | F_ACTIVE) == F_PATH | F_ACTIVE }
}

#[inline]
unsafe fn is_selected_stream(stream: *const StandardStream) -> bool {
    is_permanent_stream(stream)
        // SAFETY: the path helper dereferences only the exact private slot.
        || unsafe { is_active_path_stream(stream) }
}

#[inline]
unsafe fn is_path_stream(stream: *const StandardStream) -> bool {
    // SAFETY: this is the exact private pathname slot predicate.
    unsafe { is_active_path_stream(stream) }
}

/// Publish a selected-stream argument failure without dereferencing an
/// arbitrary `FILE *`. The permanent block's public contract still requires
/// its three exported objects; the path block uses this for its closed slot.
#[inline]
unsafe fn reject_stream() {
    // SAFETY: the x86 static C ABI owns this calling thread's errno slot.
    unsafe { errno::set_errno(EINVAL) };
}

/// Install the one private pathname slot after `open(2)` succeeds.
///
/// The caller has already established that the slot is inactive. The backing
/// object has process lifetime and supplies eight bytes of pushback headroom,
/// exactly like the permanent input buffer. It is never exposed as a public
/// `FILE` layout or reused as a general allocator.
unsafe fn initialize_path_stream(file_descriptor: c_int, flags: u32) -> *mut StandardStream {
    // SAFETY: the single private slot and its static backing object are owned
    // by this externally serialized pathname-stream lifecycle.
    unsafe {
        let buffer = ptr::addr_of_mut!(PATH_STREAM_STORAGE).cast::<u8>().add(UNGET);
        PATH_STREAM.flags = F_PATH | F_ACTIVE | flags;
        PATH_STREAM.file_descriptor = file_descriptor;
        PATH_STREAM.buffer = buffer;
        PATH_STREAM.capacity = BUFSIZ;
        PATH_STREAM.read_position = buffer;
        PATH_STREAM.read_end = buffer;
        PATH_STREAM.write_position = buffer;
        ptr::addr_of_mut!(PATH_STREAM)
    }
}

/// Forget a closed pathname stream after its descriptor lifecycle ends.
///
/// No caller-held pointer remains a valid selected stream after this reset.
/// The static backing bytes remain process-owned and are reinitialized by the
/// next successful `fopen` before any read or write consumes them.
unsafe fn reset_path_stream() {
    // SAFETY: only `fclose` reaches this after it has claimed the exact slot.
    unsafe {
        PATH_STREAM = StandardStream::new(-1, F_PATH);
    }
}

#[derive(Clone, Copy)]
enum PathOpenMode {
    Read,
    WriteUpdate,
}

impl PathOpenMode {
    const fn open_flags(self) -> c_int {
        match self {
            Self::Read => O_RDONLY | O_LARGEFILE,
            Self::WriteUpdate => O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE,
        }
    }

    const fn stream_flags(self) -> u32 {
        match self {
            Self::Read => F_NOWR,
            Self::WriteUpdate => 0,
        }
    }
}

/// Parse the exact two pathname-stream mode spellings selected by this leaf.
///
/// The bounded vertical intentionally does not accept append, exclusive,
/// close-on-exec, binary-extension, or broad mode-parser behavior. Those need
/// their own source-mapped lifecycle evidence before they can join this slot.
unsafe fn parse_path_open_mode(mode: *const core::ffi::c_char) -> Option<PathOpenMode> {
    if mode.is_null() {
        return None;
    }
    // SAFETY: C's `fopen` contract supplies a readable NUL-terminated mode
    // string. Inspect each prefix byte only after the preceding byte selects a
    // spelling that requires it: an empty object need contain only `\0`, and
    // the exact `"r"` object need contain only `r\0`. All other strings fail
    // as EINVAL without an unbounded scan.
    unsafe {
        match *mode as u8 {
            b'r' if *mode.add(1) == 0 => Some(PathOpenMode::Read),
            b'w' if *mode.add(1) as u8 == b'+' && *mode.add(2) == 0 => {
                Some(PathOpenMode::WriteUpdate)
            }
            _ => None,
        }
    }
}

/// Synchronize a selected pathname stream before input after buffered output.
///
/// This intentionally covers only the one regular-file `w+` route. The
/// permanent streams are direction-fixed, so they never acquire this path.
unsafe fn prepare_path_read(stream: *mut StandardStream) -> bool {
    // SAFETY: path predicate dereferences only the exact private slot.
    if !unsafe { is_path_stream(stream) } || !unsafe { is_writable(stream) } {
        return true;
    }
    // SAFETY: the selected pathname slot is initialized and externally
    // serialized; flush_output owns the pending static/caller buffer range.
    unsafe { flush_output(stream) != EOF }
}

/// Discard prefetched input before a pathname-stream output operation.
///
/// The kernel position follows the buffered refill, while C's logical stream
/// position remains at `read_position`; `lseek(-unread, SEEK_CUR)` restores
/// the selected regular-file descriptor to that logical position.
unsafe fn prepare_path_write(stream: *mut StandardStream) -> bool {
    // SAFETY: path predicate dereferences only the exact private slot.
    if !unsafe { is_path_stream(stream) } {
        return true;
    }
    let unread = unsafe { (*stream).read_end.offset_from((*stream).read_position) };
    if unread == 0 {
        return true;
    }
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from((*stream).file_descriptor),
            -(unread as i64),
            i64::from(SEEK_CUR),
        )
    };
    if c_off_status(result) < 0 {
        // SAFETY: the selected path slot owns this stream-local error marker.
        unsafe { mark_error(stream) };
        return false;
    }
    // SAFETY: the seek has synchronized the descriptor to the logical cursor;
    // reset only the private initialized buffer range.
    unsafe {
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
    }
    true
}

#[inline]
unsafe fn mark_path_io_started(stream: *mut StandardStream) {
    // SAFETY: path predicate dereferences only the exact private slot.
    if unsafe { is_path_stream(stream) } {
        // SAFETY: caller owns the selected pathname stream state transition.
        unsafe { (*stream).flags |= F_IO_STARTED };
    }
}

#[inline]
unsafe fn mark_error(stream: *mut StandardStream) {
    // SAFETY: caller owns one selected stream state record.
    unsafe { (*stream).flags |= F_ERR };
}

#[inline]
unsafe fn is_readable(stream: *const StandardStream) -> bool {
    // SAFETY: caller owns one selected stream state record.
    unsafe { (*stream).flags & F_NORD == 0 }
}

#[inline]
unsafe fn is_writable(stream: *const StandardStream) -> bool {
    // SAFETY: caller owns one selected stream state record.
    unsafe { (*stream).flags & F_NOWR == 0 }
}

/// Refill a readable selected stream using musl's caller-plus-lookahead
/// shape. When more than one byte is requested, Linux reads all but the final
/// requested byte directly into the caller and retains trailing input in the
/// owned stream buffer. This preserves byte/block operation ordering
/// without reducing fgetc to an unbuffered one-byte syscall loop.
///
/// # Safety
///
/// `destination` must designate `length` writable bytes when `length` is
/// nonzero. `stream` must be one selected owned stream record.
unsafe fn refill_into(
    stream: *mut StandardStream,
    destination: *mut u8,
    length: usize,
) -> usize {
    if length == 0 {
        return 0;
    }
    // Musl's __toread leaves EOF sticky: an exhausted stream must not issue a
    // fresh read merely because its descriptor is later replaced. clearerr,
    // ungetc, or an unselected repositioning transition is the only route
    // that can clear this marker before input resumes.
    if unsafe { (*stream).flags & F_EOF != 0 } {
        return 0;
    }

    // SAFETY: the stream pointer belongs to this private selected state
    // machine; it is initialized before the public call reaches this helper.
    let (file_descriptor, buffer, capacity) = unsafe {
        (
            (*stream).file_descriptor,
            (*stream).buffer,
            (*stream).capacity,
        )
    };
    if capacity == 0 {
        // SAFETY: every readable selected stream has owned or caller storage. This
        // branch remains defensive if a malformed internal record reaches it.
        unsafe {
            errno::set_errno(EIO);
            mark_error(stream);
        }
        return 0;
    }

    let direct_length = length - 1;
    let result = if direct_length == 0 {
        // SAFETY: the static input buffer is writable for its declared
        // capacity and lives across the raw syscall.
        unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_READ,
                i64::from(file_descriptor),
                buffer as usize as i64,
                capacity as i64,
            )
        }
    } else {
        let mut vectors = [
            IoVec {
                base: destination.cast(),
                length: direct_length,
            },
            IoVec {
                base: buffer.cast(),
                length: capacity,
            },
        ];
        // SAFETY: both iovec ranges are writable for their exact declared
        // lengths, and the fixed two-entry record lives through readv.
        unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_READV,
                i64::from(file_descriptor),
                vectors.as_mut_ptr() as usize as i64,
                vectors.len() as i64,
            )
        }
    };
    let count = c_ssize_status(result);
    if count < 0 {
        // SAFETY: c_ssize_status published the raw Linux errno; this records
        // the selected stream-local error state exactly once.
        unsafe { mark_error(stream) };
        return 0;
    }
    if count == 0 {
        // SAFETY: zero read is the selected EOF transition for this stream.
        unsafe { (*stream).flags |= F_EOF };
        return 0;
    }

    let count = count as usize;
    // SAFETY: a positive read initialized exactly its returned prefix of the
    // two submitted buffers. Keep the trailing buffer bytes for later byte
    // operations and copy the first retained byte into the final caller slot.
    unsafe {
        if direct_length == 0 {
            (*stream).read_position = buffer.add(1);
            (*stream).read_end = buffer.add(count);
            destination.write(buffer.read());
            return 1;
        }
        if count <= direct_length {
            return count;
        }
        let retained = count - direct_length;
        (*stream).read_position = buffer.add(1);
        (*stream).read_end = buffer.add(retained);
        destination.add(direct_length).write(buffer.read());
        length
    }
}

/// Read one byte from a selected input stream.
///
/// # Safety
///
/// `stream` must be one exported permanent pointer or the still-active pointer
/// returned by this module's `fopen`; callers must serialize its access.
unsafe fn read_byte(stream: *mut StandardStream) -> c_int {
    // SAFETY: this initializes only permanent private state before dereference.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return EOF;
    }
    if !unsafe { is_readable(stream) } {
        // Wrong-direction I/O is outside the selected stream contract, but a
        // local error marker prevents it from looking like ordinary EOF.
        unsafe { mark_error(stream) };
        return EOF;
    }
    // SAFETY: output pending in the one `w+` path slot must reach the
    // descriptor before a selected input route observes it.
    if !unsafe { prepare_path_read(stream) } {
        return EOF;
    }
    // SAFETY: only the fixed pathname slot records this local transition.
    unsafe { mark_path_io_started(stream) };
    // SAFETY: selected stream state is initialized; the buffered range was
    // produced by a prior successful readv/read or a successful ungetc.
    unsafe {
        if (*stream).read_position < (*stream).read_end {
            let byte = (*stream).read_position.read();
            (*stream).read_position = (*stream).read_position.add(1);
            return c_int::from(byte);
        }
    }

    let mut byte = 0u8;
    // SAFETY: one local writable byte and a selected stream satisfy
    // refill_into's complete raw-I/O contract.
    if unsafe { refill_into(stream, ptr::addr_of_mut!(byte), 1) } == 0 {
        EOF
    } else {
        c_int::from(byte)
    }
}

/// Flush the currently buffered output of one selected stream.
///
/// # Safety
///
/// `stream` must be one selected owned stream record. Its state is externally
/// serialized for this lock-free artifact.
unsafe fn flush_output(stream: *mut StandardStream) -> c_int {
    // SAFETY: the caller supplies one initialized selected stream record.
    if !unsafe { is_writable(stream) } {
        return 0;
    }
    // SAFETY: selected stream output storage and pointer positions were
    // initialized together; their difference is the currently pending prefix.
    let pending = unsafe {
        (*stream)
            .write_position
            .offset_from((*stream).buffer) as usize
    };
    if pending == 0 {
        return 0;
    }

    let mut written = 0usize;
    while written < pending {
        // SAFETY: the remaining pending prefix is readable through the raw
        // write syscall for the duration of this call.
        let result = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_WRITE,
                i64::from((*stream).file_descriptor),
                (*stream).buffer.add(written) as usize as i64,
                (pending - written) as i64,
            )
        };
        let count = c_ssize_status(result);
        if count <= 0 {
            if count == 0 {
                // Linux write should not make zero progress for a nonempty
                // blocking transfer. Treat it as a deterministic selected
                // failure instead of spinning.
                unsafe { errno::set_errno(EIO) };
            }
            // Musl's __stdio_write clears all output cursors on an error,
            // even after a preceding short write. This bounded leaf has no
            // direct caller iovec to report, so it discards the buffered
            // prefix and records only the selected stream error state.
            unsafe {
                (*stream).write_position = (*stream).buffer;
                mark_error(stream);
            }
            return EOF;
        }
        written += count as usize;
    }
    // SAFETY: all pending bytes reached Linux; retain the static backing array
    // as the empty output buffer for the next selected write.
    unsafe { (*stream).write_position = (*stream).buffer };
    0
}

/// Buffer or directly write one byte to one selected output stream.
///
/// # Safety
///
/// `stream` must be one exported permanent pointer or the still-active pointer
/// returned by this module's `fopen`; callers must serialize its access.
unsafe fn write_byte(stream: *mut StandardStream, byte: u8) -> c_int {
    // SAFETY: this initializes permanent private state before dereference.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return EOF;
    }
    if !unsafe { is_writable(stream) } {
        unsafe { mark_error(stream) };
        return EOF;
    }
    // SAFETY: only the selected pathname `w+` slot can retain input ahead of
    // its logical cursor; its helper seeks that descriptor back before write.
    if !unsafe { prepare_path_write(stream) } {
        return EOF;
    }
    // SAFETY: only the fixed pathname slot records this local transition.
    unsafe { mark_path_io_started(stream) };
    // SAFETY: state is initialized and capacity belongs to static backing.
    let capacity = unsafe { (*stream).capacity };
    if capacity == 0 {
        // SAFETY: the address of `byte` remains readable for the syscall.
        let result = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_WRITE,
                i64::from((*stream).file_descriptor),
                ptr::addr_of!(byte) as usize as i64,
                1,
            )
        };
        if c_ssize_status(result) == 1 {
            return c_int::from(byte);
        }
        unsafe { mark_error(stream) };
        return EOF;
    }

    // SAFETY: the active output cursor lies inside the static backing range.
    unsafe {
        if (*stream).write_position == (*stream).buffer.add(capacity)
            && flush_output(stream) == EOF
        {
            return EOF;
        }
        (*stream).write_position.write(byte);
        (*stream).write_position = (*stream).write_position.add(1);
    }
    c_int::from(byte)
}

/// Return the descriptor owned by one selected stream.
///
/// # Safety
///
/// `stream` must be one of `stdin`, `stdout`, or `stderr`, or the still-active
/// pointer returned by this module's `fopen`.
#[no_mangle]
pub unsafe extern "C" fn fileno(stream: *mut StandardStream) -> c_int {
    // SAFETY: first-use initialization cannot move permanent stream objects.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return -1;
    }
    // SAFETY: the selected public contract admits only the permanent pointers.
    unsafe { (*stream).file_descriptor }
}

// Musl's `weak_alias(fileno, fileno_unlocked)` preserves both a weak archive
// override point and one ELF address. A Rust forwarding wrapper would create a
// second address, so retain the source-specific GNU/BSD alias in assembler.
core::arch::global_asm!(
    ".weak fileno_unlocked",
    ".set fileno_unlocked, fileno",
);

/// Flush one selected output stream, or every owned output stream for NULL.
///
/// Input-stream flushing, dynamic stream lists, terminal line-buffer policy,
/// and ordinary-exit flushing are outside this explicit-flush-only artifact.
///
/// # Safety
///
/// A non-null `stream` must be one permanent exported pointer or the
/// still-active pointer returned by this module's `fopen`; callers must
/// externally serialize every selected stream affected by the call.
#[no_mangle]
pub unsafe extern "C" fn fflush(stream: *mut StandardStream) -> c_int {
    // SAFETY: permanent static state does not require a CRT initializer.
    unsafe { ensure_standard_streams() };
    if stream.is_null() {
        // SAFETY: these are the only output streams this module owns. Preserve
        // every flush attempt like musl's global walk, including the separately
        // selected path slot when its externally serialized lifecycle is live.
        let stdout_status = unsafe { flush_output(ptr::addr_of_mut!(STDOUT_STREAM)) };
        let stderr_status = unsafe { flush_output(ptr::addr_of_mut!(STDERR_STREAM)) };
        let path_status = if unsafe { is_active_path_stream(ptr::addr_of!(PATH_STREAM)) } {
            unsafe { flush_output(ptr::addr_of_mut!(PATH_STREAM)) }
        } else {
            0
        };
        if stdout_status == EOF || stderr_status == EOF || path_status == EOF {
            EOF
        } else {
            0
        }
    } else {
        // SAFETY: this predicate dereferences only the exact static pathname
        // slot; permanent pointers are compared without dereference.
        if !unsafe { is_selected_stream(stream) } {
            // SAFETY: no caller stream was dereferenced on this closed boundary.
            unsafe { reject_stream() };
            return EOF;
        }
        // SAFETY: caller supplies one selected stream pointer.
        unsafe { flush_output(stream) }
    }
}

/// Read one byte from a selected stream.
///
/// # Safety
///
/// `stream` must be one permanent exported pointer or the still-active pointer
/// returned by this module's `fopen`; its access must be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn fgetc(stream: *mut StandardStream) -> c_int {
    // SAFETY: caller supplies the selected stream state contract.
    unsafe { read_byte(stream) }
}

/// C's `getc` function entry for one selected stream.
///
/// # Safety
///
/// `stream` must be one permanent exported pointer or the still-active pointer
/// returned by this module's `fopen`; its access must be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn getc(stream: *mut StandardStream) -> c_int {
    // SAFETY: preserves the fgetc selected-stream contract.
    unsafe { fgetc(stream) }
}

/// C's `getchar` function entry for the permanent standard input stream.
#[no_mangle]
pub unsafe extern "C" fn getchar() -> c_int {
    // SAFETY: this module owns the permanent stdin object and its state
    // remains externally serialized by the artifact contract.
    unsafe { fgetc(ptr::addr_of_mut!(STDIN_STREAM)) }
}

/// Push one byte back into a selected permanent input stream.
///
/// # Safety
///
/// `stream` must be one exported permanent stream pointer and its access must
/// be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn ungetc(character: c_int, stream: *mut StandardStream) -> c_int {
    // SAFETY: permanent state must exist before reading the static buffer
    // cursor and UNGET prefix.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return EOF;
    }
    if character == EOF {
        return EOF;
    }
    if !unsafe { is_readable(stream) } {
        // Musl enters read mode before it decides whether pushback storage is
        // available. A permanent output stream therefore records F_ERR rather
        // than appearing indistinguishable from an input pushback-limit miss.
        unsafe { mark_error(stream) };
        return EOF;
    }
    // The pathname sibling intentionally selects ordinary byte/block transfer
    // and logical positions, not its own pushback semantics. In particular a
    // caller buffer has no private headroom, so reject all path-slot ungetc
    // calls rather than manufacture a second state model or an out-of-bounds
    // prefix.
    if unsafe { is_path_stream(stream) } {
        unsafe { mark_error(stream) };
        return EOF;
    }
    // SAFETY: the static input backing reserves exactly UNGET bytes immediately
    // before buffer. A successful pushback clears EOF and never allocates.
    unsafe {
        let lower_bound = (*stream).buffer.sub(UNGET);
        if (*stream).read_position <= lower_bound {
            return EOF;
        }
        (*stream).read_position = (*stream).read_position.sub(1);
        (*stream).read_position.write(character as u8);
        (*stream).flags &= !F_EOF;
    }
    // SAFETY: only the fixed pathname slot records this local transition.
    unsafe { mark_path_io_started(stream) };
    c_int::from(character as u8)
}

/// Read complete elements from one selected input stream.
///
/// # Safety
///
/// `destination` must designate `size * count` writable bytes when both are
/// nonzero. `stream` must be one permanent exported pointer or the still-active
/// pointer returned by this module's `fopen`; its access must be serialized.
#[no_mangle]
pub unsafe extern "C" fn fread(
    destination: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut StandardStream,
) -> usize {
    if size == 0 || count == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(count) else {
        // SAFETY: this selected range diagnostic owns the C errno slot and
        // stream-local error state without touching caller storage.
        unsafe {
            errno::set_errno(EOVERFLOW);
            ensure_standard_streams();
            mark_error(stream);
        }
        return 0;
    };
    // SAFETY: selected stream state exists before its direction and buffer
    // fields are observed.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return 0;
    }
    if !unsafe { is_readable(stream) } {
        unsafe { mark_error(stream) };
        return 0;
    }
    // SAFETY: pending output in the selected `w+` pathname slot is flushed
    // before its read boundary consumes descriptor bytes.
    if !unsafe { prepare_path_read(stream) } {
        return 0;
    }
    // SAFETY: only the fixed pathname slot records this local transition.
    unsafe { mark_path_io_started(stream) };

    let mut received = 0usize;
    let destination = destination.cast::<u8>();
    while received < total {
        // SAFETY: `received < total` keeps the local pointer inside the exact
        // caller-owned destination range promised by this C ABI call.
        let next = unsafe { destination.add(received) };
        // SAFETY: all buffered bytes were initialized by prior read input or
        // ungetc, and pointer subtraction remains within static backing.
        let buffered = unsafe {
            ((*stream).read_end as usize).saturating_sub((*stream).read_position as usize)
        };
        if buffered != 0 {
            let copied = core::cmp::min(buffered, total - received);
            // SAFETY: source/destination are nonoverlapping exact ranges;
            // the public destination cannot alias private opaque storage.
            unsafe {
                ptr::copy_nonoverlapping((*stream).read_position, next, copied);
                (*stream).read_position = (*stream).read_position.add(copied);
            }
            received += copied;
            continue;
        }
        // SAFETY: `next` has the remaining exact writable suffix; refill
        // preserves one trailing lookahead byte for later operations.
        let read = unsafe { refill_into(stream, next, total - received) };
        if read == 0 {
            break;
        }
        received += read;
    }
    received / size
}

/// Write one byte to a selected output stream.
///
/// # Safety
///
/// `stream` must be one permanent exported pointer or the still-active pointer
/// returned by this module's `fopen`; its access must be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn fputc(character: c_int, stream: *mut StandardStream) -> c_int {
    // SAFETY: preserves the selected output-stream contract.
    unsafe { write_byte(stream, character as u8) }
}

/// C's `putc` function entry for a selected output stream.
///
/// # Safety
///
/// `stream` must be one permanent exported pointer or the still-active pointer
/// returned by this module's `fopen`; its access must be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn putc(character: c_int, stream: *mut StandardStream) -> c_int {
    // SAFETY: preserves the fputc selected-stream contract.
    unsafe { fputc(character, stream) }
}

/// C's `putchar` function entry for permanent standard output.
#[no_mangle]
pub unsafe extern "C" fn putchar(character: c_int) -> c_int {
    // SAFETY: this module owns the permanent stdout object and its state
    // remains externally serialized by the artifact contract.
    unsafe { fputc(character, ptr::addr_of_mut!(STDOUT_STREAM)) }
}

/// Write complete elements to one selected output stream.
///
/// # Safety
///
/// `source` must designate `size * count` readable bytes when both are
/// nonzero. `stream` must be one permanent exported pointer or the still-active
/// pointer returned by this module's `fopen`; its access must be serialized.
#[no_mangle]
pub unsafe extern "C" fn fwrite(
    source: *const c_void,
    size: usize,
    count: usize,
    stream: *mut StandardStream,
) -> usize {
    if size == 0 || count == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(count) else {
        // SAFETY: preserve the local stream error state without reading the
        // invalid oversized caller range.
        unsafe {
            ensure_standard_streams();
            mark_error(stream);
        }
        return 0;
    };
    // SAFETY: selected stream state must exist before its direction is read.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return 0;
    }
    if !unsafe { is_writable(stream) } {
        unsafe { mark_error(stream) };
        return 0;
    }
    // SAFETY: selected pathname input lookahead must be rewound before an
    // update-stream write reaches the descriptor.
    if !unsafe { prepare_path_write(stream) } {
        return 0;
    }
    // SAFETY: only the fixed pathname slot records this local transition.
    unsafe { mark_path_io_started(stream) };

    let source = source.cast::<u8>();
    let mut written = 0usize;
    while written < total {
        // SAFETY: `written < total` keeps this byte inside the caller-owned
        // exact readable range. write_byte preserves musl-shaped output
        // error-state behavior.
        if unsafe { write_byte(stream, source.add(written).read()) } == EOF {
            break;
        }
        written += 1;
    }
    written / size
}

/// Read one newline-bounded byte string from one permanent standard stream.
///
/// This deliberately accepts only `stdin`, `stdout`, or `stderr`; it does not
/// extend the separately selected fixed pathname/tmpfile stream slot. The
/// bounded leaf follows musl's `fgets` empty-input and `count == 1`
/// contract: a positive one-byte destination is NUL-terminated without
/// consuming input, while EOF before any copied byte returns null.
///
/// # Safety
///
/// `destination` must be non-null, `count` must be nonnegative, and a
/// positive `count` requires at least that many writable `char` bytes.
/// `stream` must be one of the three exported permanent stream pointers, and
/// callers must externally serialize its access.
#[no_mangle]
pub unsafe extern "C" fn fgets(
    destination: *mut c_char,
    count: c_int,
    stream: *mut StandardStream,
) -> *mut c_char {
    // SAFETY: first use initializes only permanent private records.
    unsafe { ensure_standard_streams() };
    if !is_permanent_stream(stream) {
        // SAFETY: this boundary does not dereference an arbitrary FILE pointer.
        unsafe { reject_stream() };
        return ptr::null_mut();
    }
    if destination.is_null() {
        // C requires writable caller storage. Keep the private diagnostic
        // deterministic instead of dereferencing a null destination.
        unsafe { errno::set_errno(EINVAL) };
        return ptr::null_mut();
    }
    // Pinned musl returns the destination for its one-byte boundary after
    // writing only the terminator; no input transition occurs here.
    if count <= 1 {
        if count != 0 {
            // SAFETY: the caller promised one writable byte for positive count.
            unsafe { destination.write(0) };
        }
        return destination;
    }

    let mut cursor = destination;
    let mut remaining = count;
    while remaining > 1 {
        // SAFETY: the permanent-only predicate above proves this is one
        // selected stream; read_byte owns its buffered input transition.
        let character = unsafe { read_byte(stream) };
        if character == EOF {
            break;
        }
        // SAFETY: `remaining > 1` reserves this byte and the final terminator
        // inside the caller-promised destination range.
        unsafe { cursor.write(character as u8 as c_char) };
        // SAFETY: the prior write stayed inside the caller-promised range.
        cursor = unsafe { cursor.add(1) };
        remaining -= 1;
        if character == c_int::from(b'\n') {
            break;
        }
    }
    if cursor == destination {
        return ptr::null_mut();
    }
    // SAFETY: at least one byte was copied while `remaining > 1`, leaving the
    // terminating slot inside the caller-promised range.
    unsafe { cursor.write(0) };
    destination
}

/// Write one NUL-terminated byte string to one permanent standard stream.
///
/// This deliberately accepts only `stdin`, `stdout`, or `stderr`; in
/// particular, it does not make line output available through the one active
/// pathname/tmpfile slot. Output remains subject to the existing
/// permanent stdout/stderr buffering contract. In particular, a newline in
/// this bulk string entry does not itself widen the selected byte/block output
/// behavior into a general line-buffering contract.
///
/// # Safety
///
/// `source` must point to a readable NUL-terminated C string. `stream` must
/// be one of the three exported permanent stream pointers, and callers must
/// externally serialize its access.
#[no_mangle]
pub unsafe extern "C" fn fputs(
    source: *const c_char,
    stream: *mut StandardStream,
) -> c_int {
    // SAFETY: first use initializes only permanent private records.
    unsafe { ensure_standard_streams() };
    if !is_permanent_stream(stream) {
        // SAFETY: this boundary does not dereference an arbitrary FILE pointer.
        unsafe { reject_stream() };
        return EOF;
    }
    if source.is_null() {
        // C requires a readable NUL-terminated source. Keep this candidate
        // boundary fail-closed instead of dereferencing a null pointer.
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }

    let mut cursor = source;
    loop {
        // SAFETY: the C contract promises a readable NUL-terminated source.
        let byte = unsafe { cursor.read() as u8 };
        if byte == 0 {
            return 0;
        }
        // SAFETY: permanent-only admission above proves the selected stream;
        // write_byte preserves its buffer/error transition.
        if unsafe { write_byte(stream, byte) } == EOF {
            return EOF;
        }
        // SAFETY: the non-NUL byte proves the next byte belongs to the
        // caller-promised C string.
        cursor = unsafe { cursor.add(1) };
    }
}

/// Write one NUL-terminated byte string and one newline to permanent stdout.
///
/// # Safety
///
/// `source` must point to a readable NUL-terminated C string. Callers must
/// externally serialize access to the permanent stdout stream.
#[no_mangle]
pub unsafe extern "C" fn puts(source: *const c_char) -> c_int {
    // SAFETY: fputs keeps this call inside the permanent stdout boundary.
    if unsafe { fputs(source, ptr::addr_of_mut!(STDOUT_STREAM)) } == EOF {
        return EOF;
    }
    // SAFETY: stdout is one process-lifetime permanent record owned here.
    if unsafe { write_byte(ptr::addr_of_mut!(STDOUT_STREAM), b'\n') } == EOF {
        EOF
    // SAFETY: musl's permanent stdout newline transition publishes the
    // selected line through its existing static output buffer.
    } else if unsafe { flush_output(ptr::addr_of_mut!(STDOUT_STREAM)) } == EOF {
        EOF
    } else {
        0
    }
}

/// Return the selected EOF-state marker for one selected stream.
///
/// # Safety
///
/// `stream` must be one permanent exported pointer or the still-active pointer
/// returned by this module's `fopen`.
#[no_mangle]
pub unsafe extern "C" fn feof(stream: *mut StandardStream) -> c_int {
    // SAFETY: permanent state must exist before the selected flag is read.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return 0;
    }
    // SAFETY: caller supplies one selected stream pointer.
    unsafe { ((*stream).flags & F_EOF) as c_int }
}

// Pinned musl `src/stdio/feof.c` uses `weak_alias(feof, feof_unlocked)` to
// preserve both a weak archive override point and one ELF address. A Rust
// forwarding wrapper would create a second address, so retain this GNU/BSD
// alias in assembler. The selected permanent-stream observation remains
// externally serialized; its conventional unlocked spelling does not make this
// a lock-free FILE boundary.
core::arch::global_asm!(
    ".weak feof_unlocked",
    ".set feof_unlocked, feof",
);

/// Return the selected error-state marker for one selected stream.
///
/// # Safety
///
/// `stream` must be one permanent exported pointer or the still-active pointer
/// returned by this module's `fopen`.
#[no_mangle]
pub unsafe extern "C" fn ferror(stream: *mut StandardStream) -> c_int {
    // SAFETY: permanent state must exist before the selected flag is read.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return 0;
    }
    // SAFETY: caller supplies one selected stream pointer.
    unsafe { ((*stream).flags & F_ERR) as c_int }
}

/// Clear EOF and error markers on one selected stream.
///
/// # Safety
///
/// `stream` must be one permanent exported pointer or the still-active pointer
/// returned by this module's `fopen`; its access must be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn clearerr(stream: *mut StandardStream) {
    // SAFETY: permanent state must exist before its selected flags are reset.
    unsafe { ensure_standard_streams() };
    // SAFETY: this predicate dereferences only the exact static pathname slot.
    if !unsafe { is_selected_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return;
    }
    // SAFETY: caller supplies one selected stream pointer.
    unsafe { (*stream).flags &= !(F_EOF | F_ERR) };
}

// -------------------------------------------------------------------------
// One fixed pathname-stream / logical-position sibling
// -------------------------------------------------------------------------

/// Open the one selected pathname stream.
///
/// Only an externally serialized regular-file `"r"` or `"w+"` route is
/// selected. `"w+"` maps directly to Linux `open` with
/// `O_RDWR|O_CREAT|O_TRUNC|O_LARGEFILE` and mode `0666`; `"r"` maps to
/// `O_RDONLY|O_LARGEFILE`. The one static slot is intentionally not a stream
/// allocator: a second live path stream fails with `EMFILE`. Pathname lifetime,
/// resolution races, umask, and special-file behavior remain Linux-owned.
///
/// # Safety
///
/// `path` and `mode` must point to readable NUL-terminated C strings for this
/// call. The caller must serialize the entire selected pathname-stream
/// lifecycle and close a successful result through this module's `fclose`.
#[no_mangle]
pub unsafe extern "C" fn fopen(
    path: *const core::ffi::c_char,
    mode: *const core::ffi::c_char,
) -> *mut StandardStream {
    if path.is_null() {
        // SAFETY: the x86 static C ABI owns this calling thread's errno slot.
        unsafe { errno::set_errno(EINVAL) };
        return ptr::null_mut();
    }
    let Some(open_mode) = (unsafe { parse_path_open_mode(mode) }) else {
        // SAFETY: the x86 static C ABI owns this calling thread's errno slot.
        unsafe { errno::set_errno(EINVAL) };
        return ptr::null_mut();
    };
    // SAFETY: this predicate dereferences only the exact private pathname slot.
    if unsafe { is_active_path_stream(ptr::addr_of!(PATH_STREAM)) } {
        // SAFETY: one fixed active slot is the selected capacity boundary.
        unsafe { errno::set_errno(EMFILE) };
        return ptr::null_mut();
    }

    // SAFETY: C's fopen path contract supplies a valid NUL-terminated pathname
    // for Linux's raw `open` syscall. The selected write route owns the fixed
    // `0666` creation mode and leaves umask policy to the kernel.
    let descriptor = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_OPEN,
            path as usize as i64,
            i64::from(open_mode.open_flags()),
            0o666,
        )
    };
    if descriptor < 0 {
        let _ = c_status(descriptor);
        return ptr::null_mut();
    }

    // Linux x86 file descriptors fit in `int`; retain a checked narrowing so
    // a malformed future raw boundary cannot silently create an invalid FILE.
    if descriptor > i64::from(c_int::MAX) {
        let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor) };
        // SAFETY: this impossible selected descriptor value maps to overflow.
        unsafe { errno::set_errno(EOVERFLOW) };
        return ptr::null_mut();
    }
    // SAFETY: the inactive one-slot predicate above and externally serialized
    // lifecycle grant this call ownership of the private record and storage.
    unsafe { initialize_path_stream(descriptor as c_int, open_mode.stream_flags()) }
}

/// Create one unnamed private read/write temporary-file stream.
///
/// Pinned musl requests an exclusive mode-`0600` pathname below `/tmp`, lets
/// the process umask mask that mode, unlinks it immediately, and adopts the
/// descriptor through its `w+` stream path. This bounded translation preserves
/// those observable descriptor and stream transitions while drawing a 96-bit
/// hexadecimal candidate suffix directly from Linux `getrandom`. It contains
/// no userspace PRNG and retains musl's [`TMPFILE_MAX_ATTEMPTS`]-attempt retry
/// bound. Unlike musl's clock/TID `__randname` helper, this name source has no
/// userspace random state; unlike musl's ignored unlink result, this bounded
/// route fails closed if unlinking cannot establish unnamed ownership. A busy
/// fixed stream slot fails before creating an object, and every later failure
/// closes any descriptor it has acquired.
///
/// Linux LP64 exposes `tmpfile64` only as the preprocessing alias in
/// `<stdio.h>`; no distinct ELF entry is emitted here.
///
/// # Safety
///
/// The caller must externally serialize the selected fixed-stream lifecycle
/// and close a successful result through this module's [`fclose`].
#[no_mangle]
pub unsafe extern "C" fn tmpfile() -> *mut StandardStream {
    // SAFETY: the predicate dereferences only the one private slot.
    if unsafe { is_active_path_stream(ptr::addr_of!(PATH_STREAM)) } {
        // SAFETY: the bounded runtime has no second stream record to consume.
        unsafe { errno::set_errno(EMFILE) };
        return ptr::null_mut();
    }

    let mut attempt = 0;
    let mut last_open_error = EIO;
    while attempt < TMPFILE_MAX_ATTEMPTS {
        let mut entropy = [0u8; TMPFILE_RANDOM_BYTES];
        let mut initialized = 0;
        while initialized < entropy.len() {
            // SAFETY: the not-yet-filled suffix is writable for the exact
            // remaining length and lives across the direct Linux call.
            let result = unsafe {
                raw_syscall::syscall3(
                    raw_syscall::SYS_GETRANDOM,
                    entropy.as_mut_ptr().add(initialized) as usize as i64,
                    (entropy.len() - initialized) as i64,
                    0,
                )
            };
            if result < 0 {
                let error = (-result) as c_int;
                if error == EINTR {
                    continue;
                }
                // SAFETY: the x86 static C ABI owns this thread's errno slot.
                unsafe { errno::set_errno(error) };
                return ptr::null_mut();
            }
            if result == 0 {
                // Linux 5.10 does not return a zero-length success for a
                // nonempty getrandom request. Retry defensively without
                // treating uninitialized bytes as a pathname.
                continue;
            }
            initialized += result as usize;
        }

        let mut path = *b"/tmp/tmpfile_XXXXXXXXXXXXXXXXXXXXXXXX\0";
        let hexadecimal = b"0123456789abcdef";
        let mut index = 0;
        while index < entropy.len() {
            path[TMPFILE_SUFFIX_OFFSET + index * 2] = hexadecimal[(entropy[index] >> 4) as usize];
            path[TMPFILE_SUFFIX_OFFSET + index * 2 + 1] = hexadecimal[(entropy[index] & 0x0f) as usize];
            index += 1;
        }

        // SAFETY: `path` is a live NUL-terminated pathname; O_EXCL makes the
        // name acquisition atomic, and mode 0600 supplies the musl contract.
        let descriptor = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_OPEN,
                path.as_ptr() as usize as i64,
                i64::from(O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE),
                0o600,
            )
        };
        if descriptor < 0 {
            // Pinned musl retries the entire fixed budget after every failed
            // open, not just collisions. Keep its final-open errno behavior
            // while the stronger entropy source makes ordinary collisions
            // vanishingly unlikely.
            last_open_error = (-descriptor) as c_int;
            attempt += 1;
            continue;
        }
        if descriptor > i64::from(c_int::MAX) {
            // SAFETY: this impossible future raw-boundary value still owns
            // the exclusive pathname. Retire that name before closing the
            // descriptor so no failure can leave a temporary-file entry.
            let _ = unsafe {
                raw_syscall::syscall1(raw_syscall::SYS_UNLINK, path.as_ptr() as usize as i64)
            };
            let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor) };
            // SAFETY: an unrepresentable descriptor cannot enter FILE state.
            unsafe { errno::set_errno(EOVERFLOW) };
            return ptr::null_mut();
        }

        // SAFETY: the successful exclusive path is still live and owned by
        // this call. Do not expose a FILE until the directory entry is gone.
        let unlink_status = unsafe {
            raw_syscall::syscall1(raw_syscall::SYS_UNLINK, path.as_ptr() as usize as i64)
        };
        if unlink_status < 0 {
            let unlink_error = (-unlink_status) as c_int;
            let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor) };
            // SAFETY: preserve the operation that prevented unnamed ownership.
            unsafe { errno::set_errno(unlink_error) };
            return ptr::null_mut();
        }

        // SAFETY: external serialization and the busy-slot preflight grant
        // ownership of the inactive fixed record; zero direction flags are
        // exactly the read/write `w+` stream state.
        return unsafe { initialize_path_stream(descriptor as c_int, 0) };
    }

    // SAFETY: every bounded candidate failed to open; preserve the final
    // kernel reason exactly as musl's fixed retry loop does.
    unsafe { errno::set_errno(last_open_error) };
    ptr::null_mut()
}

/// Close the one selected pathname or tmpfile stream.
///
/// Pending selected output is flushed first. The static slot is retired even
/// when flushing or closing reports an error, matching the lifecycle boundary
/// that no caller can keep using the returned opaque `FILE *` afterward.
///
/// # Safety
///
/// `stream` must be the still-active pointer returned by this module's
/// selected `fopen` or `tmpfile`, and no other caller may access it during this
/// transition.
#[no_mangle]
pub unsafe extern "C" fn fclose(stream: *mut StandardStream) -> c_int {
    // SAFETY: this predicate dereferences only the exact private pathname slot.
    if !unsafe { is_path_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return EOF;
    }
    // SAFETY: this selected path stream owns its pending output state.
    let flush_status = unsafe { flush_output(stream) };
    let flush_errno = if flush_status == EOF {
        // SAFETY: flush_output has already published this thread's error.
        unsafe { errno::get_errno() }
    } else {
        0
    };
    // SAFETY: the selected path stream owns exactly this live descriptor.
    let close_status = c_status(unsafe {
        raw_syscall::syscall1(
            raw_syscall::SYS_CLOSE,
            i64::from((*stream).file_descriptor),
        )
    });
    // SAFETY: no future call may treat this pointer as an active selected slot.
    unsafe { reset_path_stream() };
    if close_status < 0 {
        return EOF;
    }
    if flush_status == EOF {
        // SAFETY: a successful close must not hide the earlier flush errno.
        unsafe { errno::set_errno(flush_errno) };
        return EOF;
    }
    0
}

/// Install one caller-owned full buffer before pathname-stream byte I/O.
///
/// This is intentionally narrower than ISO/POSIX `setvbuf`: it admits only
/// `_IOFBF` with a non-null, nonempty caller buffer before the first selected
/// byte/block/pushback operation. `_IONBF`, `_IOLBF`, automatic allocation,
/// reconfiguration after I/O, and `setbuf`/`setbuffer`/`setlinebuf` remain
/// unselected. The caller must retain the buffer until `fclose`.
///
/// # Safety
///
/// `stream` must be the active selected pathname stream. `buffer` must point
/// to `size` writable bytes that remain valid and non-overlapping with the
/// stream state through `fclose`.
#[no_mangle]
pub unsafe extern "C" fn setvbuf(
    stream: *mut StandardStream,
    buffer: *mut core::ffi::c_char,
    mode: c_int,
    size: usize,
) -> c_int {
    // SAFETY: this predicate dereferences only the exact private pathname slot.
    if !unsafe { is_path_stream(stream) }
        || mode != _IOFBF
        || buffer.is_null()
        || size == 0
        // SAFETY: the exact active slot was proved above.
        || unsafe { (*stream).flags & F_IO_STARTED != 0 }
    {
        // SAFETY: the x86 static C ABI owns this calling thread's errno slot.
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }
    // SAFETY: pre-I/O state has no initialized buffered input/output bytes;
    // caller owns the declared buffer lifetime and capacity.
    unsafe {
        (*stream).buffer = buffer.cast::<u8>();
        (*stream).capacity = size;
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).write_position = (*stream).buffer;
        (*stream).flags |= F_EXTERNAL_BUFFER;
    }
    0
}

/// Seek a selected pathname stream at its logical, not merely kernel-buffered,
/// position.
///
/// `SEEK_CUR` subtracts any unread refill suffix before raw `lseek=8`; pending
/// output is flushed first. A successful seek discards selected read lookahead
/// and clears EOF, but leaves an existing error indication unchanged. A failed
/// positioning operation reports errno without manufacturing an I/O-error
/// indication, matching pinned musl's separation of those states.
///
/// # Safety
///
/// `stream` must be the active selected pathname stream and callers must
/// serialize access. The path slot is intended for the evidenced regular-file
/// routes; nonseekable descriptors expose their direct Linux error.
#[no_mangle]
pub unsafe extern "C" fn fseeko(
    stream: *mut StandardStream,
    offset: i64,
    whence: c_int,
) -> c_int {
    // SAFETY: this predicate dereferences only the exact private pathname slot.
    if !unsafe { is_path_stream(stream) }
        || (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END)
    {
        // SAFETY: the x86 static C ABI owns this calling thread's errno slot.
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }

    let unread = unsafe { (*stream).read_end.offset_from((*stream).read_position) };
    let adjusted_offset = if whence == SEEK_CUR {
        let unread = unread as i64;
        let Some(value) = offset.checked_sub(unread) else {
            // SAFETY: logical-position arithmetic overflow has no kernel call.
            unsafe { errno::set_errno(EOVERFLOW) };
            return EOF;
        };
        value
    } else {
        offset
    };
    // SAFETY: selected path output buffer belongs to this external lifecycle.
    if unsafe { flush_output(stream) } == EOF {
        return EOF;
    }
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from((*stream).file_descriptor),
            adjusted_offset,
            i64::from(whence),
        )
    };
    if c_off_status(result) < 0 {
        // Like pinned musl, a positioning failure reports errno without
        // changing the stream's separate I/O error indicator.
        return EOF;
    }
    // SAFETY: raw lseek established the new logical position; all old
    // prefetch and EOF state is now invalid, while the backing buffer survives.
    unsafe {
        (*stream).read_position = (*stream).buffer;
        (*stream).read_end = (*stream).buffer;
        (*stream).write_position = (*stream).buffer;
        (*stream).flags &= !F_EOF;
    }
    0
}

/// Return the selected pathname stream's logical file position.
///
/// # Safety
///
/// `stream` must be the active selected pathname stream and callers must
/// serialize access.
#[no_mangle]
pub unsafe extern "C" fn ftello(stream: *mut StandardStream) -> i64 {
    // SAFETY: this predicate dereferences only the exact private pathname slot.
    if !unsafe { is_path_stream(stream) } {
        // SAFETY: no caller stream was dereferenced on this closed boundary.
        unsafe { reject_stream() };
        return -1;
    }
    let raw_position = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from((*stream).file_descriptor),
            0,
            i64::from(SEEK_CUR),
        )
    };
    let kernel_position = c_off_status(raw_position);
    if kernel_position < 0 {
        // Like pinned musl, a position query failure is not a stream-I/O error.
        return -1;
    }
    let unread = unsafe { (*stream).read_end.offset_from((*stream).read_position) } as i64;
    let pending = if unsafe { is_writable(stream) } {
        (unsafe { (*stream).write_position.offset_from((*stream).buffer) }) as i64
    } else {
        0
    };
    let Some(logical_position) = kernel_position
        .checked_sub(unread)
        .and_then(|position| position.checked_add(pending))
    else {
        // SAFETY: logical-position arithmetic overflow has no kernel retry.
        unsafe { errno::set_errno(EOVERFLOW) };
        return -1;
    };
    logical_position
}

/// C `long` position wrapper for the selected pathname stream.
///
/// # Safety
///
/// `stream` must be the active selected pathname stream and callers must
/// serialize access.
#[no_mangle]
pub unsafe extern "C" fn ftell(stream: *mut StandardStream) -> core::ffi::c_long {
    // SAFETY: the x86 LP64 ABI gives c_long the same range as off_t here.
    unsafe { ftello(stream) as core::ffi::c_long }
}

/// C `long` seek wrapper for the selected pathname stream.
///
/// # Safety
///
/// `stream` must be the active selected pathname stream and callers must
/// serialize access.
#[no_mangle]
pub unsafe extern "C" fn fseek(
    stream: *mut StandardStream,
    offset: core::ffi::c_long,
    whence: c_int,
) -> c_int {
    // SAFETY: x86 LP64 passes the selected long offset unchanged as off_t.
    unsafe { fseeko(stream, offset as i64, whence) }
}

/// Rewind the selected pathname stream and clear its EOF/error indicators.
///
/// # Safety
///
/// `stream` must be the active selected pathname stream and callers must
/// serialize access.
#[no_mangle]
pub unsafe extern "C" fn rewind(stream: *mut StandardStream) {
    // SAFETY: fseeko validates the selected stream before touching its state.
    let _ = unsafe { fseeko(stream, 0, SEEK_SET) };
    // SAFETY: this predicate dereferences only the exact private pathname slot.
    if unsafe { is_path_stream(stream) } {
        // SAFETY: rewind owns the selected stream's status transition.
        unsafe { (*stream).flags &= !(F_EOF | F_ERR) };
    }
}

/// Store the selected pathname stream's logical offset in the first eight
/// bytes of the public opaque 16-byte `fpos_t` representation.
///
/// # Safety
///
/// `stream` must be the active selected pathname stream. `position` must
/// designate a writable 16-byte `fpos_t` object for this call.
#[no_mangle]
pub unsafe extern "C" fn fgetpos(
    stream: *mut StandardStream,
    position: *mut c_void,
) -> c_int {
    if position.is_null() {
        // SAFETY: the x86 static C ABI owns this calling thread's errno slot.
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }
    // SAFETY: ftello validates the selected stream and preserves buffer state.
    let offset = unsafe { ftello(stream) };
    if offset < 0 {
        return EOF;
    }
    // SAFETY: pinned musl stores only the logical offset prefix and preserves
    // the remaining opaque bytes. Use an unaligned store because the public
    // object is not a Rust-aligned i64 record.
    unsafe { ptr::write_unaligned(position.cast::<i64>(), offset) };
    0
}

/// Restore a selected pathname stream from the first eight bytes of the
/// public opaque `fpos_t` representation.
///
/// # Safety
///
/// `stream` must be the active selected pathname stream. `position` must
/// designate a readable 16-byte `fpos_t` object for this call.
#[no_mangle]
pub unsafe extern "C" fn fsetpos(
    stream: *mut StandardStream,
    position: *const c_void,
) -> c_int {
    if position.is_null() {
        // SAFETY: the x86 static C ABI owns this calling thread's errno slot.
        unsafe { errno::set_errno(EINVAL) };
        return EOF;
    }
    // SAFETY: caller supplies an initialized opaque fpos_t object; this
    // selected representation stores its logical byte offset first.
    let offset = unsafe { ptr::read_unaligned(position.cast::<i64>()) };
    // SAFETY: fseeko validates and performs the selected logical seek route.
    unsafe { fseeko(stream, offset, SEEK_SET) }
}
