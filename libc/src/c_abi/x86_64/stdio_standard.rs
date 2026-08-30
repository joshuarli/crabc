//! Bounded permanent-standard-stream C stdio core for Linux/x86-64.
//!
//! This target-local leaf owns only the three process-lifetime stream objects
//! exported as `stdin`, `stdout`, and `stderr`, plus their selected byte and
//! block operations: `fgetc`/`getc`/`getchar`, `ungetc`, `fread`,
//! `fputc`/`putc`/`putchar`, `fwrite`, `fflush`, `feof`, `ferror`,
//! `clearerr`, and `fileno`. The only valid non-null `FILE *` arguments are
//! those three exported pointers. It is a deliberately lock-free,
//! externally-serialized state machine: it does not select concurrent stream
//! access, `flockfile`, unlocked entry points, path streams, stream
//! allocation, formatters/scanners, seeking, buffer reconfiguration, wide
//! streams, callbacks, or an open-file registry.
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
//! | `src/stdio/{fread,fwrite,fgetc,getc,getchar,fputc,putc,putchar,ungetc}.c` | selected public byte/block entries |
//! | `src/stdio/{fflush,feof,ferror,clearerr,fileno}.c` | selected flush, status, and descriptor entries |
//!
//! The intentional boundaries are explicit. Musl's private x86 `FILE` record
//! is a 232-byte internal layout tied to its full stream list, lock state,
//! allocator, cancellation, and locale owners. This leaf instead keeps one
//! target-private typed state record for each permanently allocated stream;
//! public `FILE` remains opaque. It retains the observable `UNGET` headroom,
//! input lookahead, musl-shaped buffered-output discard-on-error behavior,
//! error/EOF state, and selected
//! C entry contracts without importing those unselected owners. `stdout`
//! is exercised only through explicit `fflush`; terminal-sensitive automatic
//! newline flushing is not selected. The existing static `exit` lifecycle
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
    ffi::{c_int, c_void},
    ptr,
};

use super::{c_ssize_status, errno, raw_syscall};

const BUFSIZ: usize = 1024;
const UNGET: usize = 8;
const STREAM_STORAGE: usize = BUFSIZ + UNGET;
const EOF: c_int = -1;
const EIO: c_int = 5;
const EOVERFLOW: c_int = 75;

// These are the selected musl stdio flags. Keeping their source values makes
// the public nonzero `feof`/`ferror` results and internal direction checks
// auditable without exposing musl's private FILE layout.
const F_PERM: u32 = 1;
const F_NORD: u32 = 4;
const F_NOWR: u32 = 8;
const F_EOF: u32 = 16;
const F_ERR: u32 = 32;

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    length: usize,
}

const _: [(); 16] = [(); core::mem::size_of::<IoVec>()];
const _: [(); 8] = [(); core::mem::align_of::<IoVec>()];

/// Private state of one permanent standard stream.
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

static mut STDIN_STREAM: StandardStream = StandardStream::new(0, F_PERM | F_NOWR);
static mut STDOUT_STREAM: StandardStream = StandardStream::new(1, F_PERM | F_NORD);
static mut STDERR_STREAM: StandardStream = StandardStream::new(2, F_PERM | F_NORD);
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
unsafe fn mark_error(stream: *mut StandardStream) {
    // SAFETY: caller owns one selected permanent stream state record.
    unsafe { (*stream).flags |= F_ERR };
}

#[inline]
unsafe fn is_readable(stream: *const StandardStream) -> bool {
    // SAFETY: caller owns one selected permanent stream state record.
    unsafe { (*stream).flags & F_NORD == 0 }
}

#[inline]
unsafe fn is_writable(stream: *const StandardStream) -> bool {
    // SAFETY: caller owns one selected permanent stream state record.
    unsafe { (*stream).flags & F_NOWR == 0 }
}

/// Refill a readable permanent stream using musl's caller-plus-lookahead
/// shape. When more than one byte is requested, Linux reads all but the final
/// requested byte directly into the caller and retains trailing input in the
/// permanent stream buffer. This preserves byte/block operation ordering
/// without reducing fgetc to an unbuffered one-byte syscall loop.
///
/// # Safety
///
/// `destination` must designate `length` writable bytes when `length` is
/// nonzero. `stream` must be one selected permanent standard-stream record.
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
        // SAFETY: a readable permanent stream always has static storage. This
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

/// Read one byte from the selected permanent input stream.
///
/// # Safety
///
/// `stream` must be one of the three exported permanent stream pointers and
/// external callers must serialize all access to that stream.
unsafe fn read_byte(stream: *mut StandardStream) -> c_int {
    // SAFETY: this initializes only permanent private state before dereference.
    unsafe { ensure_standard_streams() };
    if !unsafe { is_readable(stream) } {
        // Wrong-direction I/O is outside the selected stream contract, but a
        // local error marker prevents it from looking like ordinary EOF.
        unsafe { mark_error(stream) };
        return EOF;
    }
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
    // SAFETY: one local writable byte and a selected permanent stream satisfy
    // refill_into's complete raw-I/O contract.
    if unsafe { refill_into(stream, ptr::addr_of_mut!(byte), 1) } == 0 {
        EOF
    } else {
        c_int::from(byte)
    }
}

/// Flush the currently buffered output of one selected permanent stream.
///
/// # Safety
///
/// `stream` must be one selected permanent standard-stream record. Its state
/// is externally serialized for this lock-free first artifact.
unsafe fn flush_output(stream: *mut StandardStream) -> c_int {
    // SAFETY: the caller supplies one initialized permanent stream record.
    if !unsafe { is_writable(stream) } {
        return 0;
    }
    // SAFETY: permanent stream output storage and pointer positions were
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

/// Buffer or directly write one byte to one selected permanent output stream.
///
/// # Safety
///
/// `stream` must be one of the permanent exported stream pointers and callers
/// must externally serialize stream access.
unsafe fn write_byte(stream: *mut StandardStream, byte: u8) -> c_int {
    // SAFETY: this initializes permanent private state before dereference.
    unsafe { ensure_standard_streams() };
    if !unsafe { is_writable(stream) } {
        unsafe { mark_error(stream) };
        return EOF;
    }
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

/// Return the descriptor owned by one selected permanent stream.
///
/// # Safety
///
/// `stream` must be one of `stdin`, `stdout`, or `stderr`.
#[no_mangle]
pub unsafe extern "C" fn fileno(stream: *mut StandardStream) -> c_int {
    // SAFETY: first-use initialization cannot move permanent stream objects.
    unsafe { ensure_standard_streams() };
    // SAFETY: the selected public contract admits only the permanent pointers.
    unsafe { (*stream).file_descriptor }
}

/// Flush one permanent output stream, or every owned output stream for NULL.
///
/// Input-stream flushing, dynamic stream lists, terminal line-buffer policy,
/// and ordinary-exit flushing are outside this explicit-flush-only artifact.
///
/// # Safety
///
/// A non-null `stream` must be one of `stdin`, `stdout`, or `stderr`; callers
/// must externally serialize access to every selected stream being flushed.
#[no_mangle]
pub unsafe extern "C" fn fflush(stream: *mut StandardStream) -> c_int {
    // SAFETY: permanent static state does not require a CRT initializer.
    unsafe { ensure_standard_streams() };
    if stream.is_null() {
        // SAFETY: these are the only output streams owned by this first
        // artifact. Preserve both flush attempts like musl's global walk.
        let stdout_status = unsafe { flush_output(ptr::addr_of_mut!(STDOUT_STREAM)) };
        let stderr_status = unsafe { flush_output(ptr::addr_of_mut!(STDERR_STREAM)) };
        if stdout_status == EOF || stderr_status == EOF {
            EOF
        } else {
            0
        }
    } else {
        // SAFETY: caller supplies one selected permanent stream pointer.
        unsafe { flush_output(stream) }
    }
}

/// Read one byte from a selected permanent stream.
///
/// # Safety
///
/// `stream` must be one exported permanent stream pointer and its access must
/// be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn fgetc(stream: *mut StandardStream) -> c_int {
    // SAFETY: caller supplies the selected permanent stream state contract.
    unsafe { read_byte(stream) }
}

/// C's `getc` function entry for one selected permanent stream.
///
/// # Safety
///
/// `stream` must be one exported permanent stream pointer and its access must
/// be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn getc(stream: *mut StandardStream) -> c_int {
    // SAFETY: preserves the fgetc selected permanent-stream contract.
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
    c_int::from(character as u8)
}

/// Read complete elements from one selected permanent input stream.
///
/// # Safety
///
/// `destination` must designate `size * count` writable bytes when both are
/// nonzero. `stream` must be one selected permanent stream pointer and its
/// access must be externally serialized.
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
    // SAFETY: selected permanent state exists before its direction and buffer
    // fields are observed.
    unsafe { ensure_standard_streams() };
    if !unsafe { is_readable(stream) } {
        unsafe { mark_error(stream) };
        return 0;
    }

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

/// Write one byte to a selected permanent output stream.
///
/// # Safety
///
/// `stream` must be one exported permanent stream pointer and its access must
/// be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn fputc(character: c_int, stream: *mut StandardStream) -> c_int {
    // SAFETY: preserves the selected permanent-output-stream contract.
    unsafe { write_byte(stream, character as u8) }
}

/// C's `putc` function entry for a selected permanent output stream.
///
/// # Safety
///
/// `stream` must be one exported permanent stream pointer and its access must
/// be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn putc(character: c_int, stream: *mut StandardStream) -> c_int {
    // SAFETY: preserves the fputc selected permanent-stream contract.
    unsafe { fputc(character, stream) }
}

/// C's `putchar` function entry for permanent standard output.
#[no_mangle]
pub unsafe extern "C" fn putchar(character: c_int) -> c_int {
    // SAFETY: this module owns the permanent stdout object and its state
    // remains externally serialized by the artifact contract.
    unsafe { fputc(character, ptr::addr_of_mut!(STDOUT_STREAM)) }
}

/// Write complete elements to one selected permanent output stream.
///
/// # Safety
///
/// `source` must designate `size * count` readable bytes when both are
/// nonzero. `stream` must be one selected permanent stream pointer and its
/// access must be externally serialized.
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
    // SAFETY: permanent stream state must exist before its direction is read.
    unsafe { ensure_standard_streams() };
    if !unsafe { is_writable(stream) } {
        unsafe { mark_error(stream) };
        return 0;
    }

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

/// Return the selected EOF-state marker for one permanent stream.
///
/// # Safety
///
/// `stream` must be one exported permanent stream pointer.
#[no_mangle]
pub unsafe extern "C" fn feof(stream: *mut StandardStream) -> c_int {
    // SAFETY: permanent state must exist before the selected flag is read.
    unsafe { ensure_standard_streams() };
    // SAFETY: caller supplies one selected permanent stream pointer.
    unsafe { ((*stream).flags & F_EOF) as c_int }
}

/// Return the selected error-state marker for one permanent stream.
///
/// # Safety
///
/// `stream` must be one exported permanent stream pointer.
#[no_mangle]
pub unsafe extern "C" fn ferror(stream: *mut StandardStream) -> c_int {
    // SAFETY: permanent state must exist before the selected flag is read.
    unsafe { ensure_standard_streams() };
    // SAFETY: caller supplies one selected permanent stream pointer.
    unsafe { ((*stream).flags & F_ERR) as c_int }
}

/// Clear EOF and error markers on one permanent stream.
///
/// # Safety
///
/// `stream` must be one exported permanent stream pointer and its access must
/// be externally serialized.
#[no_mangle]
pub unsafe extern "C" fn clearerr(stream: *mut StandardStream) {
    // SAFETY: permanent state must exist before its selected flags are reset.
    unsafe { ensure_standard_streams() };
    // SAFETY: caller supplies one selected permanent stream pointer.
    unsafe { (*stream).flags &= !(F_EOF | F_ERR) };
}
