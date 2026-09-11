//! Private Linux/x86-64 environment and command-process adapter for the
//! unselected deterministic `wordexp` candidate.
//!
//! This binds only the candidate core's narrow `WordexpContext` and
//! `WordexpCommandAdapter` seams.  It deliberately does not select the C ABI
//! provider in `owned_wordexp.rs`, create a second process implementation, or
//! decide the public `wordexp_t` status/ownership contract.  Its durable
//! boundary and remaining integration work are recorded in
//! `compat/x86_64/owned-wordexp-process.md`.
//!
//! The environment snapshot is taken under the ordinary C caller obligation
//! that `__environ`, its terminating vector, and every pointed-to C string
//! remain readable and unchanged until this constructor returns.  The caller
//! similarly keeps the active LC_CTYPE selection stable for that one locale
//! query.  After construction, the copied non-identifier entries no longer
//! borrow the process environment; the core's identifier values are also
//! call-local.  This adapter never invokes `setenv`, `putenv`, `unsetenv`, or
//! `clearenv`, and therefore never mutates the parent environment.
//!
//! `WordexpProcessAdapter::execute` has an additional lifecycle precondition:
//! its caller must have disabled deferred cancellation until the adapter has
//! closed its output descriptor and reaped or observed its child.  The
//! selected `wordexp` C ABI wrapper already establishes that complete-call
//! cancellation boundary; a later candidate binding must retain it.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the private x86 wordexp process adapter requires little-endian Linux/x86-64");

use core::{
    ffi::{c_char, c_int, c_void},
    mem::size_of,
    ptr,
    slice,
};

use super::{
    environment, errno, locale_multibyte, owned_spawn,
    posix_spawn_file_actions::{FdOp, PosixSpawnFileActions}, raw_syscall,
};
use super::owned_wordexp_engine::{
    CommandOutput, CommandStyle, WordexpCommandAdapter, WordexpContext,
    WordexpError, WordexpLocaleMode,
};

const CLOEXEC: i64 = 0x80000;
const ECHILD: c_int = 10;
const EIO: c_int = 5;
const EINTR: i64 = 4;
const SIGKILL: i64 = 9;
const FDOP_DUP2: c_int = 2;
// `pointer.add` and the C allocation boundary both require a representable
// signed offset. Keep every private allocation within the same Rust bound.
const MAX_C_ALLOCATION: usize = isize::MAX as usize;

const SH: &[u8] = b"/bin/sh\0";
const SH_ARG0: &[u8] = b"sh\0";
const SH_C: &[u8] = b"-c\0";
const QUIET_STDERR_PREFIX: &[u8] = b"exec 2>/dev/null;\n";

unsafe extern "C" {
    #[link_name = "realloc"]
    fn wordexp_process_realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn wordexp_process_free(pointer: *mut c_void);
}

/// Grow one C allocation without allowing either element count or byte size
/// to cross Rust's signed-offset allocation limit.
fn grown_c_allocation<T>(
    capacity: usize,
    initial_capacity: usize,
) -> Result<(usize, usize), WordexpError> {
    let capacity = if capacity == 0 {
        initial_capacity
    } else {
        capacity.checked_mul(2).ok_or(WordexpError::NoSpace)?
    };
    let bytes = capacity
        .checked_mul(size_of::<T>())
        .ok_or(WordexpError::NoSpace)?;
    if bytes > MAX_C_ALLOCATION { return Err(WordexpError::NoSpace); }
    Ok((capacity, bytes))
}

/// C-allocator-backed growable storage with no Rust allocator dependency.
///
/// It deliberately has no inline capacity so every retained environment byte
/// and process-script byte has the same selected C allocation owner as the
/// core candidate.
struct CBuffer {
    pointer: *mut u8,
    length: usize,
    capacity: usize,
}

impl CBuffer {
    const fn new() -> Self {
        Self { pointer: ptr::null_mut(), length: 0, capacity: 0 }
    }

    #[inline]
    const fn len(&self) -> usize { self.length }

    fn push(&mut self, byte: u8) -> Result<(), WordexpError> {
        if self.length == self.capacity {
            let (capacity, bytes) = grown_c_allocation::<u8>(self.capacity, 64)?;
            let grown = unsafe {
                // SAFETY: `pointer` is null or this buffer's own C allocation.
                wordexp_process_realloc(self.pointer.cast(), bytes)
            }.cast::<u8>();
            if grown.is_null() { return Err(WordexpError::NoSpace); }
            self.pointer = grown;
            self.capacity = capacity;
        }
        // SAFETY: growth reserves the next initialized byte.
        unsafe { ptr::write(self.pointer.add(self.length), byte); }
        self.length += 1;
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), WordexpError> {
        for byte in bytes {
            self.push(*byte)?;
        }
        Ok(())
    }

    unsafe fn slice(&self, start: usize, length: usize) -> &[u8] {
        debug_assert!(start <= self.length && length <= self.length - start);
        if length == 0 {
            &[]
        } else {
            // SAFETY: callers prove the requested range is initialized here.
            unsafe { slice::from_raw_parts(self.pointer.add(start), length) }
        }
    }

    unsafe fn c_string_at(&self, start: usize) -> *const c_char {
        debug_assert!(start < self.length);
        // SAFETY: callers retain an entry span whose copied terminator follows
        // this byte inside the allocation.
        unsafe { self.pointer.add(start).cast::<c_char>() }
    }

    unsafe fn as_c_string(&self) -> *const c_char {
        debug_assert!(self.length != 0);
        // SAFETY: script construction appends exactly one trailing NUL.
        self.pointer.cast::<c_char>()
    }
}

impl Drop for CBuffer {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: this buffer exclusively owns the allocation.
            unsafe { wordexp_process_free(self.pointer.cast()); }
        }
    }
}

/// C-allocator-backed vectors are used for pointers and spans so a private
/// adapter never pulls Rust `alloc` into the libc artifact.
struct CVector<T: Copy> {
    pointer: *mut T,
    length: usize,
    capacity: usize,
}

impl<T: Copy> CVector<T> {
    const fn new() -> Self {
        Self { pointer: ptr::null_mut(), length: 0, capacity: 0 }
    }

    #[inline]
    const fn len(&self) -> usize { self.length }

    fn push(&mut self, value: T) -> Result<(), WordexpError> {
        if self.length == self.capacity {
            let (capacity, bytes) = grown_c_allocation::<T>(self.capacity, 8)?;
            let grown = unsafe {
                // SAFETY: `pointer` is null or this vector's own C allocation.
                wordexp_process_realloc(self.pointer.cast(), bytes)
            }.cast::<T>();
            if grown.is_null() { return Err(WordexpError::NoSpace); }
            self.pointer = grown;
            self.capacity = capacity;
        }
        // SAFETY: growth reserves the next initialized element.
        unsafe { ptr::write(self.pointer.add(self.length), value); }
        self.length += 1;
        Ok(())
    }

    unsafe fn get(&self, index: usize) -> T {
        debug_assert!(index < self.length);
        // SAFETY: callers prove the index names an initialized element.
        unsafe { ptr::read(self.pointer.add(index)) }
    }

    #[inline]
    fn as_ptr(&self) -> *const T { self.pointer.cast_const() }
}

impl<T: Copy> Drop for CVector<T> {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: this vector exclusively owns the allocation.
            unsafe { wordexp_process_free(self.pointer.cast()); }
        }
    }
}

#[derive(Clone, Copy)]
struct ByteSpan {
    start: usize,
    length: usize,
}

/// A copied, call-local view of the portion of `envp` that the shell core
/// cannot model as identifiers.
///
/// Valid `NAME=value` identifiers are installed once, in first-match order,
/// in `WordexpContext` as exported values.  Every other original entry is
/// retained byte-for-byte here and is supplied to the child alongside the
/// core's current exported overlays.  This mirrors `environment::getenv`'s
/// first-match rule without allowing a later duplicate to overwrite the
/// context's value.
pub(super) struct WordexpEnvironmentSnapshot {
    non_identifier_bytes: CBuffer,
    non_identifier_entries: CVector<ByteSpan>,
}

impl WordexpEnvironmentSnapshot {
    /// Copy the current selected environment into a fresh wordexp context.
    ///
    /// # Safety
    /// `environment::__environ` must name a readable, null-terminated pointer
    /// vector (or be null), and every non-null entry must remain a readable
    /// NUL-terminated C string until this function returns.  The caller also
    /// keeps the selected LC_CTYPE state stable during this call.  `context`
    /// must be a fresh call-local context that the caller discards if this
    /// constructor returns an error; a failure can leave earlier copied
    /// variables installed in it.
    pub(super) unsafe fn capture(
        context: &mut WordexpContext,
    ) -> Result<Self, WordexpError> {
        let mode = if locale_multibyte::locale_ctype_is_utf8() {
            WordexpLocaleMode::CUtf8
        } else {
            WordexpLocaleMode::C
        };
        context.set_locale_mode(mode);

        let mut snapshot = Self {
            non_identifier_bytes: CBuffer::new(),
            non_identifier_entries: CVector::new(),
        };
        let mut seen_name_bytes = CBuffer::new();
        let mut seen_names = CVector::<ByteSpan>::new();
        let mut has_ifs = false;

        // Take a raw machine-word snapshot, just as the selected `getenv` and
        // `execv` adapters do.  Constructing a Rust reference to this mutable
        // C global would claim stronger synchronization than the C contract.
        let environment = unsafe { ptr::read(ptr::addr_of!(environment::__environ)) };
        if !environment.is_null() {
            let mut index = 0usize;
            loop {
                // SAFETY: the caller's vector remains readable through its
                // terminating null pointer for this constructor.
                let entry = unsafe { ptr::read(environment.add(index)) };
                if entry.is_null() { break; }
                let (length, separator) = unsafe { environment_entry_shape(entry) }?;
                // SAFETY: `length` was measured before the entry's NUL.
                let bytes = unsafe { slice::from_raw_parts(entry.cast::<u8>(), length) };
                if let Some(separator) = separator {
                    let name = &bytes[..separator];
                    let value = &bytes[separator + 1..];
                    if valid_shell_identifier(name) {
                        if !seen_contains(&seen_name_bytes, &seen_names, name) {
                            context.set_initial(name, Some(value), true)?;
                            let start = seen_name_bytes.len();
                            seen_name_bytes.append(name)?;
                            seen_names.push(ByteSpan { start, length: name.len() })?;
                            if name == b"IFS" {
                                // Keep the ordinary variable record and the
                                // core's splitting state as one snapshot.
                                context.set_ifs(Some(value))?;
                                has_ifs = true;
                            }
                        }
                    } else {
                        snapshot.retain_non_identifier(bytes)?;
                    }
                } else {
                    snapshot.retain_non_identifier(bytes)?;
                }
                index = index.checked_add(1).ok_or(WordexpError::NoSpace)?;
            }
        }
        if !has_ifs {
            // Absence is semantically different from an explicit empty IFS.
            context.set_ifs(None)?;
        }
        Ok(snapshot)
    }

    /// Borrow this immutable snapshot for one command-substitution adapter.
    /// `show_errors` is the selected C API's WRDE_SHOWERR decision already
    /// made by a later binding; this private adapter does not inspect C flags.
    pub(super) fn process_adapter(&self, show_errors: bool) -> WordexpProcessAdapter<'_> {
        WordexpProcessAdapter { environment: self, show_errors }
    }

    fn retain_non_identifier(&mut self, entry: &[u8]) -> Result<(), WordexpError> {
        let start = self.non_identifier_bytes.len();
        self.non_identifier_bytes.append(entry)?;
        self.non_identifier_bytes.push(0)?;
        self.non_identifier_entries.push(ByteSpan { start, length: entry.len() })
    }
}

/// The concrete process adapter borrows one immutable environment snapshot.
/// It has no process-global mutable state and owns every per-command script,
/// `envp` vector, pipe descriptor, and child lifecycle locally.
pub(super) struct WordexpProcessAdapter<'snapshot> {
    environment: &'snapshot WordexpEnvironmentSnapshot,
    show_errors: bool,
}

/// A temporary `envp` pointer vector.  The non-identifier pointers borrow the
/// copied snapshot; exported entries borrow the core's argument only through
/// `spawn_with_outcome`, which does not return success until exec closed its
/// CLOEXEC error pipe.
struct ChildEnvironment {
    entries: CVector<*const c_char>,
}

impl ChildEnvironment {
    fn build(
        snapshot: &WordexpEnvironmentSnapshot,
        exported_entries: &[u8],
    ) -> Result<Self, WordexpError> {
        let mut environment = Self { entries: CVector::new() };
        let mut index = 0usize;
        while index < snapshot.non_identifier_entries.len() {
            // SAFETY: this index names one copied NUL-terminated entry.
            let entry = unsafe { snapshot.non_identifier_entries.get(index) };
            // SAFETY: retain_non_identifier appended this exact terminator.
            let pointer = unsafe { snapshot.non_identifier_bytes.c_string_at(entry.start) };
            environment.entries.push(pointer)?;
            index += 1;
        }

        let mut cursor = 0usize;
        while let Some(entry) = exported_entry(exported_entries, &mut cursor)? {
            // The core emits its own NUL-delimited entries.  Keeping a pointer
            // into that live argument avoids a second copied value while the
            // owned spawn transaction still needs it.
            let pointer = unsafe {
                exported_entries.as_ptr().add(entry.start).cast::<c_char>()
            };
            environment.entries.push(pointer)?;
        }
        environment.entries.push(ptr::null())?;
        Ok(environment)
    }

    #[inline]
    fn as_ptr(&self) -> *const *const c_char { self.entries.as_ptr() }
}

#[derive(Clone, Copy)]
struct ExportedEntry {
    start: usize,
    name_end: usize,
    end: usize,
}

impl ExportedEntry {
    fn value<'a>(self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.name_end + 1..self.end]
    }
}

/// Decode one core-owned NUL-delimited exported entry.  A malformed entry is
/// an internal contract failure, not an ambient environment fallback.
fn exported_entry(
    entries: &[u8],
    cursor: &mut usize,
) -> Result<Option<ExportedEntry>, WordexpError> {
    if *cursor == entries.len() { return Ok(None); }
    let start = *cursor;
    let mut end = start;
    while end < entries.len() && entries[end] != 0 {
        end += 1;
    }
    if end == entries.len() { return Err(WordexpError::Syntax); }
    let mut separator = start;
    while separator < end && entries[separator] != b'=' {
        separator += 1;
    }
    if separator == start || separator == end ||
        !valid_shell_identifier(&entries[start..separator])
    {
        return Err(WordexpError::Syntax);
    }
    *cursor = end + 1;
    Ok(Some(ExportedEntry { start, name_end: separator, end }))
}

fn exported_ifs(entries: &[u8]) -> Result<Option<&[u8]>, WordexpError> {
    let mut cursor = 0usize;
    while let Some(entry) = exported_entry(entries, &mut cursor)? {
        if &entries[entry.start..entry.name_end] == b"IFS" {
            return Ok(Some(entry.value(entries)));
        }
    }
    Ok(None)
}

fn append_single_quoted_assignment(
    script: &mut CBuffer,
    name: &[u8],
    value: &[u8],
) -> Result<(), WordexpError> {
    script.append(name)?;
    script.append(b"='")?;
    for byte in value {
        if *byte == b'\'' {
            script.append(b"'\\''")?;
        } else {
            script.push(*byte)?;
        }
    }
    script.append(b"'\n")
}

/// Apply the narrowly specified quote removal for an already-scanned
/// backquoted body.  This does not parse or execute the body a second time.
///
/// Backticks outside double quotes remove a backslash only before `$`, a
/// backquote, another backslash, or a physical newline.  Within double
/// quotes, the core's `CommandStyle` context additionally makes `\"` subject
/// to this one escape-removal rule.
fn append_backtick_body(
    script: &mut CBuffer,
    body: &[u8],
    double_quoted: bool,
) -> Result<(), WordexpError> {
    let mut index = 0usize;
    while index < body.len() {
        let byte = body[index];
        if byte == b'\\' && index + 1 < body.len() {
            let next = body[index + 1];
            if next == b'\n' {
                // A backslash followed by a physical newline is a line
                // continuation: POSIX removes both bytes before the shell
                // receives the opaque command body.
                index += 2;
                continue;
            }
            if matches!(next, b'$' | b'`' | b'\\') ||
                (double_quoted && next == b'"')
            {
                script.push(next)?;
                index += 2;
                continue;
            }
        }
        script.push(byte)?;
        index += 1;
    }
    Ok(())
}

fn command_script(
    body: &[u8],
    style: CommandStyle,
    assignment_prefix: &[u8],
    exported_entries: &[u8],
    show_errors: bool,
) -> Result<CBuffer, WordexpError> {
    let mut script = CBuffer::new();
    if !show_errors {
        // This must run before parsing the delegated body, matching the
        // selected provider's POSIX correction for shell parse diagnostics.
        script.append(QUIET_STDERR_PREFIX)?;
    }
    if let Some(ifs) = exported_ifs(exported_entries)? {
        // POSIX `sh` ignores inherited IFS at startup.  Restore the call-local
        // exported value explicitly, rather than letting an envp overlay lose
        // the core's current splitting semantics in the child shell.
        append_single_quoted_assignment(&mut script, b"IFS", ifs)?;
    }
    // The core has already made this a sequence of standalone shell
    // assignments.  It is intentionally not converted into temporary envp
    // bindings for the first simple command in `body`.
    script.append(assignment_prefix)?;
    match style {
        CommandStyle::DollarParen => script.append(body)?,
        CommandStyle::Backtick { double_quoted } => {
            append_backtick_body(&mut script, body, double_quoted)?;
        }
    }
    script.push(0)?;
    Ok(script)
}

#[inline]
unsafe fn close(descriptor: c_int) {
    // SAFETY: each caller owns this private descriptor exactly once.  Errors
    // are intentionally not allowed to overwrite the boundary's primary
    // allocation/read/spawn error.
    unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor as i64); }
}

unsafe fn reap(process: c_int) -> Result<(), c_int> {
    let mut status = 0;
    loop {
        // SAFETY: `status` is private writable storage and this adapter owns
        // the successful `owned_spawn` child until wait reports otherwise.
        let result = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_WAIT4,
                process as i64,
                ptr::addr_of_mut!(status) as i64,
                0,
                0,
            )
        };
        if result == -EINTR { continue; }
        if result == process as i64 { return Ok(()); }
        if result >= 0 { return Err(EIO); }
        return Err((-result) as c_int);
    }
}

unsafe fn kill_and_reap(process: c_int) {
    if process <= 0 { return; }
    // Closing the read side may only provoke SIGPIPE; a shell or descendant
    // can ignore it, so always force the process leader down before reaping.
    let _ = unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_KILL, process as i64, SIGKILL)
    };
    let _ = unsafe { reap(process) };
}

impl WordexpCommandAdapter for WordexpProcessAdapter<'_> {
    fn execute(
        &mut self,
        body: &[u8],
        style: CommandStyle,
        assignment_prefix: &[u8],
        exported_entries: &[u8],
        output: &mut CommandOutput<'_>,
    ) -> Result<(), WordexpError> {
        let script = command_script(
            body,
            style,
            assignment_prefix,
            exported_entries,
            self.show_errors,
        )?;
        let child_environment = ChildEnvironment::build(self.environment, exported_entries)?;

        let mut pipes = [-1_i32; 2];
        let pipe_result = unsafe {
            // SAFETY: `pipes` is private writable storage for Linux pipe2.
            raw_syscall::syscall2(
                raw_syscall::SYS_PIPE2,
                pipes.as_mut_ptr() as i64,
                CLOEXEC,
            )
        };
        if pipe_result < 0 {
            unsafe { errno::set_errno((-pipe_result) as c_int); }
            return Err(WordexpError::NoSpace);
        }

        let mut action = FdOp {
            next: ptr::null_mut(),
            prev: ptr::null_mut(),
            cmd: FDOP_DUP2,
            fd: 1,
            srcfd: pipes[1],
            oflag: 0,
            mode: 0,
        };
        let actions = PosixSpawnFileActions {
            _pad0: [0; 2],
            actions: ptr::addr_of_mut!(action).cast(),
            _pad: [0; 16],
        };
        let arguments = [
            SH_ARG0.as_ptr().cast::<c_char>(),
            SH_C.as_ptr().cast::<c_char>(),
            unsafe { script.as_c_string() },
            ptr::null(),
        ];
        let errno_before_spawn = unsafe { errno::get_errno() };
        let mut process = 0;
        let spawned = unsafe {
            // SAFETY: stack-local action/argv and C-allocated script/envp
            // remain live through this transaction.  On success the owner has
            // observed exec's CLOEXEC handoff before these buffers drop.
            owned_spawn::spawn_with_outcome(
                &mut process,
                SH.as_ptr().cast(),
                &actions,
                ptr::null(),
                arguments.as_ptr(),
                child_environment.as_ptr(),
                false,
            )
        };
        match spawned {
            owned_spawn::SpawnOutcome::Success => {}
            owned_spawn::SpawnOutcome::ParentFailure(error) => {
                unsafe {
                    close(pipes[0]);
                    close(pipes[1]);
                    errno::set_errno(error);
                }
                return Err(WordexpError::NoSpace);
            }
            owned_spawn::SpawnOutcome::ChildFailure(_) => {
                // owned_spawn has already reaped the child that failed before
                // `/bin/sh -c` began.  Preserve the selected adapter's source
                // boundary: this is not a command status or stderr diagnosis,
                // and the child-side errno cannot overwrite the parent's
                // pre-spawn errno.
                unsafe {
                    close(pipes[0]);
                    close(pipes[1]);
                    errno::set_errno(errno_before_spawn);
                }
                return Err(WordexpError::Syntax);
            }
        }
        if process <= 0 {
            // Successful owned_spawn must transfer a live positive PID.  This
            // defensive internal-contract failure has no child to reap.
            unsafe {
                close(pipes[0]);
                close(pipes[1]);
            }
            return Err(WordexpError::NoSpace);
        }

        // The child now owns the duplicate source until exec closes CLOEXEC;
        // this parent must retire its write end before reading to EOF.
        unsafe { close(pipes[1]); }
        let read_descriptor = pipes[0];
        let mut bytes = [0u8; 4096];
        loop {
            let read = unsafe {
                // SAFETY: the pipe read end and local output buffer remain
                // valid for this raw read invocation.
                raw_syscall::syscall3(
                    raw_syscall::SYS_READ,
                    read_descriptor as i64,
                    bytes.as_mut_ptr() as i64,
                    bytes.len() as i64,
                )
            };
            if read == -EINTR { continue; }
            if read < 0 {
                unsafe {
                    close(read_descriptor);
                    kill_and_reap(process);
                    errno::set_errno((-read) as c_int);
                }
                return Err(WordexpError::NoSpace);
            }
            if read == 0 { break; }
            if read > bytes.len() as i64 {
                // A kernel cannot return more than the requested buffer, but
                // retain a fail-closed path for a corrupted/mock boundary.
                unsafe {
                    close(read_descriptor);
                    kill_and_reap(process);
                }
                return Err(WordexpError::NoSpace);
            }
            let append = output.append(&bytes[..read as usize]);
            if let Err(error) = append {
                unsafe {
                    close(read_descriptor);
                    kill_and_reap(process);
                }
                return Err(error);
            }
        }
        unsafe { close(read_descriptor); }
        match unsafe { reap(process) } {
            Ok(()) => {}
            Err(ECHILD) => {
                // With SIGCHLD ignored or SA_NOCLDWAIT set, POSIX discards
                // child status and wait reports ECHILD after its stdout pipe
                // has reached EOF. The selected wordexp reap path likewise
                // ignores this final result, and this engine intentionally
                // has no exit-status semantics. Do not signal a recycled PID
                // or overwrite the caller's errno for this successful output.
            }
            Err(error) => {
                unsafe {
                    kill_and_reap(process);
                    errno::set_errno(error);
                }
                return Err(WordexpError::NoSpace);
            }
        }
        // Exit status is deliberately ignored: command substitution uses
        // stdout bytes, and ordinary nonzero command status is not a typed
        // undefined-variable or syntax failure.
        Ok(())
    }
}

/// Return an entry's byte length excluding its terminator and its first `=`.
/// A valid C environment entry is caller-owned; overflow is represented as a
/// local resource error rather than wrapping this adapter's copied storage.
unsafe fn environment_entry_shape(
    entry: *const c_char,
) -> Result<(usize, Option<usize>), WordexpError> {
    let mut length = 0usize;
    let mut separator = None;
    loop {
        // SAFETY: the capture caller retains the valid C-string obligation.
        let byte = unsafe { ptr::read(entry.add(length).cast::<u8>()) };
        if byte == 0 { return Ok((length, separator)); }
        if byte == b'=' && separator.is_none() { separator = Some(length); }
        length = length.checked_add(1).ok_or(WordexpError::NoSpace)?;
    }
}

fn valid_shell_identifier(name: &[u8]) -> bool {
    if name.is_empty() || !(name[0].is_ascii_alphabetic() || name[0] == b'_') {
        return false;
    }
    name[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn seen_contains(bytes: &CBuffer, names: &CVector<ByteSpan>, name: &[u8]) -> bool {
    let mut index = 0usize;
    while index < names.len() {
        // SAFETY: the index names an initialized seen-name span.
        let span = unsafe { names.get(index) };
        if span.length == name.len() {
            // SAFETY: every seen span names copied initialized name bytes.
            if unsafe { bytes.slice(span.start, span.length) } == name {
                return true;
            }
        }
        index += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_allocation_growth_refuses_signed_offset_overflow_without_reallocating() {
        let mut bytes = CBuffer {
            pointer: ptr::null_mut(),
            length: MAX_C_ALLOCATION,
            capacity: MAX_C_ALLOCATION,
        };
        assert_eq!(bytes.push(b'x'), Err(WordexpError::NoSpace));

        let capacity = MAX_C_ALLOCATION / size_of::<*const c_char>();
        let mut entries = CVector::<*const c_char> {
            pointer: ptr::null_mut(),
            length: capacity,
            capacity,
        };
        assert_eq!(entries.push(ptr::null()), Err(WordexpError::NoSpace));
    }
}
