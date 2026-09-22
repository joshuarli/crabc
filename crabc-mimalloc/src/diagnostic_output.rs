// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/options.c:15-16,111-178,347-549`,
// its `mi_vfprintf_thread` prefix at `src/options.c:498-507`, the selected
// `%tx` formatter route at `src/libc.c:254-261,285-307,313-397`, and Linux
// thread identity at `include/mimalloc/prim-tls.h:170-190` /
// `src/prim/prim-tls.c:34-38`, the warning gate's C11 fetch-add at
// `include/mimalloc/atomic.h:88,98`, final MI_STAT=0 formatting and process
// information at `src/stats.c:151-430,568-597`, and its retained/physical
// process ordering at `src/init.c:633-650` / `src/subproc.c:241-245`.
//
// The C source keeps one 16 KiB delayed byte buffer, one lock, independently
// published output function/argument pointers, and an AcqRel warning counter.
// This private owner preserves those observable transitions without exporting
// a `mi_*` ABI or putting callback state in the VM policy. The source's
// built-in callbacks are C statics and can reach static `out_buf` directly.
// Rust permits several test-local owners, so `default_sink` represents those
// three built-ins while the custom callback and opaque argument retain their
// separate source-shaped atomic publication. The source's `fputs(msg,stderr)`
// primitive stays caller-supplied: this owner does not assert that a raw Linux
// descriptor write has FILE buffering, locking, or failure equivalence.

use crate::config::VmOptionEnvironmentReader;
use crate::lock::PrivateLock;
use crate::os::ProcessUsage;
use crate::statistics::{
    FinalStatCount, FinalStatisticsSnapshot, ProcessInfoCommittedDefaults,
};
use crabc_core::{Errno, thread::thread_pointer_identity};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void, CStr};
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

const INITIAL_MAX_WARNING_COUNT: isize = 16;
const DELAYED_OUTPUT_BYTES: usize = 16 * 1024;
const SOURCE_FORMAT_STORAGE_BYTES: usize = 992;
const SOURCE_FORMAT_PAYLOAD_BYTES: usize = SOURCE_FORMAT_STORAGE_BYTES - 2;

const DEFAULT_DELAYED: u8 = 0;
const DEFAULT_STDERR: u8 = 1;
const DEFAULT_STDERR_AND_DELAYED: u8 = 2;
const DEFAULT_CALLBACK: u8 = 3;

const THREAD_WARNING_PREFIX_BYTES: usize = 64;
const WARNING_PREFIX_HEAD: &[u8] = b"mimalloc: warning: thread 0x";
const WARNING_PREFIX_TAIL: &[u8] = b": ";
const FINAL_NOT_ALL_FREED: &[u8] = b"not all freed";
const FINAL_EXPLICIT_EMPTY_NOT_OK: &[u8] = b"";

/// The four descriptors consumed by this intentionally partial M7 owner.
///
/// This mirrors only `show_errors`, `show_stats`, `verbose`, and `max_warnings` in the
/// pinned table. It does not parse an environment, mutate options, or claim
/// any other `src/options.c` descriptor/API.
#[derive(Clone, Copy)]
pub(crate) struct DiagnosticOptionSnapshot {
    show_errors: isize,
    show_stats: isize,
    verbose: isize,
    max_warnings: isize,
}


#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub struct RuntimeStderrOutput {
    invoke: DefaultStderrOutput,
}

#[cfg(target_arch = "x86_64")]
impl RuntimeStderrOutput {
    /// Wraps the selected process FILE output primitive for the private x86
    /// runtime initializer.
    ///
    /// # Safety
    ///
    /// `invoke` must remain callable for this process lifetime; accept each
    /// non-null NUL-terminated fragment; never unwind through the C ABI; and
    /// preserve the selected `fputs(message, stderr)` FILE behavior, including
    /// its locking, buffering, and error/short-write semantics. Pinned
    /// `_mi_prim_out_stderr` deliberately ignores `fputs`'s integer result.
    /// During this private slice it must also not synchronously reenter
    /// `warning_from_source_options` or `MbindWarningRoute`: staged invalid
    /// `verbose` restoration precedes foreign delivery. A raw descriptor
    /// write, an ambient symbol lookup, or a no-op callback does not satisfy
    /// this capability.
    #[inline]
    pub const unsafe fn new(invoke: unsafe extern "C" fn(*const c_char)) -> Self {
        Self { invoke }
    }

    #[inline]
    pub(crate) const fn into_default_stderr_output(self) -> DefaultStderrOutput {
        self.invoke
    }
}

/// Mandatory process-startup inputs for this private diagnostic owner.
///
/// This is not a VM-policy input: it retains exactly the raw environment
/// reader needed for the four selected `options.c` descriptors and the
/// caller-owned FILE primitive held by [`OutputOwner`] for process life.
pub(crate) struct ProcessDiagnosticInputs {
    environment_reader: VmOptionEnvironmentReader,
    default_stderr_output: DefaultStderrOutput,
}

impl ProcessDiagnosticInputs {
    /// Builds the one source-startup diagnostic input image.
    ///
    /// # Safety
    ///
    /// `environment_reader` must satisfy [`VmOptionEnvironmentReader`] on
    /// every selected descriptor retry. Each read needs the same foreign
    /// environment-vector validity and direct-mutation coordination as the
    /// existing VM option reader; a coordinated later environment vector may
    /// therefore replace the startup observation. `default_stderr_output` has
    /// the lifetime and selected FILE obligations
    /// documented on [`RuntimeStderrOutput::new`] for x86 callers.
    #[inline]
    pub(crate) const unsafe fn new(
        environment_reader: VmOptionEnvironmentReader,
        default_stderr_output: DefaultStderrOutput,
    ) -> Self {
        Self { environment_reader, default_stderr_output }
    }

    #[inline]
    pub(crate) const fn environment_reader(&self) -> VmOptionEnvironmentReader {
        self.environment_reader
    }

    #[inline]
    pub(crate) const fn into_parts(self) -> (VmOptionEnvironmentReader, DefaultStderrOutput) {
        (self.environment_reader, self.default_stderr_output)
    }
}

const DIAGNOSTIC_DESCRIPTOR_COUNT: usize = 4;
const SOURCE_OPTION_VALUE_BYTES: usize = 64;
const SOURCE_ENVIRONMENT_ENTRY_LIMIT: usize = 10_000;
const DIAGNOSTIC_SHOW_ERRORS: usize = 0;
const DIAGNOSTIC_SHOW_STATS: usize = 1;
const DIAGNOSTIC_VERBOSE: usize = 2;
const DIAGNOSTIC_MAX_WARNINGS: usize = 3;

#[derive(Clone, Copy, Eq, PartialEq)]
enum DiagnosticOptionInit {
    Uninitialized,
    Defaulted,
    Initialized,
}

#[derive(Clone, Copy)]
struct DiagnosticOptionSlot {
    name: &'static [u8],
    value: isize,
    init: DiagnosticOptionInit,
}

/// The exact selected four-entry `options.c` image. It intentionally does
/// not share `VmOptions`: callback/output state and these source descriptors
/// remain outside `VmPolicy`.
struct ProcessDiagnosticOptions {
    slots: [DiagnosticOptionSlot; DIAGNOSTIC_DESCRIPTOR_COUNT],
    environment_reader: VmOptionEnvironmentReader,
}

impl ProcessDiagnosticOptions {
    const fn new(environment_reader: VmOptionEnvironmentReader) -> Self {
        Self {
            slots: [
                DiagnosticOptionSlot { name: b"show_errors", value: 0, init: DiagnosticOptionInit::Uninitialized },
                DiagnosticOptionSlot { name: b"show_stats", value: 0, init: DiagnosticOptionInit::Uninitialized },
                DiagnosticOptionSlot { name: b"verbose", value: 0, init: DiagnosticOptionInit::Uninitialized },
                DiagnosticOptionSlot { name: b"max_warnings", value: 32, init: DiagnosticOptionInit::Uninitialized },
            ],
            environment_reader,
        }
    }

    #[inline]
    const fn snapshot(&self) -> DiagnosticOptionSnapshot {
        DiagnosticOptionSnapshot::new(
            self.slots[DIAGNOSTIC_SHOW_ERRORS].value,
            self.slots[DIAGNOSTIC_VERBOSE].value,
            self.slots[DIAGNOSTIC_MAX_WARNINGS].value,
        )
        .with_show_stats(self.slots[DIAGNOSTIC_SHOW_STATS].value)
    }

    /// Mirrors one `mi_option_init`: unavailable source environment results
    /// intentionally leave the slot UNINIT so a later warning route retries.
    unsafe fn initialize_one(&mut self, index: usize) -> Option<usize> {
        if self.slots[index].init != DiagnosticOptionInit::Uninitialized {
            return None;
        }
        // SAFETY: ProcessDiagnosticInputs documents this reader's source
        // lifetime and stability obligation; this is its bounded source use.
        let environment = unsafe { (self.environment_reader)() };
        let mut value = [0_u8; SOURCE_OPTION_VALUE_BYTES + 1];
        match unsafe { diagnostic_environment_value(environment, self.slots[index].name, &mut value) } {
            DiagnosticEnvironmentValue::Unavailable => None,
            DiagnosticEnvironmentValue::Absent => {
                self.slots[index].init = DiagnosticOptionInit::Defaulted;
                None
            }
            DiagnosticEnvironmentValue::Value(length) => match parse_diagnostic_source_value(&value[..length]) {
                Some(parsed) => {
                    self.slots[index].value = parsed;
                    self.slots[index].init = DiagnosticOptionInit::Initialized;
                    None
                }
                None => {
                    // C defaults before `_mi_warning_message` to avoid a
                    // recursive verbose lookup. The caller emits only after
                    // this state is fully visible in its exclusive startup or
                    // lock-serialized retry phase.
                    self.slots[index].init = DiagnosticOptionInit::Defaulted;
                    Some(index)
                }
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DiagnosticEnvironmentValue {
    Absent,
    Value(usize),
    Unavailable,
}

/// The selected `_mi_prim_getenv` scan for the four diagnostic descriptors.
unsafe fn diagnostic_environment_value(
    environment: *const *const c_char,
    name: &[u8],
    value: &mut [u8; SOURCE_OPTION_VALUE_BYTES + 1],
) -> DiagnosticEnvironmentValue {
    if environment.is_null() {
        return DiagnosticEnvironmentValue::Unavailable;
    }
    for entry_index in 0..SOURCE_ENVIRONMENT_ENTRY_LIMIT {
        // SAFETY: ProcessDiagnosticInputs owns the same stable valid vector
        // obligation as the pinned Unix `_mi_prim_getenv` boundary.
        let entry = unsafe { core::ptr::read(environment.add(entry_index)) };
        if entry.is_null() {
            return DiagnosticEnvironmentValue::Absent;
        }
        if !unsafe { diagnostic_environment_name_matches(entry, name) } {
            continue;
        }
        let entry_value = unsafe { entry.add(b"mimalloc_".len() + name.len() + 1) };
        for value_index in 0..=SOURCE_OPTION_VALUE_BYTES {
            let byte = unsafe { core::ptr::read(entry_value.add(value_index).cast::<u8>()) };
            if byte == 0 {
                return DiagnosticEnvironmentValue::Value(value_index);
            }
            if value_index == SOURCE_OPTION_VALUE_BYTES {
                return DiagnosticEnvironmentValue::Unavailable;
            }
            value[value_index] = byte;
        }
        unreachable!("bounded diagnostic source environment scan returns in-loop");
    }
    DiagnosticEnvironmentValue::Absent
}

unsafe fn diagnostic_environment_name_matches(entry: *const c_char, name: &[u8]) -> bool {
    for (index, expected) in b"mimalloc_".iter().chain(name).enumerate() {
        let found = unsafe { core::ptr::read(entry.add(index).cast::<u8>()) };
        if !found.eq_ignore_ascii_case(expected) {
            return false;
        }
    }
    unsafe { core::ptr::read(entry.add(b"mimalloc_".len() + name.len()).cast::<u8>()) == b'=' }
}

/// `options.c:639-688` without size suffix handling: the selected descriptors
/// are source `long` scalars, so the value must consume the complete string.
fn parse_diagnostic_source_value(input: &[u8]) -> Option<isize> {
    if input.is_empty() || ascii_eq_ignore_case(input, b"1")
        || ascii_eq_ignore_case(input, b"TRUE") || ascii_eq_ignore_case(input, b"YES")
        || ascii_eq_ignore_case(input, b"ON")
    {
        return Some(1);
    }
    if ascii_eq_ignore_case(input, b"0") || ascii_eq_ignore_case(input, b"FALSE")
        || ascii_eq_ignore_case(input, b"NO") || ascii_eq_ignore_case(input, b"OFF")
    {
        return Some(0);
    }
    let mut index = 0;
    while input.get(index).is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)) {
        index += 1;
    }
    let negative = match input.get(index) {
        Some(b'+') => { index += 1; false }
        Some(b'-') => { index += 1; true }
        _ => false,
    };
    let digit_start = index;
    let mut magnitude = 0_u128;
    while let Some(byte @ b'0'..=b'9') = input.get(index).copied() {
        magnitude = magnitude.checked_mul(10)?.checked_add((byte - b'0') as u128)?;
        index += 1;
    }
    if index == digit_start || index != input.len() {
        return None;
    }
    let positive_limit = isize::MAX as u128;
    let negative_limit = positive_limit + 1;
    if negative {
        (magnitude <= negative_limit).then(|| {
            if magnitude == negative_limit { isize::MIN } else { -(magnitude as isize) }
        })
    } else {
        (magnitude <= positive_limit).then_some(magnitude as isize)
    }
}

#[inline]
fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| left.eq_ignore_ascii_case(right))
}

impl DiagnosticOptionSnapshot {
    /// Constructs the exact scalar values used by the selected descriptors.
    #[inline]
    pub(crate) const fn new(show_errors: isize, verbose: isize, max_warnings: isize) -> Self {
        Self {
            show_errors,
            show_stats: 0,
            verbose,
            max_warnings,
        }
    }

    /// Adds the selected signed `show_stats` descriptor without changing the
    /// existing warning-gate constructor shape.
    #[inline]
    pub(crate) const fn with_show_stats(mut self, show_stats: isize) -> Self {
        self.show_stats = show_stats;
        self
    }

    /// The pinned normal release defaults: `show_errors=0`, `verbose=0`, and
    /// `max_warnings=32`. `_mi_options_init` changes the static initial
    /// warning cap of 16 to this descriptor value before OS initialization.
    #[inline]
    pub(crate) const fn release_defaults() -> Self {
        Self::new(0, 0, 32)
    }

    #[inline]
    const fn show_errors_enabled(self) -> bool {
        self.show_errors != 0
    }

    #[inline]
    const fn verbose_enabled(self) -> bool {
        self.verbose != 0
    }

}

/// Scalar process information captured before final diagnostic output.
///
/// This follows `stats.c:334-353,568-597`: Unix process usage supplies the
/// elapsed/user/system/peak-RSS/fault values while the selected subprocess
/// statistics supply the current and peak commit fields.  It contains no OS,
/// heap, Theap, TLS, or allocator-owner capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalProcessInfo {
    elapsed_milliseconds: usize,
    user_milliseconds: usize,
    system_milliseconds: usize,
    peak_resident_bytes: usize,
    page_faults: usize,
    numa_nodes: usize,
}

impl FinalProcessInfo {
    /// Captures the signed Unix primitive values at the source print edge.
    ///
    /// Pinned `stats.c:568-597` clamps each elapsed/user/system observation to
    /// the nonnegative `PTRDIFF_MAX` `size_t` range before it reaches the
    /// formatter. The raw `ProcessUsage` sampler is called by the process
    /// owner at that same edge; this constructor performs only the source
    /// scalar conversion and stores no OS or allocator capability.
    #[inline]
    pub(crate) fn from_source_observations(
        elapsed_milliseconds: i64,
        usage: ProcessUsage,
        numa_nodes: usize,
    ) -> Self {
        Self::new(
            source_process_milliseconds(elapsed_milliseconds),
            source_process_milliseconds(usage.user_milliseconds),
            source_process_milliseconds(usage.system_milliseconds),
            usage.peak_resident_bytes,
            usage.major_page_faults,
            numa_nodes,
        )
    }

    /// Captures `mi_process_info`'s Unix-primitive failure defaults.
    ///
    /// Pinned `stats.c:568-588` starts user time, system time, and page faults
    /// at zero and seeds peak RSS from the committed peak before
    /// `_mi_prim_process_info`. On Linux a failed `getrusage` leaves that
    /// scalar image intact. The process owner retains the paired current
    /// committed default for its source process-info record; this final
    /// renderer needs the corresponding peak RSS only.
    #[inline]
    pub(crate) fn from_source_committed_defaults(
        elapsed_milliseconds: i64,
        committed: ProcessInfoCommittedDefaults,
        numa_nodes: usize,
    ) -> Self {
        Self::new(
            source_process_milliseconds(elapsed_milliseconds),
            0,
            0,
            committed.peak_bytes,
            0,
            numa_nodes,
        )
    }

    #[inline]
    pub(crate) const fn new(
        elapsed_milliseconds: usize,
        user_milliseconds: usize,
        system_milliseconds: usize,
        peak_resident_bytes: usize,
        page_faults: usize,
        numa_nodes: usize,
    ) -> Self {
        Self {
            elapsed_milliseconds,
            user_milliseconds,
            system_milliseconds,
            peak_resident_bytes,
            page_faults,
            numa_nodes,
        }
    }
}

/// Pinned `stats.c:589-591`'s signed millisecond-to-size conversion.
#[inline]
const fn source_process_milliseconds(value: i64) -> usize {
    if value <= 0 {
        0
    } else if value >= isize::MAX as i64 {
        isize::MAX as usize
    } else {
        value as usize
    }
}

/// The renderer-only final process image.
///
/// The process lifecycle owns the source teardown/merge order and must capture
/// this value after the applicable `Theap -> Heap -> MainSubprocess` merges.
/// The diagnostic adapter can then run in its ordinary retained marker or the
/// terminal descriptor-local scope without reopening allocator admission or
/// borrowing source owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalProcessDiagnosticView {
    subprocess_sequence: usize,
    statistics: FinalStatisticsSnapshot,
    process: FinalProcessInfo,
}

/// A final source-diagnostic phase could not inspect its owner.
///
/// Source-disabled output is deliberately not an error: it is represented by
/// `Ok(None)` from [`OutputOwner::final_statistics_enabled`] and `Ok(false)`
/// from [`OutputOwner::final_process_done_message`]. The process lifecycle
/// must instead retain after either error, because it has already crossed its
/// one-way process-done boundary and must not turn an unavailable descriptor
/// owner or a private-lock failure into silently disabled source output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalDiagnosticOutputError {
    SourceOptionsUnavailable,
    SourceOptionsLock(Errno),
}

/// Proof that pinned `show_stats || verbose` enabled one final statistics
/// phase for this exact output owner.
///
/// The private lifetime binds this one-shot permit to the owner which read the
/// descriptors. Only [`OutputOwner::final_statistics_enabled`] can construct
/// it, so its emitter cannot repeat or substitute source option reads after
/// the process caller completes its merge and sampling boundary.
#[must_use]
pub(crate) struct FinalStatisticsOutputPermit<'owner> {
    output_owner: &'owner OutputOwner,
}

impl<'owner> FinalStatisticsOutputPermit<'owner> {
    /// Emits the source-selected statistics from the already-captured scalar
    /// view without inspecting any option descriptor.
    ///
    /// # Safety
    ///
    /// The caller must hold the existing ordinary retained diagnostic marker,
    /// or the process owner's exact terminal descriptor-local diagnostic
    /// scope. It must also satisfy [`OutputOwner::raw_message`]'s serialized
    /// registration and in-flight callback lifetime obligations. The caller
    /// must capture `view` after its source-prescribed merge and sampling
    /// boundary, and call this in the retained or physical source print phase.
    #[inline]
    pub(crate) unsafe fn emit(self, view: FinalProcessDiagnosticView) {
        // SAFETY: the permit was issued by this exact owner after source
        // option selection, and the caller upholds the output lifetime above.
        unsafe { render_final_statistics(self.output_owner, view) };
    }
}

impl FinalProcessDiagnosticView {
    #[inline]
    pub(crate) const fn new(
        subprocess_sequence: usize,
        statistics: FinalStatisticsSnapshot,
        process: FinalProcessInfo,
    ) -> Self {
        Self { subprocess_sequence, statistics, process }
    }
}

/// One stack-bounded, already source-formatted message.
///
/// Pinned `mi_vfprintf` has `char buf[992]` and calls `_mi_vsnprintf` with
/// `sizeof(buf)-1`; that formatter consequently emits at most 990 payload
/// bytes plus a terminating NUL. A complete M7 formatter must preserve its
/// format/sanitizing rules before constructing this value. This bounded owner
/// only receives the resulting message, copies it into this stack value, and
/// preserves its source truncation boundary without heap storage.
pub(crate) struct SourceFormattedMessage {
    bytes: [u8; SOURCE_FORMAT_STORAGE_BYTES],
    length: usize,
}

impl SourceFormattedMessage {
    /// Copies an already source-formatted C string through the pinned 990-byte
    /// payload limit. The current selected callers have static deterministic
    /// bodies; general variadic formatting remains open with M7.
    #[inline]
    pub(crate) fn from_source_formatted(message: &CStr) -> Self {
        let source = message.to_bytes();
        let length = core::cmp::min(source.len(), SOURCE_FORMAT_PAYLOAD_BYTES);
        let mut bytes = [0; SOURCE_FORMAT_STORAGE_BYTES];
        bytes[..length].copy_from_slice(&source[..length]);
        Self { bytes, length }
    }

    /// Copies one formatter-owned byte span through the same source
    /// `mi_vfprintf` payload boundary as [`Self::from_source_formatted`].
    ///
    /// Final statistics output builds each source line on the caller stack;
    /// this constructor neither parses a format string nor permits an interior
    /// NUL.  The renderer's bounded line builder has already retained source
    /// truncation when a line reaches this boundary.
    #[inline]
    fn from_rendered_bytes(message: &[u8]) -> Self {
        let length = core::cmp::min(message.len(), SOURCE_FORMAT_PAYLOAD_BYTES);
        let mut bytes = [0; SOURCE_FORMAT_STORAGE_BYTES];
        bytes[..length].copy_from_slice(&message[..length]);
        Self { bytes, length }
    }

    /// Formats the one pinned huge-page `mbind` warning body.
    ///
    /// Pinned mimalloc v3.5.0 `src/prim/unix/prim.c:630-645` calls
    /// `_mi_warning_message` with its fixed `%d`/`%ld`/`%lx` literal after a
    /// failed `mbind`. Its selected formatter is `src/libc.c:285-307,
    /// 313-436`: decimal emits its ordinary source digits, while a widthless
    /// `x` still has the source minimum width two, zero fill, and uppercase
    /// digits. This private constructor retains only that fixed call site in
    /// the existing 992-byte `mi_vfprintf` image; it is not a general format
    /// parser or logger.
    ///
    /// The future receiver calls this only after the source node predicate
    /// `0 <= numa_node < 8 * MI_INTPTR_SIZE - 1`. `Errno` supplies the
    /// positive captured Linux `errno` value that the C source passes as both
    /// its `%ld` and `%lx` arguments.
    #[inline]
    pub(crate) fn mbind_failure(numa_node: i32, errno: Errno) -> Self {
        debug_assert!(numa_node >= 0);
        debug_assert!(numa_node < usize::BITS as i32 - 1);

        let mut bytes = [0; SOURCE_FORMAT_STORAGE_BYTES];
        let mut length = 0;
        append_mbind_bytes(&mut bytes, &mut length, b"failed to bind huge (1GiB) pages to numa node ");
        append_mbind_signed_decimal(&mut bytes, &mut length, numa_node);
        append_mbind_bytes(&mut bytes, &mut length, b" (error: ");
        let raw_errno = errno.raw() as u64;
        append_mbind_unsigned_decimal(&mut bytes, &mut length, raw_errno);
        append_mbind_bytes(&mut bytes, &mut length, b" (0x");
        append_mbind_uppercase_hex_minimum_two(&mut bytes, &mut length, raw_errno);
        append_mbind_bytes(&mut bytes, &mut length, b"))\n");
        Self { bytes, length }
    }

    #[inline]
    fn as_c_str(&self) -> &CStr {
        // SAFETY: construction always places a zero byte immediately after
        // `length`, and only copies the NUL-free contents of a `CStr`.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes[..=self.length]) }
    }
}

#[inline]
fn append_mbind_bytes(
    bytes: &mut [u8; SOURCE_FORMAT_STORAGE_BYTES], length: &mut usize, source: &[u8],
) {
    for byte in source {
        if *length == SOURCE_FORMAT_PAYLOAD_BYTES {
            return;
        }
        bytes[*length] = *byte;
        *length += 1;
    }
}

/// The selected signed `%d` route. The future primitive receiver admits only
/// nonnegative nodes, but retaining the signed source spelling here keeps the
/// body constructor tied to its exact C conversion rather than a fixture type.
#[inline]
fn append_mbind_signed_decimal(
    bytes: &mut [u8; SOURCE_FORMAT_STORAGE_BYTES], length: &mut usize, value: i32,
) {
    if value < 0 {
        append_mbind_bytes(bytes, length, b"-");
        append_mbind_unsigned_decimal(bytes, length, (-(value as i64)) as u64);
    } else {
        append_mbind_unsigned_decimal(bytes, length, value as u64);
    }
}

/// The selected base-10 part of `mi_out_num`; it writes zero as one `0` and
/// otherwise reverses source digits without heap storage.
#[inline]
fn append_mbind_unsigned_decimal(
    bytes: &mut [u8; SOURCE_FORMAT_STORAGE_BYTES], length: &mut usize, mut value: u64,
) {
    if value == 0 {
        append_mbind_bytes(bytes, length, b"0");
        return;
    }
    let mut reversed = [0_u8; 20];
    let mut digits = 0;
    while value != 0 {
        reversed[digits] = b'0' + (value % 10) as u8;
        digits += 1;
        value /= 10;
    }
    while digits != 0 {
        digits -= 1;
        append_mbind_bytes(bytes, length, &reversed[digits..digits + 1]);
    }
}

/// The selected `%lx` path: `mi_out_num`'s uppercase digits plus
/// `_mi_vsnprintf`'s widthless-hex minimum of two and zero fill.
#[inline]
fn append_mbind_uppercase_hex_minimum_two(
    bytes: &mut [u8; SOURCE_FORMAT_STORAGE_BYTES], length: &mut usize, mut value: u64,
) {
    if value == 0 {
        append_mbind_bytes(bytes, length, b"00");
        return;
    }
    let mut reversed = [0_u8; 16];
    let mut digits = 0;
    while value != 0 {
        let digit = (value & 0x0f) as u8;
        reversed[digits] = if digit <= 9 { b'0' + digit } else { b'A' + digit - 10 };
        digits += 1;
        value >>= 4;
    }
    if digits == 1 {
        append_mbind_bytes(bytes, length, b"0");
    }
    while digits != 0 {
        digits -= 1;
        append_mbind_bytes(bytes, length, &reversed[digits..digits + 1]);
    }
}

/// One source-sized `mi_vfprintf_thread` prefix for the selected warning.
///
/// Pinned `mi_vfprintf_thread` accepts the static 19-byte warning prefix,
/// forms `char tprefix[64]` with `_mi_snprintf`, and uses `%tx` for
/// `_mi_thread_id()`. `mi_out_num` writes zero as `0`, otherwise writes the
/// shortest uppercase base-16 representation. This private stack image keeps
/// exactly that selected valid-program boundary without general formatting.
struct ThreadWarningPrefix {
    bytes: [u8; THREAD_WARNING_PREFIX_BYTES],
    length: usize,
}

impl ThreadWarningPrefix {
    #[inline]
    fn new(thread_identity: usize) -> Self {
        let mut bytes = [0; THREAD_WARNING_PREFIX_BYTES];
        let mut length = WARNING_PREFIX_HEAD.len();
        bytes[..length].copy_from_slice(WARNING_PREFIX_HEAD);

        if thread_identity == 0 {
            bytes[length] = b'0';
            length += 1;
        } else {
            let mut reversed = [0; core::mem::size_of::<usize>() * 2];
            let mut value = thread_identity;
            let mut digits = 0;
            while value != 0 {
                let digit = (value & 0x0f) as u8;
                reversed[digits] = if digit < 10 { b'0' + digit } else { b'A' + digit - 10 };
                digits += 1;
                value >>= 4;
            }
            while digits != 0 {
                digits -= 1;
                bytes[length] = reversed[digits];
                length += 1;
            }
        }

        bytes[length..length + WARNING_PREFIX_TAIL.len()].copy_from_slice(WARNING_PREFIX_TAIL);
        length += WARNING_PREFIX_TAIL.len();
        debug_assert!(length < THREAD_WARNING_PREFIX_BYTES);
        Self { bytes, length }
    }

    #[inline]
    fn as_c_str(&self) -> &CStr {
        // SAFETY: the zero-initialized final byte follows the 46-byte visible
        // maximum, so the selected 64-bit C string occupies 47 bytes.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes[..=self.length]) }
    }
}

/// The source `mi_output_fun` shape, retained as a private boundary.
///
/// No public ABI uses this alias yet. The callback receives one NUL-terminated
/// fragment at a time, so a warning emits its prefix and body in two calls.
pub(crate) type OutputCallback = unsafe extern "C" fn(*const c_char, *mut c_void);

/// Private source-shaped `_mi_prim_out_stderr` primitive.
///
/// The supplied function must retain the selected Linux/musl
/// `fputs(message, stderr)` transport contract, including the runtime-owned
/// FILE's locking, buffering, and error/short-write behavior. It receives a
/// non-null, nonempty NUL-terminated message and has no opaque allocator
/// state. The current diagnostic owner has no production receiver for this
/// primitive; a raw `write(2, ...)` substitute is not source-equivalent
/// evidence and cannot close that prerequisite.
pub(crate) type DefaultStderrOutput = unsafe extern "C" fn(*const c_char);

#[derive(Clone, Copy)]
enum DelayedFlushSink {
    Custom {
        output: OutputCallback,
        argument: *mut c_void,
    },
    DefaultStderr(DefaultStderrOutput),
}

/// Private owner for the selected `options.c` output and warning path.
///
/// The fixed delayed storage is intentionally the source `16*1024 + 1` image.
/// `UnsafeCell` is protected by `out_buf_lock`, whose successful acquisition
/// and release provide the critical-section ordering. The C source permits a
/// process to install one handler from one thread because independently stored
/// callback/argument values may otherwise mismatch; `register_output` keeps
/// that exact non-owning contract rather than adding a logger or registration
/// framework.
pub(crate) struct OutputOwner {
    out_buf: UnsafeCell<[u8; DELAYED_OUTPUT_BYTES + 1]>,
    out_len: AtomicUsize,
    out_buf_lock: PrivateLock,
    default_sink: AtomicU8,
    default_stderr_output: DefaultStderrOutput,
    callback: AtomicPtr<()>,
    argument: AtomicPtr<c_void>,
    warning_count: AtomicUsize,
    max_warning_count: isize,
    source_options: UnsafeCell<core::mem::MaybeUninit<ProcessDiagnosticOptions>>,
    source_options_ready: AtomicU8,
    source_options_lock: PrivateLock,
}

// All delayed-byte mutation occurs under `out_buf_lock`. The callback's own
// aliasing and thread-safety obligations remain with the unsafe registration
// caller, matching the opaque source pointer contract.
unsafe impl Sync for OutputOwner {}

const PENDING_SOURCE_WARNINGS: usize = 4;

struct PendingSourceWarning {
    options: DiagnosticOptionSnapshot,
    message: SourceFormattedMessage,
}

/// Fixed stack staging between the descriptor lock and source output. It is
/// not a queue or registration framework: one finite warning gate can produce
/// at most its own body plus the selected invalid-descriptor bodies. Staging
/// releases `source_options_lock` before any caller-supplied FILE/callback
/// invocation while retaining the gate's selected lazy-read order.
///
/// For the one temporary invalid-`verbose` state, the staged owner restores
/// the descriptor before foreign delivery. Pinned C restores it after
/// `_mi_warning_message` returns. Therefore this private slice excludes
/// synchronous reentry from a delivery callback or FILE primitive into
/// `warning_from_source_options` or `MbindWarningRoute`; it does not claim
/// source recursive-output parity. Existing `warning` and `raw_message`
/// reentry contracts are unchanged.
struct PendingSourceWarnings {
    entries: [core::mem::MaybeUninit<PendingSourceWarning>; PENDING_SOURCE_WARNINGS],
    length: usize,
}

impl PendingSourceWarnings {
    const fn new() -> Self {
        Self { entries: [const { core::mem::MaybeUninit::uninit() }; PENDING_SOURCE_WARNINGS], length: 0 }
    }

    fn push(&mut self, options: DiagnosticOptionSnapshot, message: SourceFormattedMessage) {
        debug_assert!(self.length < PENDING_SOURCE_WARNINGS);
        self.entries[self.length].write(PendingSourceWarning { options, message });
        self.length += 1;
    }

    unsafe fn deliver(self, output: &OutputOwner) {
        for index in 0..self.length {
            // SAFETY: `push` initializes exactly the prefix below `length`;
            // this stack image has no Drop-bearing remainder.
            let entry = unsafe { self.entries[index].assume_init_read() };
            // SAFETY: source descriptor serialization ended before this
            // dispatch; caller-supplied callback lifetime obligations remain
            // exactly those of OutputOwner::warning.
            unsafe { output.warning(entry.options, entry.message) };
        }
    }
}

impl OutputOwner {
    /// Creates the source's pre-init diagnostic state with its FILE owner.
    ///
    /// `default_stderr_output` is the future private runtime integration
    /// receiver for the pinned `_mi_prim_out_stderr` primitive. It is fixed at
    /// construction because the source's `mi_out_stderr` callback is static;
    /// it is not a registered custom callback or VM policy field.
    #[inline]
    pub(crate) const fn new(default_stderr_output: DefaultStderrOutput) -> Self {
        Self {
            out_buf: UnsafeCell::new([0; DELAYED_OUTPUT_BYTES + 1]),
            out_len: AtomicUsize::new(0),
            out_buf_lock: PrivateLock::new(),
            default_sink: AtomicU8::new(DEFAULT_DELAYED),
            default_stderr_output,
            callback: AtomicPtr::new(core::ptr::null_mut()),
            argument: AtomicPtr::new(core::ptr::null_mut()),
            warning_count: AtomicUsize::new(0),
            max_warning_count: INITIAL_MAX_WARNING_COUNT,
            source_options: UnsafeCell::new(core::mem::MaybeUninit::uninit()),
            source_options_ready: AtomicU8::new(0),
            source_options_lock: PrivateLock::new(),
        }
    }

    /// Performs this slice's `_mi_options_init` contribution before OS setup.
    ///
    /// The exclusive borrow encodes the source startup ordering: initialize
    /// the descriptor-derived maximum before the owner becomes shared with
    /// warning emitters. The source does not reset `warning_count` here.
    #[inline]
    pub(crate) fn initialize_options(&mut self, options: DiagnosticOptionSnapshot) {
        self.max_warning_count = options.max_warnings;
    }

    /// Resolves the selected four `options.c` descriptors before VM/OS work.
    ///
    /// The exclusive startup borrow proves that no dispatcher can observe the
    /// inline option image until all four source-order initial attempts have
    /// completed and the post-pass warning cap has replaced the initial 16.
    /// Unavailable environment reads remain UNINIT, exactly for a later
    /// lock-serialized warning-route retry.
    pub(crate) unsafe fn initialize_source_options(
        &mut self,
        environment_reader: VmOptionEnvironmentReader,
    ) {
        let options = ProcessDiagnosticOptions::new(environment_reader);
        unsafe { (*self.source_options.get()).write(options) };
        self.source_options_ready.store(1, Ordering::Release);
        for index in 0..DIAGNOSTIC_DESCRIPTOR_COUNT {
            let mut pending = PendingSourceWarnings::new();
            // SAFETY: the exclusive startup borrow is the only descriptor
            // access before a route is borrowed or post-init dispatch starts.
            let (_, invalid) = unsafe { self.source_option_get_unlocked(index) };
            if let Some(invalid) = invalid {
                unsafe { self.collect_invalid_source_option_unlocked(invalid, &mut pending) };
            }
            // SAFETY: normal source startup has no custom registration before
            // options initialization; no source-options lock is held here.
            unsafe { pending.deliver(self) };
        }
        // `_mi_options_init` assigns the global warning cap only after its
        // complete descriptor loop. A max_warnings error above therefore used
        // the source initial cap of 16 before this write.
        self.max_warning_count = unsafe { self.source_option_snapshot_unlocked() }.max_warnings;
    }

    /// Emits through the retained descriptor state, retrying only entries that
    /// the pinned warning gate actually reads: `verbose` first and, only when
    /// disabled, `show_errors`. Descriptor access is lock-serialized, but the
    /// fixed source fragments leave that lock before default FILE/custom output.
    ///
    /// # Safety
    ///
    /// This has the same callback registration and in-flight delivery
    /// obligations as [`Self::warning`]. The source environment reader's
    /// process-lifetime stability requirement is documented by
    /// [`ProcessDiagnosticInputs`]. The registered callback/default FILE
    /// primitive must not synchronously call this source-option route or
    /// [`MbindWarningRoute`]: this private staged owner restores temporary
    /// invalid-`verbose` state before foreign delivery, unlike pinned C's
    /// recursive-output sequence. This does not narrow `warning` or
    /// `raw_message` reentry.
    pub(crate) unsafe fn warning_from_source_options(&self, message: SourceFormattedMessage) {
        debug_assert_eq!(self.source_options_ready.load(Ordering::Acquire), 1);
        let mut pending = PendingSourceWarnings::new();
        {
            let Ok(_guard) = self.source_options_lock.lock() else { return; };
            // SAFETY: ready is Release-published before a route borrows this
            // owner. The lock serializes all later UNINIT retries, and no
            // mutable descriptor reference escapes this block.
            unsafe { self.collect_warning_from_source_options_unlocked(message, &mut pending) };
        }
        // SAFETY: descriptor locking ended above. This retains the existing
        // unsafe registration/default-dispatch contract without introducing a
        // lock-across-foreign-callback boundary.
        unsafe { pending.deliver(self) };
    }

    /// Reads one source descriptor while the caller has either exclusive
    /// startup ownership or `source_options_lock`.
    unsafe fn source_option_get_unlocked(&self, index: usize) -> (isize, Option<usize>) {
        let options = unsafe { (&mut *self.source_options.get()).assume_init_mut() };
        let invalid = unsafe { options.initialize_one(index) };
        (options.slots[index].value, invalid)
    }

    unsafe fn source_option_snapshot_unlocked(&self) -> DiagnosticOptionSnapshot {
        unsafe { (&*self.source_options.get()).assume_init_ref() }.snapshot()
    }

    unsafe fn source_option_set_value_unlocked(&self, index: usize, value: isize) {
        unsafe { (&mut *self.source_options.get()).assume_init_mut() }.slots[index].value = value;
    }

    /// Implements the finite `mi_option_get(verbose)` then
    /// `mi_option_get(show_errors)` gate. It deliberately never reads max:
    /// C captures that scalar after its startup descriptor loop and uses only
    /// its dedicated counter afterward.
    unsafe fn collect_warning_from_source_options_unlocked(
        &self,
        message: SourceFormattedMessage,
        pending: &mut PendingSourceWarnings,
    ) {
        let (verbose, invalid_verbose) = unsafe { self.source_option_get_unlocked(DIAGNOSTIC_VERBOSE) };
        if let Some(invalid) = invalid_verbose {
            unsafe { self.collect_invalid_source_option_unlocked(invalid, pending) };
        }
        if verbose != 0 {
            pending.push(unsafe { self.source_option_snapshot_unlocked() }, message);
            return;
        }

        let (show_errors, invalid_show_errors) = unsafe {
            self.source_option_get_unlocked(DIAGNOSTIC_SHOW_ERRORS)
        };
        if let Some(invalid) = invalid_show_errors {
            unsafe { self.collect_invalid_source_option_unlocked(invalid, pending) };
        }
        if show_errors != 0 {
            pending.push(unsafe { self.source_option_snapshot_unlocked() }, message);
        }
    }

    /// Replays `mi_option_init`'s invalid branch after DEFAULTED. Verbose is
    /// temporarily one only while staging its own warning, and is restored
    /// before the parent gate continues.
    unsafe fn collect_invalid_source_option_unlocked(
        &self,
        index: usize,
        pending: &mut PendingSourceWarnings,
    ) {
        if index == DIAGNOSTIC_VERBOSE {
            let snapshot = unsafe { self.source_option_snapshot_unlocked() };
            if snapshot.verbose == 0 {
                unsafe { self.source_option_set_value_unlocked(DIAGNOSTIC_VERBOSE, 1) };
                unsafe {
                    self.collect_warning_from_source_options_unlocked(
                        invalid_diagnostic_option_message(index), pending,
                    )
                };
                unsafe { self.source_option_set_value_unlocked(DIAGNOSTIC_VERBOSE, 0) };
                return;
            }
        }
        unsafe {
            self.collect_warning_from_source_options_unlocked(
                invalid_diagnostic_option_message(index), pending,
            )
        };
    }

    /// Installs the source's one non-owning custom output callback, or the
    /// `NULL` registration stderr route.
    ///
    /// # Safety
    ///
    /// For a non-null callback, `output` and `argument` must remain valid for
    /// every future delivery until a serialized replacement is installed. The
    /// program must register from one thread and must not race any registration
    /// or unrelated default dispatch: like `mi_register_output`, the separately
    /// Release-stored callback and argument can otherwise be observed as a
    /// mismatched pair. The callback/argument being replaced also remain live
    /// until all in-flight deliveries finish. A custom registration flushes
    /// delayed bytes while `out_buf_lock` is held; its callback must therefore
    /// not call `register_output` or `post_init`. Reentrant `raw_message` or
    /// `warning` from that just-installed custom callback is permitted after
    /// the custom default is published and bypasses the delayed-buffer lock.
    pub(crate) unsafe fn register_output(
        &self,
        output: Option<OutputCallback>,
        argument: *mut c_void,
    ) {
        match output {
            Some(callback) => {
                self.callback.store(callback_to_pointer(callback), Ordering::Release);
                // This is the source `mi_out_default` store. It intentionally
                // precedes the independent argument store below.
                self.default_sink.store(DEFAULT_CALLBACK, Ordering::Release);
                self.argument.store(argument, Ordering::Release);
                self.flush_delayed(
                    DelayedFlushSink::Custom {
                        output: callback,
                        argument,
                    },
                    true,
                );
            }
            None => {
                // Source `mi_register_output(NULL,arg)` installs stderr but
                // does not flush or terminally claim the delayed buffer.
                self.default_sink.store(DEFAULT_STDERR, Ordering::Release);
                self.argument.store(argument, Ordering::Release);
            }
        }
    }

    /// Performs `_mi_options_post_init`'s diagnostic transition.
    ///
    /// # Safety
    ///
    /// The caller must invoke this exactly once after automatic thread setup,
    /// before any custom registration, and after source-order option
    /// initialization. It must also serialize this transition against every
    /// unrelated `raw_message` or `warning` dispatch. Calling it from a
    /// callback is invalid because it takes the delayed-buffer lock while
    /// source registration flushing holds it.
    pub(crate) unsafe fn post_init(&self) {
        debug_assert_eq!(self.default_sink.load(Ordering::Relaxed), DEFAULT_DELAYED);
        self.flush_delayed(
            DelayedFlushSink::DefaultStderr(self.default_stderr_output),
            false,
        );
        self.default_sink
            .store(DEFAULT_STDERR_AND_DELAYED, Ordering::Release);
        self.argument.store(core::ptr::null_mut(), Ordering::Release);
    }

    /// Emits a preformatted source message through `_mi_fputs`' default path.
    ///
    /// # Safety
    ///
    /// The caller must serialize this dispatch against `register_output` and
    /// `post_init`, and retain any registered callback/argument until every
    /// in-flight delivery completes. The only permitted overlap is reentry
    /// from the just-installed custom callback during its own registration
    /// flush: the source has already published that default before invoking
    /// the callback. An unrelated thread must not dispatch while a callback
    /// pair is being installed or replaced, because the source intentionally
    /// publishes that pair in separate stores.
    #[inline]
    pub(crate) unsafe fn raw_message(&self, message: SourceFormattedMessage) {
        self.fputs_default(None, message.as_c_str());
    }

    /// Selects whether the current source process-final phase prints
    /// statistics.
    ///
    /// This is pinned `init.c:636-640` and `subproc.c:241-245`'s exact signed
    /// `mi_option_is_enabled(show_stats) || mi_option_is_enabled(verbose)`
    /// condition. The process caller must invoke it before its retained
    /// Theap/Heap merges or physical process sampling: source performs no such
    /// work when this condition is false. A nonzero `show_stats`, including a
    /// negative signed value, short-circuits without reading, retrying, or
    /// warning for `verbose`.
    ///
    /// A source-disabled gate returns `Ok(None)`. An unavailable option owner
    /// or a private lock failure returns [`FinalDiagnosticOutputError`], so the
    /// one-way process caller can retain instead of treating a broken source
    /// boundary as disabled output. On `Ok(Some(_))` the opaque one-shot permit's
    /// [`FinalStatisticsOutputPermit::emit`] method performs the later
    /// source-selected print from an already-captured scalar image, without
    /// rereading descriptors. This keeps the source gate before state work and
    /// prevents the emitter from making a second option decision after the source
    /// boundary.
    ///
    /// # Safety
    ///
    /// The caller must hold the existing ordinary retained diagnostic marker,
    /// or the process owner's exact terminal descriptor-local diagnostic
    /// scope. It must also satisfy [`Self::raw_message`]'s serialized
    /// registration and in-flight callback lifetime obligations because an
    /// invalid selected descriptor can deliver a source warning after this
    /// method releases the descriptor lock.
    pub(crate) unsafe fn final_statistics_enabled(
        &self,
    ) -> Result<Option<FinalStatisticsOutputPermit<'_>>, FinalDiagnosticOutputError> {
        if self.source_options_ready.load(Ordering::Acquire) != 1 {
            return Err(FinalDiagnosticOutputError::SourceOptionsUnavailable);
        }

        let mut pending = PendingSourceWarnings::new();
        let enabled = {
            let _guard = self
                .source_options_lock
                .lock()
                .map_err(FinalDiagnosticOutputError::SourceOptionsLock)?;
            // Pinned `||` reads show_stats first and only then verbose. Each
            // lazy descriptor retry remains serialized, and any invalid-value
            // warning is staged until after the descriptor lock is released.
            let (show_stats, invalid_show_stats) = unsafe {
                self.source_option_get_unlocked(DIAGNOSTIC_SHOW_STATS)
            };
            if let Some(invalid) = invalid_show_stats {
                unsafe { self.collect_invalid_source_option_unlocked(invalid, &mut pending) };
            }
            if show_stats != 0 {
                // This is source `||`, not a two-option snapshot: a signed
                // nonzero show_stats must not initialize, retry, or stage an
                // invalid warning for verbose.
                true
            } else {
                let (verbose, invalid_verbose) = unsafe {
                    self.source_option_get_unlocked(DIAGNOSTIC_VERBOSE)
                };
                if let Some(invalid) = invalid_verbose {
                    unsafe { self.collect_invalid_source_option_unlocked(invalid, &mut pending) };
                }
                verbose != 0
            }
        };

        // SAFETY: descriptor serialization ended above; the caller owns the
        // same serialized output scope required by raw_message.
        unsafe { pending.deliver(self) };
        if !enabled {
            return Ok(None);
        }
        Ok(Some(FinalStatisticsOutputPermit { output_owner: self }))
    }

    /// Emits only the common source final verbose tail.
    ///
    /// This is pinned `init.c:646`'s `_mi_verbose_message("process done
    /// %zu\n", sizeof(mi_page_t))` path. It is separate from
    /// [`Self::final_statistics_enabled`] because the source places it after
    /// the process's final PageMap/allocator cleanup and just before it marks
    /// preloading. It needs only the caller-captured page-record size, never a
    /// source owner, heap, TLS image, VM state, or normal operation guard.
    ///
    /// # Safety
    ///
    /// The caller must hold the same retained or exact terminal diagnostic
    /// authority and serialized output lifetime described by
    /// [`Self::final_statistics_enabled`]. It must call this only at the
    /// source's common final-tail point, after any applicable final statistics
    /// phase and PageMap retirement.
    pub(crate) unsafe fn final_process_done_message(
        &self,
        page_record_bytes: usize,
    ) -> Result<bool, FinalDiagnosticOutputError> {
        if self.source_options_ready.load(Ordering::Acquire) != 1 {
            return Err(FinalDiagnosticOutputError::SourceOptionsUnavailable);
        }

        let mut pending = PendingSourceWarnings::new();
        let verbose = {
            let _guard = self
                .source_options_lock
                .lock()
                .map_err(FinalDiagnosticOutputError::SourceOptionsLock)?;
            let (verbose, invalid_verbose) = unsafe {
                self.source_option_get_unlocked(DIAGNOSTIC_VERBOSE)
            };
            if let Some(invalid) = invalid_verbose {
                unsafe { self.collect_invalid_source_option_unlocked(invalid, &mut pending) };
            }
            verbose
        };
        // SAFETY: the descriptor lock was released before any foreign output.
        unsafe { pending.deliver(self) };
        if verbose == 0 {
            return Ok(false);
        }
        // SAFETY: caller owns the current phase's diagnostic output authority.
        unsafe { render_final_verbose_tail(self, page_record_bytes) };
        Ok(true)
    }

    /// Emits the selected `_mi_warning_message` path.
    ///
    /// # Safety
    ///
    /// This has the same dispatch-versus-registration and in-flight callback
    /// lifetime obligations as `raw_message`.
    #[inline]
    pub(crate) unsafe fn warning(
        &self,
        options: DiagnosticOptionSnapshot,
        message: SourceFormattedMessage,
    ) {
        if !options.verbose_enabled() {
            if !options.show_errors_enabled() {
                return;
            }
            if self.max_warning_count >= 0 {
                // Pinned `mi_atomic_increment_acq_rel` is a C11 `fetch_add`,
                // so this comparison intentionally observes the old count.
                // A nonnegative source cap therefore admits values 0 through
                // the cap before suppressing the next warning.
                let count = self.warning_count.fetch_add(1, Ordering::AcqRel);
                if (count as isize) > self.max_warning_count {
                    return;
                }
            }
        }

        // The selected static warning prefix satisfies the source's 32-byte
        // `mi_vfprintf_thread` predicate. Preserve its one stack prefix and
        // separate prefix/body callback deliveries.
        let prefix = ThreadWarningPrefix::new(thread_pointer_identity());
        self.fputs_default(Some(prefix.as_c_str()), message.as_c_str());
    }

    fn fputs_default(&self, prefix: Option<&CStr>, message: &CStr) {
        // On the selected Linux profile, the source's recursion primitive is
        // the no-op/true implementation. The two dispatches remain distinct.
        if let Some(prefix) = prefix {
            self.dispatch_default(prefix);
        }
        self.dispatch_default(message);
    }

    fn dispatch_default(&self, message: &CStr) {
        match self.default_sink.load(Ordering::Acquire) {
            DEFAULT_DELAYED => self.delayed_output(message),
            DEFAULT_STDERR => self.default_stderr(message),
            DEFAULT_STDERR_AND_DELAYED => {
                self.default_stderr(message);
                self.delayed_output(message);
            }
            DEFAULT_CALLBACK => {
                let pointer = self.callback.load(Ordering::Acquire);
                let argument = self.argument.load(Ordering::Acquire);
                if !pointer.is_null() {
                    // SAFETY: `register_output`'s caller supplies the callback
                    // lifetime and single-registration-thread contract.
                    unsafe { invoke_callback(pointer_to_callback(pointer), message, argument) };
                }
            }
            _ => unreachable!("OutputOwner only publishes source-defined sinks"),
        }
    }

    fn delayed_output(&self, message: &CStr) {
        if self.out_len.load(Ordering::Acquire) >= DELAYED_OUTPUT_BYTES {
            return;
        }
        let mut length = message.to_bytes().len();
        if length == 0 || length >= DELAYED_OUTPUT_BYTES {
            return;
        }

        let Ok(_guard) = self.out_buf_lock.lock() else {
            // A valid process-private lock cannot fail here. `mi_lock_acquire`
            // reports its own impossible primitive error; this private port
            // drops this best-effort diagnostic rather than inventing a second
            // error recursion route without the full M7 error owner.
            return;
        };
        let start = self.out_len.fetch_add(length, Ordering::AcqRel);
        if start < DELAYED_OUTPUT_BYTES {
            if start + length >= DELAYED_OUTPUT_BYTES {
                length = DELAYED_OUTPUT_BYTES - start - 1;
            }
            // SAFETY: the lock serializes this mutable access. `start` is
            // below the fixed source maximum and `length` is clipped so the
            // copied range ends before its extra NUL byte.
            let buffer = unsafe { &mut *self.out_buf.get() };
            buffer[start..start + length].copy_from_slice(&message.to_bytes()[..length]);
        }
    }

    fn default_stderr(&self, message: &CStr) {
        // `mi_out_stderr` filters empty messages before it reaches the source
        // primitive, including ordinary NULL-registration dispatches.
        if message.to_bytes().is_empty() {
            return;
        }
        // SAFETY: `message` is source-shaped non-null/nonempty C text and the
        // constructor fixes this primitive for the owner's full lifetime.
        unsafe { (self.default_stderr_output)(message.as_ptr()) };
    }

    fn flush_delayed(&self, sink: DelayedFlushSink, no_more_buffer: bool) {
        let Ok(_guard) = self.out_buf_lock.lock() else {
            return;
        };
        let addend = if no_more_buffer { DELAYED_OUTPUT_BYTES } else { 1 };
        let mut count = self.out_len.fetch_add(addend, Ordering::AcqRel);
        if count > DELAYED_OUTPUT_BYTES {
            count = DELAYED_OUTPUT_BYTES;
        }
        // SAFETY: the lock serializes byte access and the source image has an
        // extra byte so `count == DELAYED_OUTPUT_BYTES` remains NUL-terminated.
        let buffer = unsafe { &mut *self.out_buf.get() };
        buffer[count] = 0;
        let message = buffer.as_ptr().cast::<c_char>();
        match sink {
            DelayedFlushSink::Custom { output, argument } => {
                // SAFETY: `buffer` stays live until this callback returns.
                // The custom callback's validity requirements are documented
                // on `register_output`.
                unsafe { output(message, argument) };
            }
            DelayedFlushSink::DefaultStderr(output) => {
                // `mi_out_stderr` filters the empty delayed image before it
                // reaches `_mi_prim_out_stderr`; preserve that boundary before
                // invoking the nonempty caller-supplied primitive.
                if buffer[0] != 0 {
                    // SAFETY: this is the constructor-fixed source primitive
                    // and `buffer` supplies its non-null NUL-terminated input.
                    unsafe { output(message) };
                }
            }
        }
        if !no_more_buffer {
            buffer[count] = b'\n';
        }
    }
}

/// One bounded source-format line for the final statistics path.
///
/// `fmt::Write` is used only as an allocation-free decimal/width primitive.
/// It cannot expand the selected formatting language: every caller below
/// names a literal from `stats.c`. `_mi_stats_print` sends that formatted
/// material through a 255-byte line-buffered callback, so dispatch preserves
/// that smaller boundary separately from the source `mi_vfprintf` payload
/// storage used by ordinary diagnostics.
struct FinalOutputLine {
    bytes: [u8; SOURCE_FORMAT_STORAGE_BYTES],
    length: usize,
}

impl FinalOutputLine {
    #[inline]
    const fn new() -> Self {
        Self { bytes: [0; SOURCE_FORMAT_STORAGE_BYTES], length: 0 }
    }

    #[inline]
    fn append_bytes(&mut self, bytes: &[u8]) {
        let available = SOURCE_FORMAT_PAYLOAD_BYTES.saturating_sub(self.length);
        let copied = core::cmp::min(available, bytes.len());
        self.bytes[self.length..self.length + copied].copy_from_slice(&bytes[..copied]);
        self.length += copied;
    }

    #[inline]
    fn append_spaces(&mut self, count: usize) {
        let available = SOURCE_FORMAT_PAYLOAD_BYTES.saturating_sub(self.length);
        let count = core::cmp::min(available, count);
        self.bytes[self.length..self.length + count].fill(b' ');
        self.length += count;
    }

    #[inline]
    fn append_left(&mut self, value: &[u8], width: usize) {
        self.append_bytes(value);
        self.append_spaces(width.saturating_sub(value.len()));
    }

    #[inline]
    fn append_right(&mut self, value: &[u8], width: usize) {
        self.append_spaces(width.saturating_sub(value.len()));
        self.append_bytes(value);
    }

    #[inline]
    fn as_message(&self) -> SourceFormattedMessage {
        SourceFormattedMessage::from_rendered_bytes(&self.bytes[..self.length])
    }
}

impl Write for FinalOutputLine {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let available = SOURCE_FORMAT_PAYLOAD_BYTES.saturating_sub(self.length);
        let copied = core::cmp::min(available, value.len());
        self.bytes[self.length..self.length + copied].copy_from_slice(&value.as_bytes()[..copied]);
        self.length += copied;
        if copied == value.len() { Ok(()) } else { Err(fmt::Error) }
    }
}

#[inline]
unsafe fn emit_final_statistics_line(output: &OutputOwner, line: &FinalOutputLine) {
    // `_mi_stats_print` wraps its output in `buffered_t { count: 255 }`: it
    // flushes before the next byte once that many bytes are retained, and
    // flushes again at every LF. Keep the actual callback boundary here rather
    // than treating a source statistic row as one generic diagnostic message.
    const SOURCE_STATISTICS_BUFFER_BYTES: usize = 255;
    let mut offset = 0;
    while offset < line.length {
        let end = core::cmp::min(offset + SOURCE_STATISTICS_BUFFER_BYTES, line.length);
        // SAFETY: the enclosing final-output adapter owns the serialized
        // output scope; this slice is copied into source-shaped message
        // storage before synchronous dispatch.
        unsafe {
            output.raw_message(SourceFormattedMessage::from_rendered_bytes(
                &line.bytes[offset..end],
            ))
        };
        offset = end;
    }
}

#[inline]
fn append_final_amount(line: &mut FinalOutputLine, value: i64, unit: i64, limit_width: bool) {
    let start = line.length;
    let suffix = if unit <= 0 { b" ".as_slice() } else { b"B".as_slice() };
    let base = if unit == 0 { 1_000_i64 } else { 1_024_i64 };
    let value = if unit > 0 { value.wrapping_mul(unit) } else { value };
    let magnitude = value.unsigned_abs() as i128;
    if magnitude < i128::from(base) {
        if value != 1 || suffix != b"B" {
            let _ = write!(line, "{value}");
            line.append_bytes(b"   ");
            line.append_left(if value == 0 { b"" } else { suffix }, 3);
        }
    } else {
        let mut divider = i128::from(base);
        let mut magnitude_name = b"K".as_slice();
        if magnitude >= divider * i128::from(base) {
            divider *= i128::from(base);
            magnitude_name = b"M";
        }
        if magnitude >= divider * i128::from(base) {
            divider *= i128::from(base);
            magnitude_name = b"G";
        }
        let tens = i128::from(value) / (divider / 10);
        let whole = tens / 10;
        let fractional = (tens % 10).unsigned_abs();
        let _ = write!(line, "{whole}.{fractional} ");
        line.append_bytes(magnitude_name);
        if base == 1_024 { line.append_bytes(b"i"); }
        line.append_left(suffix, 3usize.saturating_sub(magnitude_name.len() + usize::from(base == 1_024)));
    }
    if limit_width {
        let produced = line.length - start;
        if produced < 12 {
            let padding = 12 - produced;
            line.bytes.copy_within(start..line.length, start + padding);
            line.bytes[start..start + padding].fill(b' ');
            line.length += padding;
        }
    }
}

#[inline]
fn append_final_count(line: &mut FinalOutputLine, value: i64, unit: i64) {
    if unit == 1 {
        line.append_spaces(12);
    } else {
        append_final_amount(line, value, 0, true);
    }
}

#[inline]
fn emit_final_header(output: &OutputOwner, name: &[u8]) {
    let mut line = FinalOutputLine::new();
    line.append_bytes(b" ");
    line.append_left(name, 11);
    for column in [b"peak   ".as_slice(), b"total   ", b"current   ", b"block   ", b"total#   "] {
        // Each `%11s` in the pinned header has its own literal leading space.
        line.append_bytes(b" ");
        line.append_right(column, 11);
    }
    line.append_bytes(b"\n");
    // SAFETY: this helper is called only by the enclosing adapter's serialized
    // output scope.
    unsafe { emit_final_statistics_line(output, &line) };
}

#[inline]
fn emit_final_stat(output: &OutputOwner, statistic: FinalStatCount, name: &[u8], unit: i64, not_ok: &[u8]) {
    let mut line = FinalOutputLine::new();
    line.append_bytes(b"  ");
    line.append_left(name, 10);
    line.append_bytes(b":");
    if unit != 0 {
        if unit > 0 {
            append_final_amount(&mut line, statistic.peak, unit, true);
            append_final_amount(&mut line, statistic.total, unit, true);
            append_final_amount(&mut line, statistic.current, unit, true);
            append_final_amount(&mut line, unit, 1, true);
            append_final_count(&mut line, statistic.total, unit);
        } else {
            append_final_amount(&mut line, statistic.peak, -1, true);
            append_final_amount(&mut line, statistic.total, -1, true);
            append_final_amount(&mut line, statistic.current, -1, true);
            if unit == -1 {
                line.append_spaces(24);
            } else {
                append_final_amount(&mut line, -unit, 1, true);
                append_final_count(&mut line, statistic.total / -unit, 0);
            }
        }
        if statistic.current != 0 {
            line.append_bytes(b"  ");
            line.append_bytes(not_ok);
            line.append_bytes(b"\n");
        } else {
            line.append_bytes(b"  ok\n");
        }
    } else {
        append_final_amount(&mut line, statistic.peak, 0, true);
        append_final_amount(&mut line, statistic.total, 0, true);
        append_final_amount(&mut line, statistic.current, 0, true);
        line.append_bytes(b"\n");
    }
    // SAFETY: this helper is called only by the enclosing adapter's serialized
    // output scope.
    unsafe { emit_final_statistics_line(output, &line) };
}

#[inline]
fn emit_final_counter(output: &OutputOwner, value: i64, name: &[u8], unit: i64) {
    let mut line = FinalOutputLine::new();
    line.append_bytes(b"  ");
    line.append_left(name, 10);
    line.append_bytes(b":");
    append_final_amount(&mut line, value, unit, true);
    line.append_bytes(b"\n");
    // SAFETY: this helper is called only by the enclosing adapter's serialized
    // output scope.
    unsafe { emit_final_statistics_line(output, &line) };
}

#[inline]
fn emit_final_average(output: &OutputOwner, count: i64, total: i64, name: &[u8]) {
    let average_tens = if count == 0 { 0 } else { total.wrapping_mul(10) / count };
    let mut line = FinalOutputLine::new();
    line.append_bytes(b"  ");
    line.append_left(name, 10);
    let _ = write!(line, ": {:>5}.{} avg\n", average_tens / 10, (average_tens % 10).unsigned_abs());
    // SAFETY: this helper is called only by the enclosing adapter's serialized
    // output scope.
    unsafe { emit_final_statistics_line(output, &line) };
}

unsafe fn render_final_statistics(output: &OutputOwner, view: FinalProcessDiagnosticView) {
    let statistics = view.statistics;
    let process = view.process;
    let mut line = FinalOutputLine::new();
    let _ = write!(line, "subproc {}\n", view.subprocess_sequence);
    unsafe { emit_final_statistics_line(output, &line) };

    // `MI_STAT == 0` keeps the malloc section structurally present but emits
    // no lines.  The pages and arena sections retain their source guards.
    if statistics.pages.total != 0 {
        emit_final_header(output, b"pages");
        // `stats.c` supplies `""`, not NULL, for this explicit display
        // branch. A live final allocation therefore leaves its status field
        // blank instead of saying `not all freed`.
        emit_final_stat(output, statistics.page_committed, b"touched", 1, FINAL_EXPLICIT_EMPTY_NOT_OK);
        emit_final_stat(output, statistics.pages, b"pages", 0, FINAL_NOT_ALL_FREED);
        emit_final_stat(output, statistics.pages_abandoned, b"abandoned", 0, FINAL_NOT_ALL_FREED);
        emit_final_counter(output, statistics.pages_reclaim_on_alloc, b"reclaima", 0);
        emit_final_counter(output, statistics.pages_reclaim_on_free, b"reclaimf", 0);
        emit_final_counter(output, statistics.pages_reabandon_full, b"reabandon", 0);
        emit_final_counter(output, statistics.pages_unabandon_busy_wait, b"waits", 0);
        emit_final_counter(output, statistics.pages_extended, b"extended", 0);
        emit_final_counter(output, statistics.pages_retire, b"retire", 0);
        emit_final_average(output, statistics.page_searches_count, statistics.page_searches, b"searches");
        let mut separator = FinalOutputLine::new();
        separator.append_bytes(b"\n");
        unsafe { emit_final_statistics_line(output, &separator) };
    }

    if statistics.arena_count > 0 {
        emit_final_header(output, b"arenas");
        emit_final_stat(output, statistics.reserved, b"reserved", 1, FINAL_EXPLICIT_EMPTY_NOT_OK);
        emit_final_stat(output, statistics.committed, b"committed", 1, FINAL_EXPLICIT_EMPTY_NOT_OK);
        emit_final_counter(output, statistics.reset, b"reset", 1);
        emit_final_counter(output, statistics.purged, b"purged", 1);
        emit_final_counter(output, statistics.arena_count, b"arenas", 0);
        emit_final_counter(output, statistics.arena_rollback_count, b"rollback", 0);
        emit_final_counter(output, statistics.mmap_calls, b"mmaps", 0);
        emit_final_counter(output, statistics.commit_calls, b"commits", 0);
        emit_final_counter(output, statistics.reset_calls, b"resets", 0);
        emit_final_counter(output, statistics.purge_calls, b"purges", 0);
        emit_final_counter(output, statistics.malloc_guarded_count, b"guarded", 0);
        emit_final_stat(output, statistics.theaps, b"theaps", 0, FINAL_EXPLICIT_EMPTY_NOT_OK);
        emit_final_stat(output, statistics.heaps, b"heaps", 0, FINAL_EXPLICIT_EMPTY_NOT_OK);
        emit_final_counter(output, statistics.heaps_delete_wait, b"heap waits", 0);
        let mut separator = FinalOutputLine::new();
        separator.append_bytes(b"\n");
        unsafe { emit_final_statistics_line(output, &separator) };
    }

    emit_final_header(output, b"process");
    emit_final_stat(output, statistics.threads, b"threads", 0, FINAL_EXPLICIT_EMPTY_NOT_OK);
    let mut numa = FinalOutputLine::new();
    numa.append_bytes(b"  ");
    numa.append_left(b"numa nodes", 10);
    let _ = write!(numa, ": {:>5}\n", process.numa_nodes);
    unsafe { emit_final_statistics_line(output, &numa) };

    let mut elapsed = FinalOutputLine::new();
    elapsed.append_bytes(b"  ");
    elapsed.append_left(b"elapsed", 10);
    let _ = write!(elapsed, ": {:>5}.{:03} s\n", process.elapsed_milliseconds / 1_000, process.elapsed_milliseconds % 1_000);
    unsafe { emit_final_statistics_line(output, &elapsed) };

    let mut process_line = FinalOutputLine::new();
    process_line.append_bytes(b"  ");
    process_line.append_left(b"process", 10);
    let _ = write!(
        process_line,
        ": user: {}.{:03} s, system: {}.{:03} s, faults: {}, peak rss: ",
        process.user_milliseconds / 1_000,
        process.user_milliseconds % 1_000,
        process.system_milliseconds / 1_000,
        process.system_milliseconds % 1_000,
        process.page_faults,
    );
    append_final_amount(&mut process_line, process.peak_resident_bytes as i64, 1, false);
    if statistics.committed.peak > 0 {
        process_line.append_bytes(b", peak commit: ");
        append_final_amount(&mut process_line, statistics.committed.peak, 1, false);
    }
    process_line.append_bytes(b"\n");
    unsafe { emit_final_statistics_line(output, &process_line) };
    let mut separator = FinalOutputLine::new();
    separator.append_bytes(b"\n");
    unsafe { emit_final_statistics_line(output, &separator) };
}

unsafe fn render_final_verbose_tail(output: &OutputOwner, page_record_bytes: usize) {
    let mut line = FinalOutputLine::new();
    let _ = write!(line, "mimalloc: process done {page_record_bytes}\n");
    // SAFETY: `_mi_verbose_message` dispatches its one complete message
    // directly. Unlike statistics it has no 255-byte buffered wrapper.
    unsafe { output.raw_message(line.as_message()) };
}

fn invalid_diagnostic_option_message(index: usize) -> SourceFormattedMessage {
    let message = match index {
        DIAGNOSTIC_SHOW_ERRORS => b"environment option mimalloc_show_errors has an invalid value.\n\0".as_slice(),
        DIAGNOSTIC_SHOW_STATS => b"environment option mimalloc_show_stats has an invalid value.\n\0".as_slice(),
        DIAGNOSTIC_VERBOSE => b"environment option mimalloc_verbose has an invalid value.\n\0".as_slice(),
        DIAGNOSTIC_MAX_WARNINGS => b"environment option mimalloc_max_warnings has an invalid value.\n\0".as_slice(),
        _ => unreachable!("only the fixed selected source descriptors are selectable"),
    };
    // SAFETY: each fixed source message is NUL-terminated and has no interior
    // NUL, matching the fixed `mi_option_init` literals.
    SourceFormattedMessage::from_source_formatted(unsafe { CStr::from_bytes_with_nul_unchecked(message) })
}

/// Borrowed route from a process-owned diagnostic image to the one pinned
/// failed-`mbind` warning call site. It carries no VM policy, mapping, or
/// callback ownership and exists only while the source startup reservation
/// chain holds the process owner.
#[derive(Clone, Copy)]
pub(crate) struct MbindWarningRoute<'owner> {
    output: &'owner OutputOwner,
}

impl<'owner> MbindWarningRoute<'owner> {
    #[inline]
    pub(crate) const fn new(output: &'owner OutputOwner) -> Self {
        Self { output }
    }

    /// Delivers the source body after a failed valid-node `mbind` while the
    /// mapping remains owned by its caller.
    ///
    /// # Safety
    ///
    /// The caller must preserve the process startup dispatch serialization and
    /// every [`OutputOwner`] callback lifetime obligation, including this
    /// private slice's exclusion of synchronous source-option-route reentry
    /// from delivery. `numa_node` must have passed the source
    /// `0 <= node < 8 * MI_INTPTR_SIZE - 1` predicate.
    #[inline]
    pub(crate) unsafe fn mbind_failure(&self, numa_node: i32, errno: Errno) {
        let message = SourceFormattedMessage::mbind_failure(numa_node, errno);
        unsafe { self.output.warning_from_source_options(message) };
    }
}

#[inline]
fn callback_to_pointer(callback: OutputCallback) -> *mut () {
    callback as *const () as *mut ()
}

#[inline]
fn pointer_to_callback(pointer: *mut ()) -> OutputCallback {
    // SAFETY: only `callback_to_pointer` initializes this atomic storage, and
    // the non-null pointer is loaded before conversion.
    unsafe { core::mem::transmute(pointer) }
}

#[inline]
unsafe fn invoke_callback(callback: OutputCallback, message: &CStr, argument: *mut c_void) {
    // SAFETY: the caller supplies a source-shaped callback/opaque-argument
    // lifetime contract, and `message` remains valid for the call.
    unsafe { callback(message.as_ptr(), argument) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        DiagnosticOptionSnapshot, FinalDiagnosticOutputError, FinalProcessDiagnosticView, FinalProcessInfo,
        FinalStatisticsOutputPermit, OutputCallback, OutputOwner, SourceFormattedMessage,
        ThreadWarningPrefix,
    };
    use crate::{
        os::ProcessUsage,
        statistics::{FinalStatCount, FinalStatisticsSnapshot},
    };
    use crabc_core::{Errno, thread::thread_pointer_identity};
    use core::cell::UnsafeCell;
    use core::ffi::{c_char, c_void, CStr};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    const MAX_MESSAGES: usize = 80;
    const MAX_MESSAGE_BYTES: usize = 256;

    struct Capture {
        count: AtomicUsize,
        lengths: UnsafeCell<[usize; MAX_MESSAGES]>,
        messages: UnsafeCell<[[u8; MAX_MESSAGE_BYTES]; MAX_MESSAGES]>,
    }

    // Test callbacks run on the registration/emission thread. The tests read
    // the fixed storage only after that callback route has returned.
    unsafe impl Sync for Capture {}

    impl Capture {
        const fn new() -> Self {
            Self {
                count: AtomicUsize::new(0),
                lengths: UnsafeCell::new([0; MAX_MESSAGES]),
                messages: UnsafeCell::new([[0; MAX_MESSAGE_BYTES]; MAX_MESSAGES]),
            }
        }

        fn reset(&self) {
            self.count.store(0, Ordering::Relaxed);
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::Relaxed)
        }

        fn message(&self, index: usize) -> &[u8] {
            assert!(index < self.count());
            // SAFETY: callbacks are complete before each assertion reads the
            // single-threaded test capture.
            let lengths = unsafe { &*self.lengths.get() };
            // SAFETY: see the `lengths` access above.
            let messages = unsafe { &*self.messages.get() };
            &messages[index][..lengths[index]]
        }
    }

    unsafe extern "C" fn capture_output(message: *const c_char, argument: *mut c_void) {
        if message.is_null() || argument.is_null() {
            return;
        }
        // SAFETY: every test passes a live `Capture` as the opaque argument.
        let capture = unsafe { &*(argument as *const Capture) };
        // SAFETY: `OutputOwner` invokes an output callback with a NUL-terminated
        // source-form message whose storage remains live for the callback.
        let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
        let index = capture.count.fetch_add(1, Ordering::Relaxed);
        if index >= MAX_MESSAGES || bytes.len() > MAX_MESSAGE_BYTES {
            return;
        }
        // SAFETY: this test callback is single-threaded and writes its unique
        // fixed slot before the test reads it.
        unsafe {
            let messages = &mut *capture.messages.get();
            let lengths = &mut *capture.lengths.get();
            messages[index][..bytes.len()].copy_from_slice(bytes);
            lengths[index] = bytes.len();
        }
    }

    fn capture_argument(capture: &Capture) -> *mut c_void {
        capture as *const Capture as *mut c_void
    }

    fn assert_live_thread_warning_prefix(prefix: &[u8]) {
        let expected = std::format!(
            "mimalloc: warning: thread 0x{:X}: ",
            thread_pointer_identity(),
        );
        assert_eq!(prefix, expected.as_bytes());
    }

    static DEFAULT_STDERR_CAPTURE: Capture = Capture::new();
    static DEFAULT_STDERR_TEST_LOCK: Mutex<()> = Mutex::new(());
    static DIAGNOSTIC_ENVIRONMENT_TEST_LOCK: Mutex<()> = Mutex::new(());
    static DIAGNOSTIC_ENVIRONMENT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DIAGNOSTIC_ENVIRONMENT_MODE: AtomicUsize = AtomicUsize::new(0);
    static mut DIAGNOSTIC_ENVIRONMENT_ENTRIES: [*const c_char; 5] = [core::ptr::null(); 5];

    const DIAGNOSTIC_ENV_FIXED: usize = 0;
    const DIAGNOSTIC_ENV_FOUR_UNAVAILABLE_THEN_VERBOSE: usize = 1;

    unsafe fn diagnostic_test_environment_reader() -> *const *const c_char {
        let call = DIAGNOSTIC_ENVIRONMENT_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
        if DIAGNOSTIC_ENVIRONMENT_MODE.load(Ordering::Relaxed)
            == DIAGNOSTIC_ENV_FOUR_UNAVAILABLE_THEN_VERBOSE && call <= 4
        {
            return core::ptr::null();
        }
        // SAFETY: the test lock serializes fixed-vector writes and every
        // synchronous owner observation stays inside that locked test scope.
        unsafe { core::ptr::addr_of!(DIAGNOSTIC_ENVIRONMENT_ENTRIES).cast() }
    }

    unsafe fn install_diagnostic_test_environment(
        mode: usize,
        entries: [*const c_char; 5],
    ) {
        // SAFETY: callers hold DIAGNOSTIC_ENVIRONMENT_TEST_LOCK and no route
        // can outlive the test's synchronous initialization/dispatch.
        unsafe { DIAGNOSTIC_ENVIRONMENT_ENTRIES = entries };
        DIAGNOSTIC_ENVIRONMENT_CALLS.store(0, Ordering::Relaxed);
        DIAGNOSTIC_ENVIRONMENT_MODE.store(mode, Ordering::Relaxed);
    }

    fn default_stderr_test_guard() -> MutexGuard<'static, ()> {
        DEFAULT_STDERR_TEST_LOCK
            .lock()
            .expect("default stderr capture lock is not poisoned")
    }

    unsafe extern "C" fn test_default_stderr_output(message: *const c_char) {
        // SAFETY: the test suite serializes this fixed test primitive and the
        // static capture remains live for every default delivery.
        unsafe { capture_output(message, capture_argument(&DEFAULT_STDERR_CAPTURE)) };
    }

    fn output_owner() -> OutputOwner {
        OutputOwner::new(test_default_stderr_output)
    }

    fn reset_default_stderr_capture() {
        DEFAULT_STDERR_CAPTURE.reset();
    }

    fn source_message(bytes: &[u8]) -> SourceFormattedMessage {
        SourceFormattedMessage::from_source_formatted(
            CStr::from_bytes_with_nul(bytes).expect("test messages are NUL-terminated"),
        )
    }

    const fn final_stat_count(peak: i64, total: i64, current: i64) -> FinalStatCount {
        FinalStatCount { peak, total, current }
    }

    fn final_statistics_fixture() -> FinalStatisticsSnapshot {
        FinalStatisticsSnapshot {
            pages: final_stat_count(5, 7, 2),
            page_committed: final_stat_count(6_144, 5_120, 4_096),
            pages_abandoned: final_stat_count(1, 2, 0),
            threads: final_stat_count(2, 2, 1),
            reserved: final_stat_count(2_048, 3_072, 1_024),
            committed: final_stat_count(2_048, 3_072, 1_024),
            theaps: final_stat_count(2, 2, 1),
            heaps: final_stat_count(3, 3, 1),
            reset: 1_024,
            purged: 2_048,
            mmap_calls: 3,
            commit_calls: 4,
            reset_calls: 5,
            purge_calls: 6,
            arena_count: 1,
            malloc_guarded_count: 7,
            arena_rollback_count: 2,
            pages_reclaim_on_alloc: 3,
            pages_reclaim_on_free: 4,
            pages_reabandon_full: 5,
            pages_unabandon_busy_wait: 6,
            pages_extended: 7,
            pages_retire: 8,
            page_searches: 9,
            page_searches_count: 2,
            heaps_delete_wait: 8,
        }
    }

    fn final_process_view() -> FinalProcessDiagnosticView {
        FinalProcessDiagnosticView::new(
            7,
            final_statistics_fixture(),
            FinalProcessInfo::new(12_345, 5_678, 91_011, 4_096, 12, 3),
        )
    }

    fn final_statistics_permit(owner: &OutputOwner) -> FinalStatisticsOutputPermit<'_> {
        // SAFETY: every caller owns the selected final output phase and its
        // serialized callback lifetime through the permit's later emission.
        unsafe { owner.final_statistics_enabled() }
            .expect("the selected source final statistics gate must inspect its owner")
            .expect("the selected source final statistics gate must be enabled")
    }

    fn install_final_output_environment(show_stats: &[u8], verbose: &[u8]) {
        let show_errors = b"mimalloc_show_errors=0\0";
        let max_warnings = b"mimalloc_max_warnings=32\0";
        // SAFETY: every caller holds DIAGNOSTIC_ENVIRONMENT_TEST_LOCK and
        // keeps the fixed input byte strings live through its synchronous use.
        unsafe {
            install_diagnostic_test_environment(
                DIAGNOSTIC_ENV_FIXED,
                [
                    show_errors.as_ptr().cast(),
                    show_stats.as_ptr().cast(),
                    verbose.as_ptr().cast(),
                    max_warnings.as_ptr().cast(),
                    core::ptr::null(),
                ],
            )
        };
    }

    struct LengthCapture {
        count: AtomicUsize,
        last_length: AtomicUsize,
    }

    impl LengthCapture {
        const fn new() -> Self {
            Self {
                count: AtomicUsize::new(0),
                last_length: AtomicUsize::new(0),
            }
        }
    }

    unsafe extern "C" fn capture_length(message: *const c_char, argument: *mut c_void) {
        if message.is_null() || argument.is_null() {
            return;
        }
        // SAFETY: this test passes a live `LengthCapture` and the owner holds
        // the source-shaped buffer live through the callback.
        let capture = unsafe { &*(argument as *const LengthCapture) };
        let length = unsafe { CStr::from_ptr(message) }.to_bytes().len();
        capture.last_length.store(length, Ordering::Relaxed);
        capture.count.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn source_formatted_message_retains_the_990_byte_vfprintf_payload_limit() {
        let mut source = [b'x'; 992];
        source[991] = 0;
        let source = CStr::from_bytes_with_nul(&source).expect("one terminal NUL");

        let bounded = SourceFormattedMessage::from_source_formatted(source);

        assert_eq!(bounded.as_c_str().to_bytes().len(), 990);
    }

    #[test]
    fn mbind_failure_body_formats_each_valid_source_node_and_representative_errno() {
        // `_mi_prim_alloc_huge_os_pages` accepts a node strictly below
        // `8 * MI_INTPTR_SIZE - 1`: every 64-bit source-valid node is 0..62.
        // These errno representatives prove `%ld` and the source `%lx`
        // minimum-two, uppercase format without baking the fixture's EPERM
        // body into this selected formatter.
        for numa_node in 0..63 {
            for raw_errno in [1, 9, 10, 15, 16, 255, 4095] {
                let body = SourceFormattedMessage::mbind_failure(
                    numa_node,
                    Errno::from_raw(raw_errno).expect("representative Linux errno"),
                );
                let expected = std::format!(
                    "failed to bind huge (1GiB) pages to numa node {numa_node} (error: {raw_errno} (0x{raw_errno:02X}))\n"
                );

                assert_eq!(body.as_c_str().to_bytes(), expected.as_bytes());
                assert_eq!(body.as_c_str().to_bytes_with_nul().len(), body.length + 1);
                assert_eq!(body.bytes.len(), 992);
                assert!(body.length <= 990);
            }
        }
    }

    #[test]
    fn invalid_show_errors_resolves_verbose_before_the_source_warning_gate() {
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_errors = b"mimalloc_show_errors=bogus\0";
        let verbose = b"mimalloc_verbose=1\0";
        // SAFETY: the lock serializes this raw-environment fixture and the
        // static byte strings remain live through initialization below.
        unsafe {
            install_diagnostic_test_environment(
                DIAGNOSTIC_ENV_FIXED,
                [
                    show_errors.as_ptr().cast(), verbose.as_ptr().cast(),
                    core::ptr::null(), core::ptr::null(), core::ptr::null(),
                ],
            )
        };
        let mut owner = output_owner();
        let capture = Capture::new();
        // SAFETY: the test owns the callback and serializes registration with
        // the private source-option initialization phase.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();
        // SAFETY: no route is borrowed until this exclusive initialization has
        // completed; the reader uses the test's stable raw vector.
        unsafe { owner.initialize_source_options(diagnostic_test_environment_reader) };

        assert_eq!(DIAGNOSTIC_ENVIRONMENT_CALLS.load(Ordering::Relaxed), 4);
        assert_eq!(capture.count(), 2);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(
            capture.message(1),
            b"environment option mimalloc_show_errors has an invalid value.\n",
            "show_errors defaults before its warning, then the source gate lazily resolves verbose=1",
        );
    }

    #[test]
    fn uninitialized_warning_gate_retries_verbose_before_show_errors() {
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_errors = b"mimalloc_show_errors=0\0";
        let verbose = b"mimalloc_verbose=1\0";
        // The four startup reads are unavailable. The first warning retry may
        // resolve only verbose: enabled verbose bypasses show_errors entirely.
        unsafe {
            install_diagnostic_test_environment(
                DIAGNOSTIC_ENV_FOUR_UNAVAILABLE_THEN_VERBOSE,
                [
                    show_errors.as_ptr().cast(), verbose.as_ptr().cast(),
                    core::ptr::null(), core::ptr::null(), core::ptr::null(),
                ],
            )
        };
        let mut owner = output_owner();
        let capture = Capture::new();
        // SAFETY: one callback and synchronous source initialization/dispatch.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();
        // SAFETY: the test owns option initialization before borrowing a route.
        unsafe { owner.initialize_source_options(diagnostic_test_environment_reader) };
        // SAFETY: registration remains live and the private lock serializes
        // the one source descriptor retry.
        unsafe { owner.warning_from_source_options(source_message(b"mbind retry\n\0")) };

        assert_eq!(DIAGNOSTIC_ENVIRONMENT_CALLS.load(Ordering::Relaxed), 5);
        assert_eq!(capture.count(), 2);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"mbind retry\n");
    }

    struct SourceOptionsLockCapture {
        capture: Capture,
        owner: *const OutputOwner,
        observed_available: AtomicBool,
    }

    unsafe impl Sync for SourceOptionsLockCapture {}

    unsafe extern "C" fn capture_source_options_lock(
        message: *const c_char,
        argument: *mut c_void,
    ) {
        // SAFETY: this test passes its live capture as the one registered
        // opaque callback argument.
        let capture = unsafe { &*(argument as *const SourceOptionsLockCapture) };
        let owner = unsafe { &*capture.owner };
        if owner.source_options_lock.try_lock().is_some() {
            capture.observed_available.store(true, Ordering::Relaxed);
        }
        unsafe { capture_output(message, capture_argument(&capture.capture)) };
    }

    #[test]
    fn source_option_lock_is_released_before_callback_delivery() {
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_errors = b"mimalloc_show_errors=1\0";
        let verbose = b"mimalloc_verbose=0\0";
        let max_warnings = b"mimalloc_max_warnings=32\0";
        unsafe {
            install_diagnostic_test_environment(
                DIAGNOSTIC_ENV_FIXED,
                [
                    show_errors.as_ptr().cast(), verbose.as_ptr().cast(), max_warnings.as_ptr().cast(),
                    core::ptr::null(), core::ptr::null(),
                ],
            )
        };
        let mut owner = output_owner();
        // SAFETY: this test owns the raw test vector through initialization.
        unsafe { owner.initialize_source_options(diagnostic_test_environment_reader) };
        let capture = SourceOptionsLockCapture {
            capture: Capture::new(),
            owner: &owner,
            observed_available: AtomicBool::new(false),
        };
        // SAFETY: the callback and opaque state remain live and registration
        // is serialized with this one source warning route.
        unsafe {
            owner.register_output(
                Some(capture_source_options_lock),
                &capture as *const SourceOptionsLockCapture as *mut c_void,
            )
        };
        capture.capture.reset();
        // SAFETY: the registered callback remains live; no registration races
        // this selected warning route.
        unsafe { owner.warning_from_source_options(source_message(b"mbind callback\n\0")) };

        assert_eq!(capture.capture.count(), 2);
        assert!(capture.observed_available.load(Ordering::Relaxed));
    }

    #[test]
    fn final_process_info_clamps_the_source_signed_time_scalars() {
        let usage = ProcessUsage {
            user_milliseconds: -1,
            system_milliseconds: i64::MAX,
            peak_resident_bytes: 4_096,
            major_page_faults: 7,
        };
        assert_eq!(
            FinalProcessInfo::from_source_observations(-1, usage, 3),
            FinalProcessInfo::new(0, 0, isize::MAX as usize, 4_096, 7, 3),
            "stats.c clamps elapsed, user, and system before its size_t formatter",
        );
    }

    #[test]
    fn final_process_info_uses_the_committed_defaults_when_unix_sampling_fails() {
        let mut statistics = final_statistics_fixture();
        statistics.committed = final_stat_count(-1, 0, i64::MAX);
        let committed = statistics.process_info_committed_defaults();
        assert_eq!(committed.current_bytes, 0);
        assert_eq!(committed.peak_bytes, isize::MAX as usize);
        assert_eq!(
            FinalProcessInfo::from_source_committed_defaults(-1, committed, 3),
            FinalProcessInfo::new(0, 0, 0, isize::MAX as usize, 0, 3),
            "stats.c keeps its committed RSS/default counters when getrusage fails",
        );
    }

    #[test]
    fn signed_show_stats_emits_the_pinned_final_statistics_layout() {
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_stats = b"mimalloc_show_stats=-7\0";
        let verbose = b"mimalloc_verbose=0\0";
        install_final_output_environment(show_stats, verbose);
        let mut owner = output_owner();
        // SAFETY: this test owns the fixed environment through initialization.
        unsafe { owner.initialize_source_options(diagnostic_test_environment_reader) };
        let capture = Capture::new();
        // SAFETY: the callback remains live and registration is serialized.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this selects source output before the caller performs the
        // state work and sampling that construct the later scalar view.
        let permit = final_statistics_permit(&owner);
        // SAFETY: this test supplies the completed source-order scalar image
        // and serializes final output with registration.
        unsafe { permit.emit(final_process_view()) };
        // SAFETY: verbose is zero in the same selected source option image.
        assert_eq!(unsafe { owner.final_process_done_message(97) }, Ok(false));

        let expected: &[&[u8]] = &[
            b"subproc 7\n",
            b" pages           peak       total     current       block      total#   \n",
            b"  touched   :     6.0 KiB     5.0 KiB     4.0 KiB                          \n",
            b"  pages     :     5           7           2      \n",
            b"  abandoned :     1           2           0      \n",
            b"  reclaima  :     3      \n",
            b"  reclaimf  :     4      \n",
            b"  reabandon :     5      \n",
            b"  waits     :     6      \n",
            b"  extended  :     7      \n",
            b"  retire    :     8      \n",
            b"  searches  :     4.5 avg\n",
            b"\n",
            b" arenas          peak       total     current       block      total#   \n",
            b"  reserved  :     2.0 KiB     3.0 KiB     1.0 KiB                          \n",
            b"  committed :     2.0 KiB     3.0 KiB     1.0 KiB                          \n",
            b"  reset     :     1.0 KiB\n",
            b"  purged    :     2.0 KiB\n",
            b"  arenas    :     1      \n",
            b"  rollback  :     2      \n",
            b"  mmaps     :     3      \n",
            b"  commits   :     4      \n",
            b"  resets    :     5      \n",
            b"  purges    :     6      \n",
            b"  guarded   :     7      \n",
            b"  theaps    :     2           2           1      \n",
            b"  heaps     :     3           3           1      \n",
            b"  heap waits:     8      \n",
            b"\n",
            b" process         peak       total     current       block      total#   \n",
            b"  threads   :     2           2           1      \n",
            b"  numa nodes:     3\n",
            b"  elapsed   :    12.345 s\n",
            b"  process   : user: 5.678 s, system: 91.011 s, faults: 12, peak rss: 4.0 KiB, peak commit: 2.0 KiB\n",
            b"\n",
        ];
        assert_eq!(capture.count(), expected.len());
        for (index, expected) in expected.iter().enumerate() {
            assert_eq!(capture.message(index), *expected, "source final line {index}");
        }
    }

    #[test]
    fn signed_show_stats_short_circuits_an_uninitialized_invalid_verbose_descriptor() {
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_errors = b"mimalloc_show_errors=0\0";
        let show_stats = b"mimalloc_show_stats=-7\0";
        let verbose = b"mimalloc_verbose=not-a-number\0";
        let max_warnings = b"mimalloc_max_warnings=32\0";
        // Leave every source descriptor UNINIT during startup. The final
        // source `show_stats || verbose` condition must resolve show_stats
        // alone and must neither read nor stage verbose's invalid warning.
        unsafe {
            install_diagnostic_test_environment(
                DIAGNOSTIC_ENV_FOUR_UNAVAILABLE_THEN_VERBOSE,
                [
                    show_errors.as_ptr().cast(),
                    show_stats.as_ptr().cast(),
                    verbose.as_ptr().cast(),
                    max_warnings.as_ptr().cast(),
                    core::ptr::null(),
                ],
            )
        };
        let mut owner = output_owner();
        // SAFETY: the raw fixture environment is locked and remains live.
        unsafe { owner.initialize_source_options(diagnostic_test_environment_reader) };
        let capture = Capture::new();
        // SAFETY: this test owns the callback and serializes the final phase.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this runs the source gate before the later scalar capture.
        let permit = final_statistics_permit(&owner);
        assert_eq!(DIAGNOSTIC_ENVIRONMENT_CALLS.load(Ordering::Relaxed), 5);
        // SAFETY: the scalar view is complete and output is serialized.
        unsafe { permit.emit(final_process_view()) };
        assert_eq!(
            DIAGNOSTIC_ENVIRONMENT_CALLS.load(Ordering::Relaxed),
            5,
            "the permit emitter must not revisit a source option after the merge/sampling boundary",
        );
        assert_eq!(capture.count(), 35);
        assert_eq!(capture.message(0), b"subproc 7\n");
        assert!(
            !capture.message(0).starts_with(b"mimalloc: warning:"),
            "the unread verbose descriptor cannot stage a source warning"
        );
    }

    #[test]
    fn verbose_final_statistics_precede_the_common_process_done_message() {
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_stats = b"mimalloc_show_stats=0\0";
        let verbose = b"mimalloc_verbose=-1\0";
        install_final_output_environment(show_stats, verbose);
        let mut owner = output_owner();
        // SAFETY: this test owns the fixed environment through initialization.
        unsafe { owner.initialize_source_options(diagnostic_test_environment_reader) };
        let capture = Capture::new();
        // SAFETY: the callback remains live and registration is serialized.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: the source gate precedes this test's later scalar view.
        let permit = final_statistics_permit(&owner);
        // SAFETY: the view is complete and this test owns the current output phase.
        unsafe { permit.emit(final_process_view()) };
        let statistics_lines = capture.count();
        // SAFETY: this is the later init.c common-tail phase, after statistics.
        assert_eq!(unsafe { owner.final_process_done_message(97) }, Ok(true));
        assert_eq!(statistics_lines, 35);
        assert_eq!(capture.count(), statistics_lines + 1);
        assert_eq!(capture.message(statistics_lines - 1), b"\n");
        assert_eq!(capture.message(statistics_lines), b"mimalloc: process done 97\n");
    }

    #[test]
    fn final_statistics_release_the_descriptor_lock_before_output_callback() {
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_stats = b"mimalloc_show_stats=1\0";
        let verbose = b"mimalloc_verbose=0\0";
        install_final_output_environment(show_stats, verbose);
        let mut owner = output_owner();
        // SAFETY: this test owns the fixed environment through initialization.
        unsafe { owner.initialize_source_options(diagnostic_test_environment_reader) };
        let capture = SourceOptionsLockCapture {
            capture: Capture::new(),
            owner: &owner,
            observed_available: AtomicBool::new(false),
        };
        // SAFETY: the callback remains live and this output phase is serialized.
        unsafe {
            owner.register_output(
                Some(capture_source_options_lock),
                &capture as *const SourceOptionsLockCapture as *mut c_void,
            )
        };
        capture.capture.reset();

        // SAFETY: this selects output before the test constructs its scalar image.
        let permit = final_statistics_permit(&owner);
        // SAFETY: no registration overlaps this completed scalar output phase.
        unsafe { permit.emit(final_process_view()) };
        assert_eq!(capture.capture.count(), 35);
        assert!(capture.observed_available.load(Ordering::Relaxed));
    }

    #[test]
    fn disabled_final_statistics_and_verbose_tail_emit_nothing() {
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_stats = b"mimalloc_show_stats=0\0";
        let verbose = b"mimalloc_verbose=0\0";
        install_final_output_environment(show_stats, verbose);
        let mut owner = output_owner();
        // SAFETY: this test owns the fixed environment through initialization.
        unsafe { owner.initialize_source_options(diagnostic_test_environment_reader) };
        let capture = Capture::new();
        // SAFETY: the callback remains live and registration is serialized.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: these source phases are serialized with registration.
        assert!(matches!(
            unsafe { owner.final_statistics_enabled() },
            Ok(None)
        ));
        // SAFETY: these source phases are serialized with registration.
        assert_eq!(unsafe { owner.final_process_done_message(97) }, Ok(false));
        assert_eq!(capture.count(), 0);
    }

    #[test]
    fn unavailable_source_options_are_not_final_output_disabled() {
        let owner = output_owner();

        // SAFETY: these both stop before source output because the option
        // owner is not initialized. An unavailable owner must remain
        // distinguishable from source-disabled output so the one-way process
        // caller retains rather than completing a partial transition.
        assert!(matches!(
            unsafe { owner.final_statistics_enabled() },
            Err(FinalDiagnosticOutputError::SourceOptionsUnavailable)
        ));
        // SAFETY: same owner and no callback dispatch occur before this error.
        assert!(matches!(
            unsafe { owner.final_process_done_message(97) },
            Err(FinalDiagnosticOutputError::SourceOptionsUnavailable)
        ));
    }

    #[test]
    fn default_dispatch_and_registration_are_explicitly_unsafe_contracts() {
        let _ = OutputOwner::register_output
            as unsafe fn(&OutputOwner, Option<OutputCallback>, *mut c_void);
        let _ = OutputOwner::post_init as unsafe fn(&OutputOwner);
        let _ = OutputOwner::raw_message as unsafe fn(&OutputOwner, SourceFormattedMessage);
        let _ = OutputOwner::warning
            as unsafe fn(&OutputOwner, DiagnosticOptionSnapshot, SourceFormattedMessage);
        let _ = OutputOwner::final_statistics_enabled
            as for<'owner> unsafe fn(
                &'owner OutputOwner,
            ) -> Result<Option<FinalStatisticsOutputPermit<'owner>>, FinalDiagnosticOutputError>;
        let _: unsafe fn(FinalStatisticsOutputPermit<'static>, FinalProcessDiagnosticView) =
            FinalStatisticsOutputPermit::<'static>::emit;
        let _ = OutputOwner::final_process_done_message
            as unsafe fn(&OutputOwner, usize) -> Result<bool, FinalDiagnosticOutputError>;
    }

    #[test]
    fn delayed_output_keeps_at_most_16k_minus_its_terminal_nul_then_stops() {
        let owner = output_owner();
        let capture = LengthCapture::new();
        let mut source = [b'x'; 991];
        source[990] = 0;

        for _ in 0..17 {
            // SAFETY: the test has no concurrent registration or dispatch.
            unsafe { owner.raw_message(source_message(&source)) };
        }
        // SAFETY: this is the only registration, and the capture remains live.
        unsafe {
            owner.register_output(
                Some(capture_length),
                &capture as *const LengthCapture as *mut c_void,
            )
        };

        assert_eq!(capture.count.load(Ordering::Relaxed), 1);
        assert_eq!(capture.last_length.load(Ordering::Relaxed), 16 * 1024 - 1);

        // SAFETY: registration is complete before the final custom dispatch.
        unsafe { owner.raw_message(source_message(&source)) };
        assert_eq!(capture.count.load(Ordering::Relaxed), 2);
        assert_eq!(capture.last_length.load(Ordering::Relaxed), 990);
    }

    #[test]
    fn initialized_release_limit_replaces_the_initial_16_warning_cap() {
        let initial_owner = output_owner();
        let initial_capture = Capture::new();
        // SAFETY: the test owns the one callback and serializes all dispatch.
        unsafe {
            initial_owner.register_output(
                Some(capture_output),
                capture_argument(&initial_capture),
            )
        };
        initial_capture.reset();

        for _ in 0..17 {
            // SAFETY: no registration overlaps these isolated pre-init calls.
            unsafe {
                initial_owner.warning(
                    DiagnosticOptionSnapshot::new(1, 0, 32),
                    source_message(b"w\n\0"),
                )
            };
        }
        assert_eq!(initial_capture.count(), 34);

        let initialized_options = DiagnosticOptionSnapshot::new(1, 0, 32);
        let mut initialized_owner = output_owner();
        initialized_owner.initialize_options(DiagnosticOptionSnapshot::release_defaults());
        let initialized_capture = Capture::new();
        // SAFETY: the test owns the one callback and serializes all dispatch.
        unsafe {
            initialized_owner.register_output(
                Some(capture_output),
                capture_argument(&initialized_capture),
            )
        };
        initialized_capture.reset();

        for _ in 0..17 {
            // SAFETY: no registration overlaps these isolated initialized calls.
            unsafe { initialized_owner.warning(initialized_options, source_message(b"w\n\0")) };
        }
        assert_eq!(initialized_capture.count(), 34);
    }

    #[test]
    fn release_default_suppresses_warning_after_custom_registration() {
        let options = DiagnosticOptionSnapshot::release_defaults();
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: `capture` and its callback remain live and registration is
        // serialized for this source-shaped test owner.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset(); // Registration flushes the source's empty delayed buffer.

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe { owner.warning(options, source_message(b"selected mbind failure\n\0")) };

        assert_eq!(capture.count(), 0);
    }

    #[test]
    fn thread_warning_prefix_uses_source_zero_minimal_uppercase_and_64_byte_bounds() {
        assert_eq!(ThreadWarningPrefix::new(0).as_c_str().to_bytes(), b"mimalloc: warning: thread 0x0: ");
        assert_eq!(
            ThreadWarningPrefix::new(0x00a_bC0d).as_c_str().to_bytes(),
            b"mimalloc: warning: thread 0xABC0D: ",
        );
        let maximum = ThreadWarningPrefix::new(usize::MAX);
        assert_eq!(
            maximum.as_c_str().to_bytes(),
            b"mimalloc: warning: thread 0xFFFFFFFFFFFFFFFF: ",
        );
        assert_eq!(maximum.length, 46);
        assert_eq!(maximum.as_c_str().to_bytes_with_nul().len(), 47);
        assert!(maximum.length < 64);
    }

    #[test]
    fn enabled_warning_delivers_prefix_then_body() {
        let options = DiagnosticOptionSnapshot::new(1, 0, 1);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: this test keeps the callback and opaque state alive and
        // performs the one source-permitted registration from one thread.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe { owner.warning(options, source_message(b"selected mbind failure\n\0")) };

        assert_eq!(capture.count(), 2);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"selected mbind failure\n");
    }

    #[test]
    fn warning_count_cap_one_admits_the_two_pre_increment_values() {
        let options = DiagnosticOptionSnapshot::new(1, 0, 1);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: the callback/argument lifetime and serialized-registration
        // obligations hold for this test.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe {
            owner.warning(options, source_message(b"first\n\0"));
            owner.warning(options, source_message(b"second\n\0"));
        }

        assert_eq!(capture.count(), 4);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"first\n");
        assert_live_thread_warning_prefix(capture.message(2));
        assert_eq!(capture.message(3), b"second\n");
    }

    #[test]
    fn zero_warning_cap_admits_only_the_zero_pre_increment_value() {
        let options = DiagnosticOptionSnapshot::new(1, 0, 0);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: the callback/argument lifetime and serialized-registration
        // obligations hold for this test.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe {
            owner.warning(options, source_message(b"first\n\0"));
            owner.warning(options, source_message(b"second\n\0"));
        }

        assert_eq!(capture.count(), 2);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"first\n");
    }

    #[test]
    fn configured_default_32_warning_cap_admits_33_pre_increment_values() {
        let options = DiagnosticOptionSnapshot::new(1, 0, 32);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: the callback/argument lifetime and serialized-registration
        // obligations hold for this test.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        for _ in 0..34 {
            unsafe { owner.warning(options, source_message(b"default\n\0")) };
        }

        assert_eq!(capture.count(), 66);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"default\n");
        assert_live_thread_warning_prefix(capture.message(64));
        assert_eq!(capture.message(65), b"default\n");
    }

    #[test]
    fn negative_warning_cap_leaves_the_source_counter_gate_unbounded() {
        let options = DiagnosticOptionSnapshot::new(1, 0, -1);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: the callback/argument lifetime and serialized-registration
        // obligations hold for this test.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe {
            owner.warning(options, source_message(b"first\n\0"));
            owner.warning(options, source_message(b"second\n\0"));
        }

        assert_eq!(capture.count(), 4);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"first\n");
        assert_live_thread_warning_prefix(capture.message(2));
        assert_eq!(capture.message(3), b"second\n");
    }

    #[test]
    fn verbose_bypasses_show_errors_and_warning_cap() {
        let options = DiagnosticOptionSnapshot::new(0, 1, 0);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: the callback/argument lifetime and serialized-registration
        // obligations hold for this test.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe {
            owner.warning(options, source_message(b"first\n\0"));
            owner.warning(options, source_message(b"second\n\0"));
        }

        assert_eq!(capture.count(), 4);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"first\n");
        assert_live_thread_warning_prefix(capture.message(2));
        assert_eq!(capture.message(3), b"second\n");
    }

    #[test]
    fn custom_registration_flushes_delayed_bytes_once_and_stops_the_buffer() {
        let owner = output_owner();
        let capture = Capture::new();

        // SAFETY: this test serializes each dispatch with registration.
        unsafe { owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: this one registration retains the callback state until the
        // test ends and is not concurrent with another registration.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        // SAFETY: registration is complete before this dispatch.
        unsafe { owner.raw_message(source_message(b"later\n\0")) };

        assert_eq!(capture.count(), 2);
        assert_eq!(capture.message(0), b"early\n");
        assert_eq!(capture.message(1), b"later\n");
    }

    #[test]
    fn null_registration_keeps_delayed_bytes_for_a_later_custom_registration() {
        let _guard = default_stderr_test_guard();
        let owner = output_owner();
        let capture = Capture::new();
        reset_default_stderr_capture();

        // SAFETY: this test serializes each dispatch with registration.
        unsafe { owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: the null route still follows the source's serialized
        // registration contract. Its argument is ignored by the stderr sink.
        unsafe { owner.register_output(None, core::ptr::null_mut()) };
        // SAFETY: the null default is installed before this serialized dispatch.
        unsafe { owner.raw_message(source_message(b"stderr\n\0")) };
        // SAFETY: the later custom callback remains live, and there is still
        // only one registration thread.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };

        assert_eq!(capture.count(), 1);
        assert_eq!(capture.message(0), b"early\n");
        assert_eq!(DEFAULT_STDERR_CAPTURE.count(), 1);
        assert_eq!(DEFAULT_STDERR_CAPTURE.message(0), b"stderr\n");
    }

    #[test]
    fn post_init_does_not_call_the_stderr_primitive_for_an_empty_delayed_buffer() {
        let _guard = default_stderr_test_guard();
        let owner = output_owner();
        reset_default_stderr_capture();

        // SAFETY: this isolated owner has no dispatch or custom registration.
        unsafe { owner.post_init() };

        assert_eq!(DEFAULT_STDERR_CAPTURE.count(), 0);
    }

    #[test]
    fn post_init_flushes_to_stderr_then_retains_newline_delayed_phase() {
        let _guard = default_stderr_test_guard();
        let owner = output_owner();
        let capture = Capture::new();
        reset_default_stderr_capture();

        // SAFETY: this test serializes each dispatch with post-init.
        unsafe { owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: the test invokes the source post-init transition before any
        // custom registration and after all pre-init emission for this owner.
        unsafe { owner.post_init() };
        // SAFETY: post-init is complete before this dispatch.
        unsafe { owner.raw_message(source_message(b"later\n\0")) };
        // SAFETY: this is the single custom registration and the capture
        // outlives every callback.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };

        assert_eq!(capture.count(), 1);
        assert_eq!(capture.message(0), b"early\n\nlater\n");
        assert_eq!(DEFAULT_STDERR_CAPTURE.count(), 2);
        assert_eq!(DEFAULT_STDERR_CAPTURE.message(0), b"early\n");
        assert_eq!(DEFAULT_STDERR_CAPTURE.message(1), b"later\n");
    }

    struct ReentrantCapture {
        capture: Capture,
        owner: *const OutputOwner,
        reentered: AtomicBool,
    }

    // The callback has the same source-level opaque-pointer obligations as a
    // normal capture; this test creates and consumes it on one thread.
    unsafe impl Sync for ReentrantCapture {}

    impl ReentrantCapture {
        fn new(owner: &OutputOwner) -> Self {
            Self {
                capture: Capture::new(),
                owner,
                reentered: AtomicBool::new(false),
            }
        }
    }

    unsafe extern "C" fn reentrant_output(message: *const c_char, argument: *mut c_void) {
        // SAFETY: the test passes a live `ReentrantCapture` for this callback.
        let capture = unsafe { &*(argument as *const ReentrantCapture) };
        // SAFETY: `capture.capture` has the same callback contract as above.
        unsafe { capture_output(message, capture_argument(&capture.capture)) };
        if !capture.reentered.swap(true, Ordering::Relaxed) {
            // SAFETY: the owner remains live through the registration callback.
            let owner = unsafe { &*capture.owner };
            // SAFETY: source permits this custom-callback reentry after that
            // same registration has published the custom default.
            unsafe { owner.raw_message(source_message(b"reentrant\n\0")) };
        }
    }

    #[test]
    fn registration_callback_can_reenter_default_dispatch_without_relocking_buffer() {
        let owner = output_owner();
        let capture = ReentrantCapture::new(&owner);
        // SAFETY: this test serializes the first dispatch with registration.
        unsafe { owner.raw_message(source_message(b"early\n\0")) };

        // SAFETY: this is one serialized registration. The callback and opaque
        // argument remain valid until it returns; its permitted reentrant
        // emission reaches the already-installed custom default directly.
        unsafe {
            owner.register_output(
                Some(reentrant_output as OutputCallback),
                &capture as *const ReentrantCapture as *mut c_void,
            )
        };

        assert_eq!(capture.capture.count(), 2);
        assert_eq!(capture.capture.message(0), b"early\n");
        assert_eq!(capture.capture.message(1), b"reentrant\n");
    }

    fn print_trace_capture(name: &str, capture: &Capture) {
        std::print!("{name}=");
        for index in 0..capture.count() {
            if index != 0 {
                std::print!(":");
            }
            for byte in capture.message(index) {
                std::print!("{byte:02x}");
            }
        }
        std::println!();
    }

    fn print_trace_thread_identity(name: &str, identity: usize) {
        std::println!("{name}={identity:x}");
    }

    fn print_default_stderr_line(name: &str, bytes: &[u8]) {
        std::eprint!("{name}=");
        for byte in bytes {
            std::eprint!("{byte:02x}");
        }
        std::eprintln!();
    }

    /// Machine-readable Rust half for the uncollected diagnostic C/Rust
    /// producer. The producer retains this raw stream and reconstructs the
    /// comparison from it; this test itself is not native evidence.
    #[test]
    fn diagnostic_output_owner_trace_for_future_pinned_c_comparison() {
        let _guard = default_stderr_test_guard();
        reset_default_stderr_capture();
        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_TRACE_BEGIN");

        let release = DiagnosticOptionSnapshot::release_defaults();
        let mut release_owner = output_owner();
        release_owner.initialize_options(release);
        let release_capture = Capture::new();
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { release_owner.register_output(Some(capture_output), capture_argument(&release_capture)) };
        release_capture.reset();
        let release_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe { release_owner.warning(release, source_message(b"selected mbind failure\n\0")) };
        print_trace_capture("release", &release_capture);

        let enabled = DiagnosticOptionSnapshot::new(1, 0, 1);
        let mut enabled_owner = output_owner();
        enabled_owner.initialize_options(enabled);
        let enabled_capture = Capture::new();
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { enabled_owner.register_output(Some(capture_output), capture_argument(&enabled_capture)) };
        enabled_capture.reset();
        let enabled_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe { enabled_owner.warning(enabled, source_message(b"selected mbind failure\n\0")) };
        print_trace_capture("enabled", &enabled_capture);

        let cap = DiagnosticOptionSnapshot::new(1, 0, 1);
        let mut cap_owner = output_owner();
        cap_owner.initialize_options(cap);
        let cap_capture = Capture::new();
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { cap_owner.register_output(Some(capture_output), capture_argument(&cap_capture)) };
        cap_capture.reset();
        let cap_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe {
            cap_owner.warning(cap, source_message(b"first\n\0"));
            cap_owner.warning(cap, source_message(b"second\n\0"));
        }
        print_trace_capture("cap", &cap_capture);

        let verbose = DiagnosticOptionSnapshot::new(0, 1, 0);
        let mut verbose_owner = output_owner();
        verbose_owner.initialize_options(verbose);
        let verbose_capture = Capture::new();
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { verbose_owner.register_output(Some(capture_output), capture_argument(&verbose_capture)) };
        verbose_capture.reset();
        let verbose_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe {
            verbose_owner.warning(verbose, source_message(b"first\n\0"));
            verbose_owner.warning(verbose, source_message(b"second\n\0"));
        }
        print_trace_capture("verbose", &verbose_capture);

        let delayed_owner = output_owner();
        let delayed_capture = Capture::new();
        let delayed_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe { delayed_owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { delayed_owner.register_output(Some(capture_output), capture_argument(&delayed_capture)) };
        // SAFETY: registration is complete before this dispatch.
        unsafe { delayed_owner.raw_message(source_message(b"later\n\0")) };
        print_trace_capture("delayed", &delayed_capture);

        let null_owner = output_owner();
        let null_capture = Capture::new();
        let null_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe { null_owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: both registrations are serialized; the null route's
        // argument is ignored and the custom capture remains live.
        unsafe { null_owner.register_output(None, core::ptr::null_mut()) };
        // SAFETY: the null default is installed before this serialized dispatch.
        unsafe { null_owner.raw_message(source_message(b"stderr\n\0")) };
        // SAFETY: see the preceding registration.
        unsafe { null_owner.register_output(Some(capture_output), capture_argument(&null_capture)) };
        print_trace_capture("null", &null_capture);

        let post_owner = output_owner();
        let post_capture = Capture::new();
        let post_init_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with post-init.
        unsafe { post_owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: this follows source post-init before custom registration.
        unsafe { post_owner.post_init() };
        // SAFETY: post-init is complete before this dispatch.
        unsafe { post_owner.raw_message(source_message(b"later\n\0")) };
        // SAFETY: this fixture retains the callback state and has one custom
        // registration after the source post-init transition.
        unsafe { post_owner.register_output(Some(capture_output), capture_argument(&post_capture)) };
        print_trace_capture("post_init", &post_capture);

        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_TRACE_END");
        let _environment_guard = DIAGNOSTIC_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("diagnostic environment test lock is not poisoned");
        let show_stats = b"mimalloc_show_stats=-7\0";
        let verbose = b"mimalloc_verbose=-1\0";
        install_final_output_environment(show_stats, verbose);
        let mut final_owner = output_owner();
        // SAFETY: the fixed source environment remains live and locked for
        // initialization plus this complete final-output trace.
        unsafe { final_owner.initialize_source_options(diagnostic_test_environment_reader) };
        let final_capture = Capture::new();
        // SAFETY: the fixed custom route remains live and no registration
        // overlaps either source-ordered final output phase.
        unsafe { final_owner.register_output(Some(capture_output), capture_argument(&final_capture)) };
        final_capture.reset();
        // SAFETY: source selects this phase before its merge/sampling work.
        let permit = final_statistics_permit(&final_owner);
        // SAFETY: this test passes the already captured scalar image through
        // the distinct stats.c and init.c tail phases in source order.
        unsafe { permit.emit(final_process_view()) };
        assert_eq!(unsafe { final_owner.final_process_done_message(97) }, Ok(true));
        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_FINAL_STATISTICS_BEGIN");
        print_trace_capture("final_stats", &final_capture);
        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_FINAL_STATISTICS_END");
        drop(_environment_guard);
        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_THREAD_IDENTITIES_BEGIN");
        print_trace_thread_identity("release", release_thread_identity);
        print_trace_thread_identity("enabled", enabled_thread_identity);
        print_trace_thread_identity("cap", cap_thread_identity);
        print_trace_thread_identity("verbose", verbose_thread_identity);
        print_trace_thread_identity("delayed", delayed_thread_identity);
        print_trace_thread_identity("null", null_thread_identity);
        print_trace_thread_identity("post_init", post_init_thread_identity);
        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_THREAD_IDENTITIES_END");
        assert_eq!(DEFAULT_STDERR_CAPTURE.count(), 3);
        std::eprintln!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_DEFAULT_STDERR_BEGIN");
        print_default_stderr_line("release", b"");
        print_default_stderr_line("enabled", b"");
        print_default_stderr_line("cap", b"");
        print_default_stderr_line("verbose", b"");
        print_default_stderr_line("delayed", b"");
        print_default_stderr_line("null", DEFAULT_STDERR_CAPTURE.message(0));
        std::eprint!("post_init=");
        for index in 1..DEFAULT_STDERR_CAPTURE.count() {
            if index != 1 {
                std::eprint!(":");
            }
            for byte in DEFAULT_STDERR_CAPTURE.message(index) {
                std::eprint!("{byte:02x}");
            }
        }
        std::eprintln!();
        std::eprintln!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_DEFAULT_STDERR_END");
    }
}
