//! Owned Linux/x86-64 shell-word expansion and C result ownership.
//!
//! The private engine performs the POSIX expansion stages with explicit quote
//! and variable state. Pathname matching and tilde lookup use the existing
//! pattern and passwd owners. Only a selected command substitution delegates
//! its opaque body to `/bin/sh`, once, through the owned spawn transaction.
//! No child exit status or diagnostic text determines `WRDE_BADVAL`.
//!
//! Musl 1.2.6 remains the fixed compatibility oracle. This implementation is
//! an owned POSIX evaluator, not a translation of musl's whole-input shell
//! protocol; its precise source differences belong in the wordexp evidence.

use core::{ffi::{c_char, c_int}, ptr};

use super::owned_wordexp_engine::{
    evaluate_wordexp_into, ExpandedResultWord, WordexpContext, WordexpDiagnosticSink,
    WordexpError, WordexpResultSink, WordexpSyntax,
};
use super::raw_syscall;
use super::owned_wordexp_paths::NativeWordexpPaths;
use super::owned_wordexp_process::WordexpEnvironmentSnapshot;
use super::owned_wordexp_results::{
    release_wordexp_result_record, WordexpResultAllocator, WordexpResultError,
    WordexpResultMode, WordexpResultOffsets, WordexpResultTransaction,
};

pub(super) use super::owned_wordexp_results::WordexpResultRecord as Wordexp;

const WRDE_DOOFFS: c_int = 1;
const WRDE_APPEND: c_int = 2;
const WRDE_NOCMD: c_int = 4;
const WRDE_REUSE: c_int = 8;
const WRDE_SHOWERR: c_int = 16;
const WRDE_UNDEF: c_int = 32;

const WRDE_NOSPACE: c_int = 1;
const WRDE_BADCHAR: c_int = 2;
const WRDE_BADVAL: c_int = 3;
const WRDE_CMDSUB: c_int = 4;
const WRDE_SYNTAX: c_int = 5;
const PTHREAD_CANCEL_DISABLE: c_int = 1;
const EINTR: i64 = 4;

unsafe extern "C" {
    fn pthread_setcancelstate(state: c_int, old: *mut c_int) -> c_int;
}

/// Private failure injection changes only C result storage. The ordinary
/// provider always selects its production C allocation domain directly.
fn result_allocator() -> WordexpResultAllocator {
    #[cfg(crabc_owned_wordexp_result_private_test)]
    { super::owned_wordexp_result_failure::allocator() }
    #[cfg(not(crabc_owned_wordexp_result_private_test))]
    { WordexpResultAllocator::selected() }
}

fn error_status(error: WordexpError) -> c_int {
    match error {
        WordexpError::NoSpace => WRDE_NOSPACE,
        WordexpError::BadCharacter => WRDE_BADCHAR,
        WordexpError::UndefinedVariable => WRDE_BADVAL,
        WordexpError::CommandSubstitution => WRDE_CMDSUB,
        // Parameter assertions can also reject a defined but empty value.
        // Their failure, arithmetic failures, and unrepresentable NUL output
        // use the explicit generic expansion-error policy, never BADVAL.
        WordexpError::Syntax | WordexpError::ParameterError |
        WordexpError::Arithmetic | WordexpError::ArithmeticOverflow |
        WordexpError::OutputNul => WRDE_SYNTAX,
    }
}

fn record_error(error: WordexpResultError) -> WordexpError {
    match error {
        WordexpResultError::NoSpace => WordexpError::NoSpace,
        WordexpResultError::InteriorNul => WordexpError::OutputNul,
        WordexpResultError::ByteLengthMismatch |
        WordexpResultError::InvalidAppendRecord => WordexpError::Syntax,
    }
}

impl WordexpResultSink for WordexpResultTransaction {
    fn append_word(&mut self, word: ExpandedResultWord<'_>) -> Result<(), WordexpError> {
        self.append_word_bytes(word.byte_len(), word.bytes()).map_err(record_error)
    }
}

struct WordexpDiagnostics { show_errors: bool }

/// Write diagnostic bytes to the inherited standard-error descriptor. Like
/// the old child protocol, this never changes the parent's FILE orientation,
/// buffering, or error indicator. It does not publish raw write failures to
/// errno; arbitrary signal handlers can independently change errno.
///
/// These are ordinary calling-thread writes: a broken pipe follows that
/// thread's SIGPIPE disposition. No hidden signal-mask policy is introduced.
fn write_diagnostic_bytes(mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        // SAFETY: bytes is a live readable range; descriptor 2 is the standard
        // error destination. Raw syscall owns result/error translation.
        let written = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_WRITE, 2, bytes.as_ptr() as i64, bytes.len() as i64,
            )
        };
        if written == -EINTR { continue; }
        if written <= 0 || written as usize > bytes.len() { return false; }
        bytes = &bytes[written as usize..];
    }
    true
}

impl WordexpDiagnosticSink for WordexpDiagnostics {
    fn parameter_error(&mut self, name: &[u8], message: Option<ExpandedResultWord<'_>>) {
        if !self.show_errors { return; }
        if !write_diagnostic_bytes(b"wordexp: ") ||
            !write_diagnostic_bytes(name) || !write_diagnostic_bytes(b": ")
        {
            return;
        }
        match message {
            None => {
                if !write_diagnostic_bytes(b"parameter is unset or empty") { return; }
            }
            Some(message) => {
                let mut chunk = [0u8; 256];
                let mut used = 0;
                for byte in message.bytes() {
                    chunk[used] = byte;
                    used += 1;
                    if used == chunk.len() {
                        if !write_diagnostic_bytes(&chunk) { return; }
                        used = 0;
                    }
                }
                if !write_diagnostic_bytes(&chunk[..used]) { return; }
            }
        }
        let _ = write_diagnostic_bytes(b"\n");
    }
}

/// Publish a releasable fresh zero prefix when parsing runs out of storage.
/// Append keeps every original field and allocation. Fresh calls only require
/// an initialized offset field when DOOFFS is set; no other field is read.
unsafe fn early_no_space(words: *mut Wordexp, flags: c_int) -> c_int {
    if flags & WRDE_APPEND == 0 {
        unsafe {
            (*words).word_count = 0;
            (*words).words = ptr::null_mut();
            if flags & WRDE_DOOFFS == 0 { (*words).offsets = 0; }
        }
    }
    WRDE_NOSPACE
}

unsafe fn do_wordexp(input: *const c_char, words: *mut Wordexp, flags: c_int) -> c_int {
    if input.is_null() || words.is_null() { return WRDE_BADCHAR; }
    let allocator = result_allocator();
    if flags & WRDE_REUSE != 0 {
        // SAFETY: REUSE transfers the prior result's ownership to wordfree.
        unsafe { release_wordexp_result_record(words, allocator); }
    }
    // SAFETY: the C caller retains a readable terminated input for this call.
    let source = unsafe { core::ffi::CStr::from_ptr(input).to_bytes() };
    let syntax = match WordexpSyntax::parse(source) {
        Ok(syntax) => syntax,
        Err(WordexpError::NoSpace) => return unsafe { early_no_space(words, flags) },
        Err(error) => return error_status(error),
    };
    if flags & WRDE_NOCMD != 0 && syntax.has_commands() { return WRDE_CMDSUB; }

    let offsets = if flags & WRDE_DOOFFS != 0 {
        // SAFETY: DOOFFS requires this field to be initialized by the caller.
        WordexpResultOffsets::Leading(unsafe { (*words).offsets })
    } else {
        WordexpResultOffsets::None
    };
    let mode = if flags & WRDE_APPEND != 0 {
        WordexpResultMode::Append { offsets }
    } else {
        WordexpResultMode::Fresh { offsets }
    };
    let mut transaction = match unsafe { WordexpResultTransaction::begin(words, mode, allocator) } {
        Ok(transaction) => transaction,
        Err(error) => return error_status(record_error(error)),
    };
    let mut context = WordexpContext::new();
    context.set_undefined_is_error(flags & WRDE_UNDEF != 0);
    context.set_no_command_substitution(flags & WRDE_NOCMD != 0);

    // Retire process and pathname owners before publishing the result. The
    // call-local context also drops before the wrapper restores cancellation.
    let outcome = (|| {
        // SAFETY: the C environment and selected CTYPE remain stable under
        // this call's documented process-state contract.
        let environment = unsafe { WordexpEnvironmentSnapshot::capture(&mut context) }?;
        let mut commands = environment.process_adapter(flags & WRDE_SHOWERR != 0);
        let mut diagnostics = WordexpDiagnostics { show_errors: flags & WRDE_SHOWERR != 0 };
        evaluate_wordexp_into(
            &syntax, &mut context, &mut commands, &mut NativeWordexpPaths::new(),
            &mut transaction, &mut diagnostics,
        )
    })();
    let status = match outcome { Ok(()) => 0, Err(error) => error_status(error) };
    if matches!(outcome, Ok(()) | Err(WordexpError::NoSpace)) {
        // SAFETY: only success and the precise resource error publish a
        // prefix. This consumes staging without another allocation or failure.
        unsafe { transaction.commit_completed(); }
    }
    // Every other outcome drops staging and preserves an APPEND record
    // exactly, including its original vector address and original strings.
    status
}

/// Expand shell words with call-local variable, quote, and result ownership.
///
/// # Safety
/// `input` is a readable NUL-terminated C string. `words` is a writable,
/// exclusively owned `wordexp_t`, disjoint from the input. DOOFFS requires
/// initialized `we_offs`; APPEND and REUSE require a valid exclusively owned
/// previous result from this provider (including a NOSPACE prefix). The
/// environment vector and its strings remain stable while the call copies
/// them; the selected CTYPE locale remains stable throughout expansion.
/// Command substitutions execute shell language unless NOCMD rejects them.
#[no_mangle]
pub unsafe extern "C" fn wordexp(
    input: *const c_char,
    words: *mut Wordexp,
    flags: c_int,
) -> c_int {
    let mut old_state = 0;
    // Preserve the selected whole-call cancellation envelope. A pending
    // request cannot abandon a child, glob result, or staged C allocation.
    let changed = unsafe { pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut old_state) == 0 };
    let result = unsafe { do_wordexp(input, words, flags) };
    if changed { unsafe { pthread_setcancelstate(old_state, ptr::null_mut()); } }
    result
}

/// Release a successful or NOSPACE partial result, retaining caller offsets.
///
/// # Safety
/// `words` is null or an exclusively owned result returned by this provider
/// with success or NOSPACE. Its vector and strings have not been separately
/// freed, copied into another owning record, or mutated. A released record
/// can be released again; its null vector makes that operation inert.
#[no_mangle]
pub unsafe extern "C" fn wordfree(words: *mut Wordexp) {
    // SAFETY: this entry supplies the same C allocation domain as wordexp.
    unsafe { release_wordexp_result_record(words, result_allocator()); }
}
