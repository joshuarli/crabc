//! Owned-static Linux/x86-64 `wordexp` / `wordfree`.
//!
//! This is the target-local process/stdio adapter for pinned musl 1.2.6
//! release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT),
//! `src/misc/wordexp.c::{do_wordexp,wordexp,wordfree}`. The shell argument
//! protocol, NUL-delimited sentinel/word stream, `WRDE_DOOFFS`, append/reuse,
//! error returns, and word-vector ownership follow that source directly.
//! `../../wordexp_nocmd.rs` remains the shared hardened lexical scanner from
//! the established AArch64 implementation, preserving its adversarial quote,
//! parameter, arithmetic, and command-substitution decisions without making
//! the two targets share raw process machinery.
//!
//! Musl's raw `pipe2`/signal-mask/`fork`/`execl` child sequence maps here to
//! the existing `owned_spawn` transaction: a stack-local musl-shaped `dup2`
//! record sends standard output to one CLOEXEC pipe end, while the shared
//! owner supplies signal masking, cancellation state, child-stack isolation,
//! close-on-exec error reporting, and reaping on failed exec. The parent uses
//! the existing owned `fdopen`/`getdelim`/`fclose` lifecycle to consume the
//! source's NUL-delimited stream, and the selected C allocator for words and
//! vectors. This neither creates a second process implementation nor revives
//! the legacy raw AArch64 fork/pipe path. Its private completion stage also
//! distinguishes parent setup from a child that closed the stream before the
//! sentinel, without treating an errno value as a failure classification.
//!
//! `wordexp` deliberately invokes `/bin/sh`, exactly as musl does. The
//! `WRDE_NOCMD` scanner rejects command substitutions before a child starts;
//! ordinary expansion remains a C compatibility facility rather than a
//! sandbox, shell replacement, dynamic-linking claim, or public x86 support.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("owned wordexp requires little-endian Linux/x86-64");

use core::{ffi::{c_char, c_int, c_void}, mem::size_of, ptr};

use super::{environment, errno, owned_spawn,
    posix_spawn_file_actions::{FdOp, PosixSpawnFileActions}, raw_syscall,
    stdio_standard};

const WRDE_DOOFFS: c_int = 1;
const WRDE_APPEND: c_int = 2;
const WRDE_NOCMD: c_int = 4;
const WRDE_REUSE: c_int = 8;
const WRDE_SHOWERR: c_int = 16;
const WRDE_UNDEF: c_int = 32;

const WRDE_NOSPACE: c_int = 1;
const WRDE_BADCHAR: c_int = 2;
const WRDE_CMDSUB: c_int = 4;
const WRDE_SYNTAX: c_int = 5;

const EINTR: i64 = 4;
const SIGKILL: i64 = 9;
const CLOEXEC: i64 = 0x80000;
const FDOP_DUP2: c_int = 2;
const PTHREAD_CANCEL_DISABLE: c_int = 1;

const SH: &[u8] = b"/bin/sh\0";
const SH_ARG0: &[u8] = b"sh\0";
const SH_C: &[u8] = b"-c\0";
const WORDEXP_SCRIPT: &[u8] = b"eval \"printf %s\\\\\\\\0 x $1 $2\"\0";
const WORDEXP_DEV_NULL: &[u8] = b"2>/dev/null\0";
const EMPTY: &[u8] = b"\0";
const READ_MODE: &[u8] = b"r\0";

#[repr(C)]
pub(super) struct Wordexp {
    word_count: usize,
    words: *mut *mut c_char,
    offsets: usize,
}

unsafe extern "C" {
    #[link_name = "calloc"]
    fn cabi_calloc(count: usize, size: usize) -> *mut c_void;
    #[link_name = "realloc"]
    fn cabi_realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn cabi_free(pointer: *mut c_void);
    fn pthread_setcancelstate(state: c_int, old: *mut c_int) -> c_int;
}

include!("../../wordexp_nocmd.rs");

#[inline]
unsafe fn close(descriptor: c_int) {
    // SAFETY: this private descriptor is exclusively owned by the current
    // source branch. Raw close must not overwrite a preceding source errno.
    unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, descriptor as i64); }
}

unsafe fn reap(process: c_int) {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a live private output word and this caller owns
        // the successful `owned_spawn` child until it is reaped.
        let result = unsafe {
            raw_syscall::syscall4(raw_syscall::SYS_WAIT4, process as i64,
                ptr::addr_of_mut!(status) as i64, 0, 0)
        };
        if result != -EINTR { return; }
    }
}

unsafe fn free_words(words: *mut *mut c_char, count: usize, offsets: usize) {
    if words.is_null() { return; }
    for index in 0..count {
        // SAFETY: source-owned vector slots are initialized through `count`.
        let word = unsafe { ptr::read(words.add(offsets + index)) };
        if !word.is_null() {
            // SAFETY: every non-null slot came from the selected C allocator.
            unsafe { cabi_free(word.cast()); }
        }
    }
    // SAFETY: the source owns the complete word vector allocation.
    unsafe { cabi_free(words.cast()); }
}

unsafe fn no_space(words: *mut Wordexp, flags: c_int) -> c_int {
    if flags & WRDE_APPEND == 0 {
        // SAFETY: source semantics reset a fresh caller record on early
        // pipe/spawn/FILE setup failure; append preserves prior ownership.
        unsafe {
            (*words).word_count = 0;
            (*words).words = ptr::null_mut();
        }
    }
    WRDE_NOSPACE
}

unsafe fn get_word(stream: *mut stdio_standard::StandardStream) -> *mut c_char {
    let mut word = ptr::null_mut();
    let mut capacity = 0usize;
    // SAFETY: the owned stream is live and the two private result words are
    // valid getdelim outputs. The delimiter is the source's NUL byte.
    if unsafe { stdio_standard::getdelim(&mut word, &mut capacity, 0, stream) } < 0 {
        // getdelim may have obtained private storage before a later read or
        // growth failure. The source's helper loses that temporary pointer;
        // retire it here before reporting the same null/error result so an
        // unpublishable word cannot escape the owned allocation lifecycle.
        if !word.is_null() { unsafe { cabi_free(word.cast()); } }
        ptr::null_mut()
    } else {
        word
    }
}

unsafe fn do_wordexp(input: *const c_char, words: *mut Wordexp, flags: c_int) -> c_int {
    if input.is_null() || words.is_null() { return WRDE_BADCHAR; }

    if flags & WRDE_REUSE != 0 {
        // SAFETY: REUSE requires one prior wordexp record just as musl does.
        unsafe { wordfree(words.cast()); }
    }
    if flags & WRDE_NOCMD != 0 {
        // SAFETY: the C API supplies a readable NUL-terminated input string.
        let result = unsafe { wordexp_nocmd_check(input) };
        if result != 0 { return result; }
    }
    // Pinned musl's wordexp source accepts this standardized flag but does
    // not enable `set -u`; retaining the read documents that exact behavior.
    let _ = flags & WRDE_UNDEF;

    let mut count = 0usize;
    let mut vector: *mut *mut c_char = ptr::null_mut();
    if flags & WRDE_APPEND != 0 {
        // SAFETY: APPEND retains the source's valid prior caller record.
        unsafe {
            count = (*words).word_count;
            vector = (*words).words;
        }
    }

    let mut index = count;
    let offsets;
    if flags & WRDE_DOOFFS != 0 {
        // This is musl's `SIZE_MAX/sizeof(void *)/4` guard before adding the
        // offset. It leaves room for the source's later vector growth.
        offsets = unsafe { (*words).offsets };
        if offsets > usize::MAX / size_of::<*mut c_char>() / 4 {
            return unsafe { no_space(words, flags) };
        }
        let Some(with_offsets) = index.checked_add(offsets) else {
            return unsafe { no_space(words, flags) };
        };
        index = with_offsets;
    } else {
        // SAFETY: source clears only the public offset field for this mode.
        unsafe { (*words).offsets = 0; }
        offsets = 0;
    }

    let mut pipes = [-1_i32; 2];
    // SAFETY: `pipes` is writable private two-int storage.
    let pipe_result = unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_PIPE2, pipes.as_mut_ptr() as i64, CLOEXEC)
    };
    if pipe_result < 0 {
        // Unlike musl's C pipe2 wrapper, this raw boundary must publish errno.
        unsafe { errno::set_errno((-pipe_result) as c_int); }
        return unsafe { no_space(words, flags) };
    }

    let mut action = FdOp {
        next: ptr::null_mut(), prev: ptr::null_mut(), cmd: FDOP_DUP2, fd: 1,
        srcfd: pipes[1], oflag: 0, mode: 0,
    };
    let actions = PosixSpawnFileActions {
        _pad0: [0; 2], actions: ptr::addr_of_mut!(action).cast(), _pad: [0; 16],
    };
    let redirect = if flags & WRDE_SHOWERR != 0 { EMPTY } else { WORDEXP_DEV_NULL };
    let arguments = [
        SH_ARG0.as_ptr().cast::<c_char>(), SH_C.as_ptr().cast::<c_char>(),
        WORDEXP_SCRIPT.as_ptr().cast::<c_char>(), SH_ARG0.as_ptr().cast::<c_char>(),
        input, redirect.as_ptr().cast::<c_char>(), ptr::null(),
    ];
    // Take musl's one machine-word environment snapshot without creating a
    // shared reference to the mutable public object.
    let environment = unsafe { ptr::read(ptr::addr_of!(environment::__environ)) };
    let mut process = 0;
    // SAFETY: the action/argv/environment storage remains live until spawn
    // returns; `owned_spawn` transfers only a successful child PID to us.
    let spawned = unsafe {
        owned_spawn::spawn_with_outcome(&mut process, SH.as_ptr().cast(), &actions,
            ptr::null(), arguments.as_ptr(), environment.cast_const().cast(), false)
    };
    match spawned {
        owned_spawn::SpawnOutcome::Success => {}
        owned_spawn::SpawnOutcome::ParentFailure(spawn_error) => {
            unsafe {
                close(pipes[0]);
                close(pipes[1]);
                errno::set_errno(spawn_error);
            }
            return unsafe { no_space(words, flags) };
        }
        owned_spawn::SpawnOutcome::ChildFailure(_) => {
            // Musl's raw child exits after an exec/dup2-side failure. The
            // parent then observes its otherwise valid result pipe without a
            // NUL sentinel and returns WRDE_SYNTAX. `owned_spawn` has already
            // reaped this child-reporting branch; retire only our two pipe
            // ends and preserve the source-visible missing-sentinel result.
            unsafe {
                close(pipes[0]);
                close(pipes[1]);
            }
            return WRDE_SYNTAX;
        }
    }
    // `owned_spawn` has executed /bin/sh. Its original CLOEXEC write end will
    // close at exec; the parent retains only the read end through fdopen.
    unsafe { close(pipes[1]); }

    let stream = unsafe { stdio_standard::fdopen(pipes[0], READ_MODE.as_ptr().cast()) };
    if stream.is_null() {
        unsafe {
            close(pipes[0]);
            raw_syscall::syscall2(raw_syscall::SYS_KILL, process as i64, SIGKILL);
            reap(process);
        }
        return unsafe { no_space(words, flags) };
    }

    let mut capacity = if vector.is_null() { 0 } else { index.saturating_add(1) };
    // The source frees its sentinel and diagnoses EOF before it as syntax.
    unsafe { cabi_free(get_word(stream).cast()); }
    if unsafe { stdio_standard::feof(stream) } != 0 {
        unsafe {
            stdio_standard::fclose(stream);
            reap(process);
        }
        return WRDE_SYNTAX;
    }

    let mut error = 0;
    loop {
        let word = unsafe { get_word(stream) };
        if word.is_null() { break; }
        if index.checked_add(1).is_none() {
            // Keep ownership in the local source vector so the returned
            // result remains releasable by wordfree, as in musl's error path.
            unsafe { cabi_free(word.cast()); }
            error = WRDE_NOSPACE;
            break;
        }
        if index + 1 >= capacity {
            let Some(growth) = capacity.checked_add(capacity / 2 + 10) else {
                unsafe { cabi_free(word.cast()); }
                error = WRDE_NOSPACE;
                break;
            };
            let Some(bytes) = growth.checked_mul(size_of::<*mut c_char>()) else {
                unsafe { cabi_free(word.cast()); }
                error = WRDE_NOSPACE;
                break;
            };
            let grown = unsafe { cabi_realloc(vector.cast(), bytes).cast::<*mut c_char>() };
            if grown.is_null() {
                unsafe { cabi_free(word.cast()); }
                error = WRDE_NOSPACE;
                break;
            }
            vector = grown;
            capacity = growth;
        }
        // SAFETY: capacity reserves `index` and its following terminator.
        unsafe {
            ptr::write(vector.add(index), word);
            index += 1;
            ptr::write(vector.add(index), ptr::null_mut());
        }
    }
    if unsafe { stdio_standard::feof(stream) } == 0 { error = WRDE_NOSPACE; }
    unsafe {
        stdio_standard::fclose(stream);
        reap(process);
    }

    if vector.is_null() {
        let Some(words_count) = index.checked_add(1) else {
            return unsafe { no_space(words, flags) };
        };
        // SAFETY: source uses a zeroed null terminator vector for zero words.
        vector = unsafe { cabi_calloc(words_count, size_of::<*mut c_char>()).cast() };
    }
    // SAFETY: complete source result ownership transfers only here, after the
    // child and FILE have been retired. A null allocation remains musl's
    // observable `we_wordv == NULL` result on this late allocation path.
    unsafe {
        (*words).words = vector;
        (*words).word_count = index;
        if flags & WRDE_DOOFFS != 0 {
            if !vector.is_null() {
                for offset in (1..=offsets).rev() {
                    ptr::write(vector.add(offset - 1), ptr::null_mut());
                }
            }
            (*words).word_count -= offsets;
        }
    }
    error
}

/// Expand shell-style words through pinned musl's `/bin/sh` protocol.
///
/// # Safety
/// `input` is a readable NUL-terminated C string. `words` is a writable
/// `wordexp_t`; APPEND and REUSE additionally require a valid result record
/// from an earlier successful call, exclusively owned by this caller. The
/// process environment remains readable and stable until the spawned shell
/// has executed. As in C and musl, ordinary expansion is not safe for
/// untrusted shell language; callers needing no command substitutions use
/// `WRDE_NOCMD` and still retain shell-word grammar obligations.
#[no_mangle]
pub unsafe extern "C" fn wordexp(
    input: *const c_char,
    words: *mut Wordexp,
    flags: c_int,
) -> c_int {
    let mut old_state = 0;
    // Musl disables deferred cancellation around the complete protocol so a
    // caller cannot abandon a live child or half-owned word vector.
    let changed = unsafe { pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut old_state) == 0 };
    let result = unsafe { do_wordexp(input, words, flags) };
    if changed {
        unsafe { pthread_setcancelstate(old_state, ptr::null_mut()); }
    }
    result
}

/// Release a successful wordexp result, including caller-requested offsets.
///
/// # Safety
/// `words` is null or an exclusively owned result record previously returned
/// by `wordexp`; it must not have been copied, mutated, or freed separately.
#[no_mangle]
pub unsafe extern "C" fn wordfree(words: *mut Wordexp) {
    if words.is_null() || unsafe { (*words).words.is_null() } { return; }
    unsafe {
        free_words((*words).words, (*words).word_count, (*words).offsets);
        (*words).words = ptr::null_mut();
        (*words).word_count = 0;
    }
}
