//! Direct fake-boundary tests for the private, unselected wordexp process
//! adapter.
//!
//! The test root deliberately imports neither `static_c_abi.rs` nor the
//! selected `owned_wordexp.rs` C ABI provider.  It gives the process adapter
//! deterministic stand-ins for the selected environment, locale, spawn, and
//! raw-syscall leaves, then exercises its real context and command boundary.
//! This proves ownership and cleanup decisions without claiming an installed
//! process or selected-ABI qualification.

use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    ptr,
};
use std::{
    collections::VecDeque,
    sync::{Mutex, OnceLock},
};

mod test_support {
    use super::*;

    #[derive(Clone, Debug)]
    pub enum ReadStep {
        Bytes(Vec<u8>),
        End,
        Error(c_int),
        Interrupted,
    }

    #[derive(Clone, Debug)]
    pub enum WaitStep {
        Exited(c_int),
        Error(c_int),
        Interrupted,
    }

    #[derive(Clone, Debug)]
    pub enum SpawnPlan {
        Success(c_int),
        ParentFailure(c_int),
        ChildFailure(c_int),
    }

    impl Default for SpawnPlan {
        fn default() -> Self { Self::Success(31337) }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ActionRecord {
        pub command: c_int,
        pub destination: c_int,
        pub source: c_int,
    }

    pub struct State {
        pub locale_utf8: bool,
        pub pipe: [c_int; 2],
        pub reads: VecDeque<ReadStep>,
        pub waits: VecDeque<WaitStep>,
        pub spawn_plan: SpawnPlan,
        pub spawn_calls: usize,
        pub scripts: Vec<Vec<u8>>,
        pub environments: Vec<Vec<Vec<u8>>>,
        pub actions: Vec<ActionRecord>,
        pub closes: Vec<c_int>,
        pub kills: Vec<c_int>,
        pub read_calls: usize,
        pub wait_calls: usize,
    }

    impl Default for State {
        fn default() -> Self {
            Self {
                locale_utf8: false,
                pipe: [41, 42],
                reads: VecDeque::new(),
                waits: VecDeque::new(),
                spawn_plan: SpawnPlan::default(),
                spawn_calls: 0,
                scripts: Vec::new(),
                environments: Vec::new(),
                actions: Vec::new(),
                closes: Vec::new(),
                kills: Vec::new(),
                read_calls: 0,
                wait_calls: 0,
            }
        }
    }

    static STATE: OnceLock<Mutex<State>> = OnceLock::new();

    pub fn state() -> &'static Mutex<State> {
        STATE.get_or_init(|| Mutex::new(State::default()))
    }

    pub fn lock() -> std::sync::MutexGuard<'static, State> {
        state().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn reset() {
        *lock() = State::default();
    }

    pub unsafe fn copy_c_string(pointer: *const c_char) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut index = 0usize;
        loop {
            // SAFETY: every fake caller receives an adapter-owned C string.
            let byte = unsafe { ptr::read(pointer.add(index).cast::<u8>()) };
            if byte == 0 { return bytes; }
            bytes.push(byte);
            index += 1;
        }
    }

    pub unsafe fn copy_vector(vector: *const *const c_char) -> Vec<Vec<u8>> {
        let mut entries = Vec::new();
        let mut index = 0usize;
        loop {
            // SAFETY: the adapter terminates argv/envp pointer vectors.
            let entry = unsafe { ptr::read(vector.add(index)) };
            if entry.is_null() { return entries; }
            // SAFETY: each non-null vector entry is NUL terminated.
            entries.push(unsafe { copy_c_string(entry) });
            index += 1;
        }
    }
}

mod environment {
    use super::*;

    #[allow(non_upper_case_globals)] // Preserve the selected C global spelling.
    pub static mut __environ: *mut *mut c_char = ptr::null_mut();
}

mod errno {
    use core::{ffi::c_int, sync::atomic::{AtomicI32, Ordering}};

    static ERRNO: AtomicI32 = AtomicI32::new(0);

    pub(crate) unsafe fn set_errno(value: c_int) {
        ERRNO.store(value, Ordering::Relaxed);
    }

    pub(crate) unsafe fn get_errno() -> c_int {
        ERRNO.load(Ordering::Relaxed)
    }
}

mod locale_multibyte {
    pub(super) fn locale_ctype_is_utf8() -> bool {
        super::test_support::lock().locale_utf8
    }
}

mod posix_spawn_file_actions {
    use super::*;

    #[repr(C)]
    pub(super) struct PosixSpawnFileActions {
        pub(super) _pad0: [c_int; 2],
        pub(super) actions: *mut c_void,
        pub(super) _pad: [c_int; 16],
    }

    #[repr(C)]
    pub(super) struct FdOp {
        pub(super) next: *mut FdOp,
        pub(super) prev: *mut FdOp,
        pub(super) cmd: c_int,
        pub(super) fd: c_int,
        pub(super) srcfd: c_int,
        pub(super) oflag: c_int,
        pub(super) mode: c_uint,
    }
}

mod raw_syscall {
    use super::*;

    pub(super) const SYS_READ: i64 = 0;
    pub(super) const SYS_CLOSE: i64 = 3;
    pub(super) const SYS_WAIT4: i64 = 61;
    pub(super) const SYS_KILL: i64 = 62;
    pub(super) const SYS_PIPE2: i64 = 293;

    pub unsafe fn syscall1(number: i64, first: i64) -> i64 {
        assert_eq!(number, SYS_CLOSE);
        test_support::lock().closes.push(first as c_int);
        0
    }

    pub unsafe fn syscall2(number: i64, first: i64, second: i64) -> i64 {
        match number {
            SYS_PIPE2 => {
                let pipe = test_support::lock().pipe;
                // SAFETY: the adapter passes its writable two-fd array.
                unsafe {
                    ptr::write((first as *mut c_int).add(0), pipe[0]);
                    ptr::write((first as *mut c_int).add(1), pipe[1]);
                }
                let _ = second;
                0
            }
            SYS_KILL => {
                assert_eq!(second, 9);
                test_support::lock().kills.push(first as c_int);
                0
            }
            _ => panic!("unexpected two-argument syscall {number}"),
        }
    }

    pub unsafe fn syscall3(number: i64, first: i64, second: i64, third: i64) -> i64 {
        assert_eq!(number, SYS_READ);
        let _ = first;
        let step = {
            let mut state = test_support::lock();
            state.read_calls += 1;
            state.reads.pop_front().unwrap_or(test_support::ReadStep::End)
        };
        match step {
            test_support::ReadStep::Bytes(bytes) => {
                assert!(bytes.len() <= third as usize);
                // SAFETY: the adapter owns a buffer at least `third` bytes.
                unsafe {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), second as *mut u8, bytes.len());
                }
                bytes.len() as i64
            }
            test_support::ReadStep::End => 0,
            test_support::ReadStep::Error(error) => -(error as i64),
            test_support::ReadStep::Interrupted => -4,
        }
    }

    pub unsafe fn syscall4(number: i64, first: i64, second: i64, _third: i64, _fourth: i64) -> i64 {
        assert_eq!(number, SYS_WAIT4);
        let step = {
            let mut state = test_support::lock();
            state.wait_calls += 1;
            state.waits.pop_front().unwrap_or(test_support::WaitStep::Exited(0))
        };
        match step {
            test_support::WaitStep::Exited(status) => {
                // SAFETY: the adapter supplies private writable wait status.
                unsafe { ptr::write(second as *mut c_int, status); }
                first
            }
            test_support::WaitStep::Error(error) => -(error as i64),
            test_support::WaitStep::Interrupted => -4,
        }
    }
}

mod owned_spawn {
    use core::ptr;
    use super::{
        c_char, c_int, c_void, posix_spawn_file_actions::{FdOp, PosixSpawnFileActions},
        test_support,
    };

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum SpawnOutcome {
        Success,
        ParentFailure(c_int),
        ChildFailure(c_int),
    }

    pub(super) unsafe fn spawn_with_outcome(
        process: *mut c_int,
        _path: *const c_char,
        actions: *const PosixSpawnFileActions,
        _attributes: *const c_void,
        arguments: *const *const c_char,
        environment: *const *const c_char,
        _search_path: bool,
    ) -> SpawnOutcome {
        let plan = {
            let mut state = test_support::lock();
            state.spawn_calls += 1;
            // SAFETY: adapter argv/envp remain live across this call.
            state.scripts.push(unsafe { test_support::copy_c_string(*arguments.add(2)) });
            // SAFETY: adapter gives a terminated child envp vector.
            state.environments.push(unsafe { test_support::copy_vector(environment) });
            // SAFETY: the adapter supplies one initialized descriptor action.
            let action = unsafe { &*((*actions).actions.cast::<FdOp>()) };
            state.actions.push(test_support::ActionRecord {
                command: action.cmd,
                destination: action.fd,
                source: action.srcfd,
            });
            state.spawn_plan.clone()
        };
        match plan {
            test_support::SpawnPlan::Success(pid) => {
                // SAFETY: successful spawn transfers the fake positive child id.
                unsafe { ptr::write(process, pid); }
                SpawnOutcome::Success
            }
            test_support::SpawnPlan::ParentFailure(error) => SpawnOutcome::ParentFailure(error),
            test_support::SpawnPlan::ChildFailure(error) => SpawnOutcome::ChildFailure(error),
        }
    }
}

#[path = "../../libc/src/c_abi/x86_64/owned_wordexp_engine.rs"]
mod owned_wordexp_engine;
#[path = "../../libc/src/c_abi/x86_64/owned_wordexp_process.rs"]
mod owned_wordexp_process;

use owned_wordexp_engine::{
    evaluate_wordexp, ExpandedWords, ParameterPatternOperator, ParameterPatternOutput,
    PathnameMatches, PatternInput, TildeOutput, WordexpContext, WordexpError,
    WordexpLocaleMode, WordexpPathAdapter, WordexpSyntax,
};
use owned_wordexp_process::WordexpEnvironmentSnapshot;

struct PlainPaths;

impl WordexpPathAdapter for PlainPaths {
    fn expand_tilde(
        &mut self,
        _user: &[u8],
        _home: Option<&[u8]>,
        _output: &mut TildeOutput<'_>,
    ) -> Result<bool, WordexpError> {
        Ok(false)
    }

    fn expand_pattern(
        &mut self,
        _pattern: &PatternInput<'_>,
        _output: &mut PathnameMatches<'_>,
    ) -> Result<bool, WordexpError> {
        Ok(false)
    }

    fn remove_parameter_pattern(
        &mut self,
        value: &[u8],
        _pattern: &PatternInput<'_>,
        _operator: ParameterPatternOperator,
        output: &mut ParameterPatternOutput<'_>,
    ) -> Result<(), WordexpError> {
        output.append_bytes(value)
    }
}

fn capture(entries: &[&'static [u8]], locale_utf8: bool) -> (WordexpContext, WordexpEnvironmentSnapshot) {
    test_support::reset();
    test_support::lock().locale_utf8 = locale_utf8;
    let mut pointers: Vec<*mut c_char> = entries.iter()
        .map(|entry| entry.as_ptr().cast::<c_char>().cast_mut())
        .collect();
    pointers.push(ptr::null_mut());
    let mut context = WordexpContext::new();
    let snapshot = unsafe {
        // SAFETY: static input strings and this terminated pointer vector stay
        // readable through the capture call, exactly as its caller contract requires.
        ptr::write(ptr::addr_of_mut!(environment::__environ), pointers.as_mut_ptr());
        let result = WordexpEnvironmentSnapshot::capture(&mut context);
        ptr::write(ptr::addr_of_mut!(environment::__environ), ptr::null_mut());
        result
    }.unwrap();
    (context, snapshot)
}

fn evaluate(
    input: &[u8],
    context: &mut WordexpContext,
    snapshot: &WordexpEnvironmentSnapshot,
    show_errors: bool,
) -> Result<ExpandedWords, WordexpError> {
    let syntax = WordexpSyntax::parse(input)?;
    let mut commands = snapshot.process_adapter(show_errors);
    let mut paths = PlainPaths;
    evaluate_wordexp(&syntax, context, &mut commands, &mut paths)
}

fn assert_words(words: &ExpandedWords, expected: &[&[u8]]) {
    assert_eq!(words.len(), expected.len());
    for (index, expected) in expected.iter().enumerate() {
        let word = words.result_word(index).expect("result word");
        assert_eq!(word.byte_len(), expected.len());
        for (offset, byte) in expected.iter().enumerate() {
            assert_eq!(word.byte_at(offset), Some(*byte));
        }
    }
}

fn contains_entry(entries: &[Vec<u8>], expected: &[u8]) -> bool {
    entries.iter().any(|entry| entry.as_slice() == expected)
}

#[test]
fn snapshot_keeps_first_values_empty_ifs_locale_and_nonidentifier_entries() {
    let (mut context, snapshot) = capture(&[
        b"EMPTY=\0",
        b"DUP=first\0",
        b"DUP=second\0",
        b"VALUE=a:b\0",
        b"IFS=:\0",
        b"1BAD=keep\0",
        b"=empty-name\0",
        b"bare\0",
    ], true);
    assert_eq!(context.locale_mode(), WordexpLocaleMode::CUtf8);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Bytes(b"done\n".to_vec()));
        state.reads.push_back(test_support::ReadStep::End);
    }
    let words = evaluate(b"\"$EMPTY\" $DUP $VALUE $(printf done)", &mut context, &snapshot, true).unwrap();
    assert_words(&words, &[b"", b"first", b"a", b"b", b"done"]);

    let state = test_support::lock();
    assert_eq!(state.spawn_calls, 1);
    assert_eq!(state.actions, vec![test_support::ActionRecord {
        command: 2, destination: 1, source: 42,
    }]);
    assert_eq!(state.scripts, vec![b"IFS=':'\nprintf done".to_vec()]);
    let environment = &state.environments[0];
    assert_eq!(&environment[..3], [b"1BAD=keep".to_vec(), b"=empty-name".to_vec(), b"bare".to_vec()]);
    assert!(contains_entry(environment, b"EMPTY="));
    assert!(contains_entry(environment, b"DUP=first"));
    assert!(contains_entry(environment, b"VALUE=a:b"));
    assert!(contains_entry(environment, b"IFS=:"));
    assert!(!contains_entry(environment, b"DUP=second"));
}

#[test]
fn command_keeps_created_local_out_of_envp_and_refreshes_exported_values() {
    let (mut context, snapshot) = capture(&[b"EXPORTED=old\0"], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Bytes(b"a'b\n".to_vec()));
        state.reads.push_back(test_support::ReadStep::End);
    }
    let words = evaluate(
        b"${LOCAL:=a\\'b} \"$(printf '%s' \"$LOCAL\")\"",
        &mut context,
        &snapshot,
        true,
    ).unwrap();
    assert_words(&words, &[b"a'b", b"a'b"]);
    {
        let state = test_support::lock();
        assert_eq!(state.scripts, vec![b"LOCAL='a'\\''b'\nprintf '%s' \"$LOCAL\"".to_vec()]);
        assert!(!contains_entry(&state.environments[0], b"LOCAL=a'b"));
        assert!(contains_entry(&state.environments[0], b"EXPORTED=old"));
    }

    let (mut context, snapshot) = capture(&[b"EXPORTED=\0"], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Bytes(b"new\n".to_vec()));
        state.reads.push_back(test_support::ReadStep::End);
    }
    let words = evaluate(
        b"${EXPORTED:=new} \"$(printf '%s' \"$EXPORTED\")\"",
        &mut context,
        &snapshot,
        true,
    ).unwrap();
    assert_words(&words, &[b"new", b"new"]);
    let state = test_support::lock();
    assert!(contains_entry(&state.environments[0], b"EXPORTED=new"));
    assert!(!contains_entry(&state.environments[0], b"EXPORTED="));
}

#[test]
fn command_retries_eintr_ignores_exit_status_and_applies_showerr_once() {
    let (mut context, snapshot) = capture(&[], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Interrupted);
        state.reads.push_back(test_support::ReadStep::Bytes(b"okay\n\n".to_vec()));
        state.reads.push_back(test_support::ReadStep::End);
        state.waits.push_back(test_support::WaitStep::Interrupted);
        state.waits.push_back(test_support::WaitStep::Exited(1 << 8));
    }
    let words = evaluate(b"\"$(false)\"", &mut context, &snapshot, false).unwrap();
    assert_words(&words, &[b"okay"]);
    {
        let state = test_support::lock();
        assert_eq!(state.spawn_calls, 1);
        assert_eq!(state.scripts, vec![b"exec 2>/dev/null;\nfalse".to_vec()]);
        assert_eq!(state.read_calls, 3);
        assert_eq!(state.wait_calls, 2);
    }

    let (mut context, snapshot) = capture(&[], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Bytes(b"shown\n".to_vec()));
        state.reads.push_back(test_support::ReadStep::End);
    }
    let words = evaluate(b"\"$(true)\"", &mut context, &snapshot, true).unwrap();
    assert_words(&words, &[b"shown"]);
    assert_eq!(test_support::lock().scripts, vec![b"true".to_vec()]);
}

#[test]
fn command_uses_backtick_quote_context_without_reparsing_or_changing_dollarparen_bytes() {
    let (mut context, snapshot) = capture(&[], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Bytes(b"literal\n".to_vec()));
        state.reads.push_back(test_support::ReadStep::End);
    }
    let words = evaluate(b"`printf '%s' \\\"hi\\\"`", &mut context, &snapshot, true).unwrap();
    assert_words(&words, &[b"literal"]);
    assert_eq!(test_support::lock().scripts, vec![b"printf '%s' \\\"hi\\\"".to_vec()]);

    let (mut context, snapshot) = capture(&[], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Bytes(b"quoted\n".to_vec()));
        state.reads.push_back(test_support::ReadStep::End);
    }
    let words = evaluate(b"\"`printf '%s' \\\"hi\\\"`\"", &mut context, &snapshot, true).unwrap();
    assert_words(&words, &[b"quoted"]);
    assert_eq!(test_support::lock().scripts, vec![b"printf '%s' \"hi\"".to_vec()]);

    let (mut context, snapshot) = capture(&[], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Bytes(b"dollar\n".to_vec()));
        state.reads.push_back(test_support::ReadStep::End);
    }
    let words = evaluate(b"\"$(printf '%s' \\\"hi\\\")\"", &mut context, &snapshot, true).unwrap();
    assert_words(&words, &[b"dollar"]);
    assert_eq!(test_support::lock().scripts, vec![b"printf '%s' \\\"hi\\\"".to_vec()]);
}

#[test]
fn command_output_failures_close_and_kill_then_reap_the_owned_child() {
    let (mut context, snapshot) = capture(&[], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Bytes(vec![b'x', 0]));
    }
    assert!(matches!(
        evaluate(b"$(printf x)", &mut context, &snapshot, true),
        Err(WordexpError::OutputNul),
    ));
    {
        let state = test_support::lock();
        assert_eq!(state.closes, vec![42, 41]);
        assert_eq!(state.kills, vec![31337]);
        assert_eq!(state.wait_calls, 1);
    }

    let (mut context, snapshot) = capture(&[], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::Error(5));
    }
    assert!(matches!(
        evaluate(b"$(printf x)", &mut context, &snapshot, true),
        Err(WordexpError::NoSpace),
    ));
    assert_eq!(unsafe { errno::get_errno() }, 5);
    {
        let state = test_support::lock();
        assert_eq!(state.closes, vec![42, 41]);
        assert_eq!(state.kills, vec![31337]);
        assert_eq!(state.wait_calls, 1);
    }

    let (mut context, snapshot) = capture(&[], false);
    {
        let mut state = test_support::lock();
        state.reads.push_back(test_support::ReadStep::End);
        // An already-reaped child must not make the adapter signal a recycled
        // PID while reporting the wait boundary to its caller.
        state.waits.push_back(test_support::WaitStep::Error(10));
    }
    assert!(matches!(
        evaluate(b"$(printf x)", &mut context, &snapshot, true),
        Err(WordexpError::NoSpace),
    ));
    assert_eq!(unsafe { errno::get_errno() }, 10);
    let state = test_support::lock();
    assert!(state.kills.is_empty());
    assert_eq!(state.wait_calls, 1);
}

#[test]
fn spawn_failures_close_pipe_once_and_preserve_the_selected_errno_boundary() {
    let (mut context, snapshot) = capture(&[], false);
    test_support::lock().spawn_plan = test_support::SpawnPlan::ParentFailure(12);
    assert!(matches!(
        evaluate(b"\"$(true)\"", &mut context, &snapshot, true),
        Err(WordexpError::NoSpace),
    ));
    assert_eq!(unsafe { errno::get_errno() }, 12);
    {
        let state = test_support::lock();
        assert_eq!(state.closes, vec![41, 42]);
        assert!(state.kills.is_empty());
        assert_eq!(state.wait_calls, 0);
    }

    let (mut context, snapshot) = capture(&[], false);
    unsafe { errno::set_errno(77); }
    test_support::lock().spawn_plan = test_support::SpawnPlan::ChildFailure(2);
    assert!(matches!(
        evaluate(b"\"$(true)\"", &mut context, &snapshot, true),
        Err(WordexpError::Syntax),
    ));
    assert_eq!(unsafe { errno::get_errno() }, 77);
    let state = test_support::lock();
    assert_eq!(state.closes, vec![41, 42]);
    assert!(state.kills.is_empty());
    assert_eq!(state.wait_calls, 0);
}
