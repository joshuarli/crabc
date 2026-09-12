//! Private pathname and conventional-passwd adapter for owned x86 wordexp.
//!
//! The expansion core owns quote removal and evaluation. This adapter copies
//! its pattern bytes together with their protection map into `owned_pattern`,
//! which owns matching, traversal, ordering, and glob-result destruction.
//! Parameter removal uses that same matcher at CTYPE character boundaries.
//! Tilde lookup copies a reentrant local passwd result before releasing its
//! scratch storage. No borrowed glob or passwd pointer escapes this adapter.
//!
//! The enclosing wordexp call disables cancellation while it owns C-allocated
//! state and keeps LC_CTYPE stable, as required by the selected C matcher.

use core::{ffi::c_void, mem::MaybeUninit, ptr};

use super::{locale_multibyte, owned_passwd, owned_pattern, process_context};
use super::owned_wordexp_engine::{
    ParameterPatternOperator, ParameterPatternOutput, PathnameMatches,
    PatternInput, TildeOutput, WordexpError, WordexpPathAdapter,
};

const ENOMEM: i32 = 12;
const ERANGE: i32 = 34;

unsafe extern "C" {
    #[link_name = "malloc"]
    fn wordexp_paths_malloc(size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn wordexp_paths_free(pointer: *mut c_void);
}

/// A C allocation whose initialized extent is controlled by its private owner.
struct PathStorage {
    pointer: *mut u8,
    capacity: usize,
}

impl PathStorage {
    fn allocate(capacity: usize) -> Result<Self, WordexpError> {
        if capacity == 0 || capacity > isize::MAX as usize {
            return Err(WordexpError::NoSpace);
        }
        // SAFETY: a nonzero bounded allocation; the owner releases it once.
        let pointer = unsafe { wordexp_paths_malloc(capacity).cast::<u8>() };
        if pointer.is_null() { return Err(WordexpError::NoSpace); }
        Ok(Self { pointer, capacity })
    }

    fn nul_terminated(bytes: &[u8]) -> Result<Self, WordexpError> {
        if bytes.contains(&0) { return Err(WordexpError::OutputNul); }
        let capacity = bytes.len().checked_add(1).ok_or(WordexpError::NoSpace)?;
        let storage = Self::allocate(capacity)?;
        // SAFETY: the allocation has a slot for each byte and its terminator.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), storage.pointer, bytes.len());
            storage.pointer.add(bytes.len()).write(0);
        }
        Ok(storage)
    }
}

impl Drop for PathStorage {
    fn drop(&mut self) {
        // SAFETY: this owner uniquely retains the original C allocation.
        unsafe { wordexp_paths_free(self.pointer.cast()); }
    }
}

/// One allocation stores the NUL-terminated pattern and a byte-aligned mask.
/// Quoting is data, not a backslash serialization that could change brackets.
struct OwnedShellPattern {
    storage: PathStorage,
    width: usize,
    mask_offset: usize,
}

impl OwnedShellPattern {
    fn copy(input: &PatternInput<'_>) -> Result<Self, WordexpError> {
        let mask_offset = input.len().checked_add(1).ok_or(WordexpError::NoSpace)?;
        let capacity = mask_offset.checked_mul(2).ok_or(WordexpError::NoSpace)?;
        let storage = PathStorage::allocate(capacity)?;
        let mut used = 0usize;
        for index in 0..input.len() {
            let atom = input.atom(index).ok_or(WordexpError::Syntax)?;
            if atom.is_empty_marker() { continue; }
            if atom.byte() == 0 { return Err(WordexpError::OutputNul); }
            // SAFETY: used never exceeds input.len(); both regions are disjoint.
            unsafe {
                storage.pointer.add(used).write(atom.byte());
                storage.pointer.add(mask_offset + used).write(
                    u8::from(!atom.is_pattern_eligible()),
                );
            }
            used += 1;
        }
        // SAFETY: each allocated region includes this terminal cell.
        unsafe {
            storage.pointer.add(used).write(0);
            storage.pointer.add(mask_offset + used).write(0);
        }
        Ok(Self { storage, width: used + 1, mask_offset })
    }

    fn view(&self) -> Result<owned_pattern::ShellPattern<'_>, WordexpError> {
        // SAFETY: copy initialized these exact regions including both terminators.
        let (bytes, protection) = unsafe {
            (
                core::slice::from_raw_parts(self.storage.pointer, self.width),
                core::slice::from_raw_parts(
                    self.storage.pointer.add(self.mask_offset), self.width,
                ),
            )
        };
        owned_pattern::ShellPattern::new(bytes, protection)
            .map_err(|_| WordexpError::Syntax)
    }
}

pub(super) struct NativeWordexpPaths;

impl NativeWordexpPaths {
    pub(super) const fn new() -> Self { Self }
}

/// Use the same CTYPE decoder as the matcher. An invalid input byte still
/// advances by one, so every candidate boundary is visited exactly once.
fn next_character(bytes: &[u8], index: usize) -> usize {
    let mut character = 0;
    // SAFETY: index points within bytes; the decoder receives its exact tail.
    let decoded = unsafe {
        locale_multibyte::mbtowc(
            &mut character, bytes.as_ptr().add(index).cast(), bytes.len() - index,
        )
    };
    index + if decoded > 0 { decoded as usize } else { 1 }
}

impl WordexpPathAdapter for NativeWordexpPaths {
    fn expand_tilde(
        &mut self,
        user: &[u8],
        home: Option<&[u8]>,
        output: &mut TildeOutput<'_>,
    ) -> Result<bool, WordexpError> {
        if user.is_empty() {
            if let Some(home) = home {
                output.append_home(home)?;
                return Ok(true);
            }
        }
        let name = if user.is_empty() { None } else {
            Some(PathStorage::nul_terminated(user)?)
        };
        let mut capacity = 1024usize;
        loop {
            let storage = PathStorage::allocate(capacity)?;
            let mut record = MaybeUninit::<owned_passwd::Passwd>::uninit();
            let mut result = ptr::null_mut();
            // SAFETY: the writable objects are live and disjoint; name owns
            // a terminated, immutable string. Only a successful result is read.
            let status = unsafe {
                if let Some(name) = &name {
                    owned_passwd::getpwnam_r(
                        name.pointer.cast(), record.as_mut_ptr(),
                        storage.pointer.cast(), storage.capacity, &mut result,
                    )
                } else {
                    owned_passwd::getpwuid_r(
                        process_context::getuid(), record.as_mut_ptr(),
                        storage.pointer.cast(), storage.capacity, &mut result,
                    )
                }
            };
            if status == ERANGE {
                capacity = capacity.checked_mul(2).ok_or(WordexpError::NoSpace)?;
                continue;
            }
            if status == ENOMEM { return Err(WordexpError::NoSpace); }
            if status != 0 || result.is_null() { return Ok(false); }
            // SAFETY: a successful reentrant lookup supplies a terminated
            // directory inside storage. append_home copies it before storage drops.
            let directory = unsafe {
                core::ffi::CStr::from_ptr((*result).directory).to_bytes()
            };
            output.append_home(directory)?;
            return Ok(true);
        }
    }

    fn expand_pattern(
        &mut self,
        input: &PatternInput<'_>,
        output: &mut PathnameMatches<'_>,
    ) -> Result<bool, WordexpError> {
        let pattern = OwnedShellPattern::copy(input)?;
        let result = owned_pattern::shell_glob(pattern.view()?);
        match result {
            Ok(owned_pattern::ShellGlobOutcome::NoActivePattern |
                owned_pattern::ShellGlobOutcome::NoMatch) => Ok(false),
            Ok(owned_pattern::ShellGlobOutcome::Matches(matches)) => {
                for index in 0..matches.len() {
                    let path = matches.path(index).ok_or(WordexpError::Syntax)?;
                    output.append_path(path.as_bytes())?;
                }
                Ok(true)
            }
            // The C wordexp status set has no filesystem-I/O result. Preserve
            // its setup/resource failure category; do not report shell syntax
            // or undefined variables for a failed pathname operation.
            Err(owned_pattern::ShellGlobError::NoSpace |
                owned_pattern::ShellGlobError::Aborted) => Err(WordexpError::NoSpace),
        }
    }

    fn remove_parameter_pattern(
        &mut self,
        value: &[u8],
        input: &PatternInput<'_>,
        operator: ParameterPatternOperator,
        output: &mut ParameterPatternOutput<'_>,
    ) -> Result<(), WordexpError> {
        let pattern = OwnedShellPattern::copy(input)?;
        let pattern = pattern.view()?;
        let prefix = matches!(operator,
            ParameterPatternOperator::RemovePrefix |
            ParameterPatternOperator::RemoveLongestPrefix);
        let first = matches!(operator,
            ParameterPatternOperator::RemovePrefix |
            ParameterPatternOperator::RemoveLongestSuffix);
        let mut selected = None;
        let mut boundary = 0usize;
        loop {
            let candidate = if prefix { &value[..boundary] } else { &value[boundary..] };
            if owned_pattern::shell_matches(pattern, candidate) {
                selected = Some(boundary);
                if first { break; }
            }
            if boundary == value.len() { break; }
            boundary = next_character(value, boundary);
        }
        let removed = match selected {
            Some(boundary) if prefix => &value[boundary..],
            Some(boundary) => &value[..boundary],
            None => value,
        };
        output.append_bytes(removed)
    }
}

// This cfg is supplied only by the focused native fixture build. The normal
// runtime archive does not expose the probe, add a public header, or select
// this adapter. A C consumer tests the real runtime owners without linking
// Rust std against the runtime's identically named C exports.
#[cfg(crabc_owned_wordexp_paths_private_test)]
mod private_probe {
    use core::ffi::{c_char, c_int};
    use super::*;
    use super::super::owned_wordexp_engine::{
        CommandOutput, CommandStyle, WordexpCommandAdapter, WordexpContext,
        WordexpLocaleMode, WordexpSyntax, evaluate_wordexp,
    };

    struct NoCommands;

    impl WordexpCommandAdapter for NoCommands {
        fn execute(
            &mut self,
            _body: &[u8],
            _style: CommandStyle,
            _assignment_prefix: &[u8],
            _exported_entries: &[u8],
            _output: &mut CommandOutput<'_>,
        ) -> Result<(), WordexpError> {
            Err(WordexpError::CommandSubstitution)
        }
    }

    unsafe extern "C" {
        fn pthread_setcancelstate(state: c_int, old: *mut c_int) -> c_int;
    }

    /// Compare a pathname-only expression with a NUL-delimited expected list.
    ///
    /// # Safety
    /// `source` and each of `variable_count` names are readable C strings;
    /// each corresponding value is null (unset) or a readable C string. Both
    /// pointer arrays are readable for that count. `expected` is readable for
    /// `expected_length` bytes, which contain `expected_count` terminated
    /// words. All inputs and the process locale stay stable through the call.
    #[no_mangle]
    pub unsafe extern "C" fn __crabc_test_wordexp_paths(
        source: *const c_char,
        names: *const *const c_char,
        values: *const *const c_char,
        variable_count: usize,
        expected: *const u8,
        expected_length: usize,
        expected_count: usize,
    ) -> c_int {
        let mut old = 0;
        if unsafe { pthread_setcancelstate(1, &mut old) } != 0 { return 90; }
        let result = unsafe {
            compare(source, names, values, variable_count,
                expected, expected_length, expected_count)
        };
        unsafe { pthread_setcancelstate(old, ptr::null_mut()); }
        result
    }

    unsafe fn compare(
        source: *const c_char,
        names: *const *const c_char,
        values: *const *const c_char,
        variable_count: usize,
        expected: *const u8,
        expected_length: usize,
        expected_count: usize,
    ) -> c_int {
        let mut context = WordexpContext::new();
        context.set_locale_mode(if super::locale_multibyte::locale_ctype_is_utf8() {
            WordexpLocaleMode::CUtf8
        } else { WordexpLocaleMode::C });
        for index in 0..variable_count {
            // SAFETY: the fixture supplies these readable pointer arrays and strings.
            let name = unsafe { core::ffi::CStr::from_ptr(names.add(index).read()).to_bytes() };
            let value = unsafe { values.add(index).read() };
            let value = if value.is_null() { None } else {
                Some(unsafe { core::ffi::CStr::from_ptr(value).to_bytes() })
            };
            if context.set_initial(name, value, false).is_err() { return 91; }
        }
        let source = unsafe { core::ffi::CStr::from_ptr(source).to_bytes() };
        let Ok(syntax) = WordexpSyntax::parse(source) else { return 92; };
        let result = evaluate_wordexp(
            &syntax, &mut context, &mut NoCommands, &mut NativeWordexpPaths::new(),
        );
        let Ok(result) = result else { return 93; };
        if result.len() != expected_count { return 94; }
        let expected = if expected_length == 0 { &[] } else {
            // SAFETY: the fixture provides exactly this immutable byte extent.
            unsafe { core::slice::from_raw_parts(expected, expected_length) }
        };
        let mut cursor = 0usize;
        for index in 0..result.len() {
            let Some(word) = result.result_word(index) else { return 95; };
            for byte in 0..word.byte_len() {
                if word.byte_at(byte) != expected.get(cursor).copied() { return 96; }
                cursor += 1;
            }
            if expected.get(cursor) != Some(&0) { return 97; }
            cursor += 1;
        }
        if cursor != expected_length { return 98; }
        0
    }
}
