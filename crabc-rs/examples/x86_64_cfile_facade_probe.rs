//! Native x86-64 `cfile` facade interpreter for the installed-product
//! differential.
//!
//! `compat/x86_64/runtime_private_facades_cfile.c` owns the scenarios. It runs
//! each one through the product's public `fmemopen` stream and through this
//! interpreter over an identical buffer, then compares the traces and final
//! bytes. This archive reaches only the private RuntimeV1 table.

#![no_std]

use core::ffi::{c_char, c_int};

use crabc_rs::cfile::{CFile, FileMode, SeekFrom};
use crabc_rs::Errno;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `ud2` raises SIGILL, ending this probe process immediately.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

// Mirrors `enum facade_op_kind` in the C driver.
const OP_WRITE: c_int = 0;
const OP_READ: c_int = 1;
const OP_FLUSH: c_int = 2;
const OP_SEEK: c_int = 3;
const OP_TELL: c_int = 4;
const OP_EOF: c_int = 5;
const OP_ERROR: c_int = 6;
const OP_RESET: c_int = 7;
const OP_CLOSE: c_int = 8;

/// Mirrors `struct facade_op` in the C driver.
#[repr(C)]
pub struct FacadeOp {
    kind: c_int,
    whence: c_int,
    value: i64,
    data: *const c_char,
}

/// Mirrors `struct facade_scenario` in the C driver.
#[repr(C)]
pub struct FacadeScenario {
    mode: c_int,
    size: usize,
    initial: *const c_char,
    initial_len: usize,
    ops: *const FacadeOp,
    op_count: usize,
}

struct Trace {
    values: *mut i64,
    capacity: usize,
    len: usize,
}

impl Trace {
    fn push(&mut self, value: i64) -> bool {
        if self.len == self.capacity {
            return false;
        }
        // SAFETY: `len < capacity` for the caller's writable trace array.
        unsafe { *self.values.add(self.len) = value };
        self.len += 1;
        true
    }

    fn result(&mut self, value: Result<i64, Errno>) -> bool {
        self.push(value.unwrap_or_else(|error| -i64::from(error.raw())))
    }
}

fn mode(value: c_int) -> Option<FileMode> {
    Some(match value {
        0 => FileMode::Read,
        1 => FileMode::Write,
        2 => FileMode::Append,
        3 => FileMode::ReadUpdate,
        4 => FileMode::WriteUpdate,
        5 => FileMode::AppendUpdate,
        _ => return None,
    })
}

/// # Safety
/// `op` is one readable scenario operation whose `data` spans `value` bytes
/// for a write.
unsafe fn apply(stream: &mut CFile<'_>, op: &FacadeOp, trace: &mut Trace) -> Option<()> {
    let recorded = match op.kind {
        OP_WRITE => {
            let length = usize::try_from(op.value).ok()?;
            // SAFETY: the scenario owns `length` readable bytes.
            let bytes = unsafe { core::slice::from_raw_parts(op.data.cast::<u8>(), length) };
            trace.result(stream.write(bytes).map(|count| count as i64))
        }
        OP_READ => {
            let mut bytes = [0u8; 64];
            let length = usize::try_from(op.value).ok().filter(|length| *length <= bytes.len())?;
            match stream.read(&mut bytes[..length]) {
                Ok(count) => {
                    trace.push(count as i64) && bytes[..count].iter().all(|byte| trace.push(i64::from(*byte)))
                }
                Err(error) => trace.push(-i64::from(error.raw())),
            }
        }
        OP_FLUSH => trace.result(stream.flush().map(|()| 0)),
        OP_SEEK => {
            // A negative absolute offset is unrepresentable in `SeekFrom`;
            // scenarios reach negative targets relative to a position.
            let origin = match op.whence {
                0 => SeekFrom::Start(u64::try_from(op.value).ok()?),
                1 => SeekFrom::Current(op.value),
                2 => SeekFrom::End(op.value),
                _ => return None,
            };
            trace.result(stream.seek(origin).map(|position| position as i64))
        }
        OP_TELL => trace.result(stream.tell().map(|position| position as i64)),
        OP_EOF => trace.result(stream.eof().map(i64::from)),
        OP_ERROR => trace.result(stream.error().map(i64::from)),
        OP_RESET => trace.result(stream.reset().map(|()| 0)),
        _ => return None,
    };
    recorded.then_some(())
}

/// Runs one scenario through `CFile` over `buffer`.
///
/// # Safety
/// `scenario` and its operations are readable, `buffer` is writable for
/// `scenario.size` bytes, and `trace` is writable for `capacity` values.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_cfile_facade_run(
    scenario: *const FacadeScenario,
    buffer: *mut u8,
    trace: *mut i64,
    capacity: usize,
    count: *mut usize,
) -> c_int {
    let scenario = unsafe { &*scenario };
    let Some(mode) = mode(scenario.mode) else { return 1 };
    let mut trace = Trace { values: trace, capacity, len: 0 };
    // SAFETY: the driver lends this buffer exclusively for the scenario.
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer, scenario.size) };
    let mut stream = match CFile::from_memory(bytes, mode) {
        Ok(stream) => Some(stream),
        Err(error) => {
            trace.push(-i64::from(error.raw()));
            None
        }
    };
    if let Some(open) = stream.as_mut() {
        // SAFETY: the driver supplies `op_count` readable operations.
        let ops = unsafe { core::slice::from_raw_parts(scenario.ops, scenario.op_count) };
        let Some((close, body)) = ops.split_last() else { return 2 };
        if close.kind != OP_CLOSE {
            return 2;
        }
        for op in body {
            if unsafe { apply(open, op, &mut trace) }.is_none() {
                return 3;
            }
        }
        if let Some(stream) = stream.take() {
            if !trace.result(stream.close().map(|()| 0)) {
                return 3;
            }
        }
    }
    unsafe { *count = trace.len };
    0
}

/// Proves the facade's typed direction checks leave libc stream state intact.
///
/// # Safety
/// `buffer` is writable for `size` bytes, with `size >= 4`.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_cfile_facade_directions(buffer: *mut u8, size: usize) -> c_int {
    if buffer.is_null() || size < 4 {
        return 1;
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer, size) };
    {
        let Ok(mut writer) = CFile::from_memory(bytes, FileMode::Write) else { return 2 };
        let mut read = [0u8; 2];
        if writer.write(b"ok") != Ok(2) || writer.read(&mut read) != Err(Errno::BADF) {
            return 3;
        }
        if writer.error() != Ok(false) || writer.tell() != Ok(2) || writer.close().is_err() {
            return 4;
        }
    }
    let Ok(mut reader) = CFile::from_memory(bytes, FileMode::Read) else { return 5 };
    let mut read = [0u8; 2];
    if reader.write(b"no") != Err(Errno::BADF) || reader.read(&mut read) != Ok(2) || read != *b"ok" {
        return 6;
    }
    if reader.error() != Ok(false) || reader.close().is_err() {
        return 7;
    }
    0
}
