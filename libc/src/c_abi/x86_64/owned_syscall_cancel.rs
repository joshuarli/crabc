//! Source-shaped cancellation-point syscall and SIGCANCEL protocol.
//!
//! musl 1.2.6 release 9fa28ece75d8a2191de7c5bb53bed224c5947417 (MIT):
//! src/thread/pthread_cancel.c supplies __syscall_cp_c, __cancel, handler and
//! installation; src/thread/x86_64/syscall_cp.s supplies the exact PC window.
//! The narrow adapted names are hidden in ELF, so neither the vfork-sensitive
//! runtime nor a signal handler can acquire interposable callback dependencies.
//! State comes only from the owned current-thread FS+32 cache. Ordinary FILE
//! descriptor backends keep their source non-canceling raw syscalls.

use core::{ffi::{c_int, c_void}, sync::atomic::{AtomicBool, Ordering}};
use super::{current_pthread_slot, PTHREAD_CANCEL_DISABLE, PTHREAD_CANCEL_ENABLE};
use super::super::{raw_syscall, signal_foundation};

const SIGCANCEL: c_int = 32;
const SIGNAL_BIT: u64 = 1 << 31;
const ECANCELED: i64 = 125;
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

// SPDX-License-Identifier: MIT
// Copyright (c) 2005-2020 Rich Felker, et al.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
core::arch::global_asm!(
    ".text",
    ".global __crabc_x86_syscall_cp_asm", ".hidden __crabc_x86_syscall_cp_asm",
    ".type __crabc_x86_syscall_cp_asm,@function",
    ".global __crabc_x86_cp_begin", ".hidden __crabc_x86_cp_begin",
    ".global __crabc_x86_cp_end", ".hidden __crabc_x86_cp_end",
    ".global __crabc_x86_cp_cancel", ".hidden __crabc_x86_cp_cancel",
    ".hidden __crabc_x86_cancel",
    "__crabc_x86_syscall_cp_asm:",
    "__crabc_x86_cp_begin:",
    "mov (%rdi),%eax", "test %eax,%eax", "jnz __crabc_x86_cp_cancel",
    "mov %rdi,%r11", "mov %rsi,%rax", "mov %rdx,%rdi",
    "mov %rcx,%rsi", "mov %r8,%rdx", "mov %r9,%r10",
    "mov 8(%rsp),%r8", "mov 16(%rsp),%r9", "mov %r11,8(%rsp)",
    "syscall",
    "__crabc_x86_cp_end:", "ret",
    "__crabc_x86_cp_cancel:", "jmp __crabc_x86_cancel",
    ".size __crabc_x86_syscall_cp_asm,.-__crabc_x86_syscall_cp_asm",
    options(att_syntax)
);
unsafe extern "C" {
    fn __crabc_x86_syscall_cp_asm(pending: *const c_int, number: i64,
        a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64;
    static __crabc_x86_cp_begin: u8;
    static __crabc_x86_cp_end: u8;
    static __crabc_x86_cp_cancel: u8;
}

// This function is reached by a tail jump with the syscall wrapper's original
// return address. MASKED cancellation returns ECANCELED and disables further
// delivery; enabled/asynchronous cancellation follows the existing owned
// pthread-exit cleanup and TSD transaction without unwinding Rust stack frames.
#[no_mangle]
unsafe extern "C" fn __crabc_x86_cancel() -> i64 {
    let Some(state) = current_pthread_slot() else { return -ECANCELED; };
    if state.state.load(Ordering::Acquire) == PTHREAD_CANCEL_ENABLE
        || state.asynchronous.load(Ordering::Acquire) != 0 {
        unsafe { super::pthread_create_join::exit_selected_pthread_worker(super::PTHREAD_CANCELED); }
    }
    state.state.store(PTHREAD_CANCEL_DISABLE, Ordering::Release);
    -ECANCELED
}

/// Execute a six-argument Linux syscall at the source cancellation boundary.
/// # Safety
/// The syscall's pointer/range/lifetime and Linux argument requirements hold;
/// the current task has an initialized owned TCB and holds no non-cancel-safe
/// runtime resource without its source cleanup or disabled-cancellation scope.
pub(super) unsafe fn syscall_cp(number: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    unsafe {
        let Some(state) = current_pthread_slot() else {
            return raw_syscall::syscall6(number,a,b,c,d,e,f);
        };
        let status = state.state.load(Ordering::Acquire);
        if status != PTHREAD_CANCEL_ENABLE && (status == PTHREAD_CANCEL_DISABLE || number == 3) {
            return raw_syscall::syscall6(number,a,b,c,d,e,f);
        }
        let result = __crabc_x86_syscall_cp_asm(state.pending.as_ptr(),number,a,b,c,d,e,f);
        if result == -4 && number != 3 && state.pending.load(Ordering::Acquire) != 0
            && state.state.load(Ordering::Acquire) != PTHREAD_CANCEL_DISABLE {
            return __crabc_x86_cancel();
        }
        result
    }
}

unsafe extern "C" fn cancel_handler(_signal: c_int, _information: *mut c_void, context: *mut c_void) {
    unsafe {
        let Some(state) = current_pthread_slot() else { return; };
        if state.pending.load(Ordering::Acquire) == 0
            || state.state.load(Ordering::Acquire) == PTHREAD_CANCEL_DISABLE { return; }
        // Linux/x86 ucontext_t: mcontext at 40, REG_RIP at gregs[16], and
        // uc_sigmask at 296. Only the kernel's first eight signal-mask bytes
        // are touched; no public tail/padding is read or manufactured.
        let pc = context.cast::<u8>().add(40+16*8).cast::<usize>();
        let mask = context.cast::<u8>().add(296).cast::<u64>();
        let saved_pc = pc.read_unaligned();
        let saved_mask = mask.read_unaligned() | SIGNAL_BIT;
        mask.write_unaligned(saved_mask);
        if state.asynchronous.load(Ordering::Acquire) != 0 {
            // pthread_sigmask forwards the input mask unchanged; it filters
            // reserved bits only in a requested old-mask result. SIGCANCEL
            // therefore stays blocked while asynchronous exit begins.
            raw_syscall::syscall4(14,2,(&saved_mask as *const u64) as i64,0,8);
            __crabc_x86_cancel();
        } else if saved_pc >= core::ptr::addr_of!(__crabc_x86_cp_begin) as usize
            && saved_pc < core::ptr::addr_of!(__crabc_x86_cp_end) as usize {
            pc.write_unaligned(core::ptr::addr_of!(__crabc_x86_cp_cancel) as usize);
        } else {
            // Requeue while the signal remains blocked in the restored
            // context; the pending load at the next PC window closes the
            // request-before-syscall race without lossy wake/check emulation.
            raw_syscall::syscall2(200,raw_syscall::syscall0(186),SIGCANCEL as i64);
        }
    }
}

pub(super) unsafe fn initialize() -> Result<(), c_int> {
    if HANDLER_INSTALLED.load(Ordering::Acquire) { return Ok(()); }
    // Multiple initializers may install the identical disposition, as in
    // musl. No in-progress lock can be abandoned by asynchronous cancellation.
    let action = signal_foundation::KernelSigAction {
        handler: cancel_handler as *const () as usize,
        flags: 4 | 0x1000_0000 | 0x0800_0000 | 0x0400_0000,
        restorer: signal_foundation::restorer_address(),
        mask: u64::MAX,
    };
    let result = unsafe { raw_syscall::syscall4(13,SIGCANCEL as i64,(&action as *const _) as i64,0,8) };
    if result < 0 { return Err((-result) as c_int); }
    HANDLER_INSTALLED.store(true,Ordering::Release);
    Ok(())
}

// pthread_kill.c blocks all requester signals across target kill exclusion.
// The guard owns only that calling-thread mask, never the registry/kill lock.
struct AllSignals(u64);
impl AllSignals {
    unsafe fn block() -> Result<Self, c_int> {
        let all = u64::MAX;
        let mut previous = 0;
        let result = unsafe { raw_syscall::syscall4(14,0,(&all as *const u64) as i64,(&mut previous as *mut u64) as i64,8) };
        if result < 0 { Err((-result) as c_int) } else { Ok(Self(previous)) }
    }
}
impl Drop for AllSignals {
    fn drop(&mut self) {
        unsafe { raw_syscall::syscall4(14,2,(&self.0 as *const u64) as i64,0,8); }
    }
}

pub(super) unsafe fn request(thread: *mut c_void) -> c_int {
    unsafe {
        if let Err(error) = initialize() { return error; }
        let mask = match AllSignals::block() { Ok(mask) => mask, Err(error) => return error };
        let caller_tid = raw_syscall::syscall0(186) as c_int;
        let result = super::pthread_create_join::with_selected_pthread_signal_target(thread, |tgid,tid,state| {
            // The lifecycle owner pins this mapped state and serializes the
            // live TID against exit. No callback/allocator/public libc or
            // condition-barrier access occurs under its target kill lock.
            let state = &*state;
            if state.kind.load(Ordering::Acquire) != super::SLOT_PTHREAD { return super::EINVAL; }
            state.pending.store(1,Ordering::Release);
            if tid == 0 || tid == caller_tid { return 0; }
            -raw_syscall::syscall3(234,tgid as i64,tid as i64,SIGCANCEL as i64) as c_int
        }).unwrap_or(super::EINVAL);
        if result == 0 {
            // Preserve the older private condition point's independent
            // registry/barrier lease until that owner replaces it. A target
            // may already have exited after signal delivery; a miss is benign.
            super::pthread_create_join::request_selected_pthread_cancellation(thread);
        }
        drop(mask);
        if thread as *mut u8 == super::super::pthread_identity::current_thread_pointer() {
            if let Some(state) = current_pthread_slot() {
                if state.state.load(Ordering::Acquire) == PTHREAD_CANCEL_ENABLE
                    && state.asynchronous.load(Ordering::Acquire) != 0 {
                    __crabc_x86_cancel();
                }
            }
        }
        result
    }
}
