//! Exercise failed signal delivery while an unrelated application signal becomes pending.

use core::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

macro_rules! static_archive_member { ($name:ident { $($body:tt)* }) => { $($body)* }; }

mod errno {
    std::thread_local! { static VALUE: core::cell::Cell<i32> = const { core::cell::Cell::new(0) }; }
    pub unsafe fn set_errno(value: i32) { VALUE.with(|slot| slot.set(value)); }
    pub fn get_errno() -> i32 { VALUE.with(|slot| slot.get()) }
}
fn c_status(result: i64) -> c_int {
    if result < 0 { unsafe { errno::set_errno(-result as i32) }; -1 } else { result as i32 }
}
mod process_context {
    pub fn getuid() -> u32 { unsafe { super::raw_syscall::kernel(102, [0; 6]) as u32 } }
    pub fn getpid() -> i32 { unsafe { super::raw_syscall::kernel(39, [0; 6]) as i32 } }
}
static INJECT: AtomicBool = AtomicBool::new(false);
static HANDLER_ERRNO: AtomicI32 = AtomicI32::new(0);
extern "C" fn handler(_: i32) {
    HANDLER_ERRNO.store(errno::get_errno(), Ordering::SeqCst);
    unsafe { errno::set_errno(1234) };
}
mod raw_syscall {
    pub const SYS_RT_SIGPROCMASK: i64 = 14;
    pub const SYS_KILL: i64 = 62;
    pub const SYS_GETTID: i64 = 186;
    pub const SYS_TKILL: i64 = 200;
    pub const SYS_RT_SIGQUEUEINFO: i64 = 129;
    pub const SYS_RT_SIGTIMEDWAIT: i64 = 128;
    pub unsafe fn kernel(number: i64, args: [i64; 6]) -> i64 {
        let result: i64;
        unsafe { core::arch::asm!("syscall", inlateout("rax") number => result,
            in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
            in("r10") args[3], in("r8") args[4], in("r9") args[5],
            lateout("rcx") _, lateout("r11") _, options(nostack)); }
        result
    }
    unsafe fn delivery(number: i64, args: [i64; 6]) -> i64 {
        if super::INJECT.swap(false, super::Ordering::SeqCst) {
            // The delivery boundary deterministically models an unrelated sender
            // racing a rejected request. The real kernel queues SIGUSR1 while
            // the implementation's application-signal transaction blocks it.
            let tid = unsafe { kernel(SYS_GETTID, [0; 6]) };
            assert_eq!(unsafe { kernel(SYS_TKILL, [tid, 10, 0, 0, 0, 0]) }, 0);
        }
        unsafe { kernel(number, args) }
    }
    pub unsafe fn syscall0(n: i64) -> i64 { unsafe { kernel(n, [0; 6]) } }
    pub unsafe fn syscall2(n: i64, a: i64, b: i64) -> i64 { unsafe { delivery(n, [a,b,0,0,0,0]) } }
    pub unsafe fn syscall3(n: i64, a: i64, b: i64, c: i64) -> i64 { unsafe { delivery(n, [a,b,c,0,0,0]) } }
    pub unsafe fn syscall4(n: i64, a: i64, b: i64, c: i64, d: i64) -> i64 { unsafe { kernel(n, [a,b,c,d,0,0]) } }
}
#[path = "../libc/src/c_abi/x86_64/signal_execution.rs"]
mod signal_execution;

core::arch::global_asm!(".text", ".global signal_errno_test_restorer", "signal_errno_test_restorer:", "mov rax, 15", "syscall");
unsafe extern "C" { fn signal_errno_test_restorer(); }
#[repr(C)]
#[derive(Clone, Copy)]
struct Action { handler: usize, flags: u64, restorer: usize, mask: u64 }

#[test]
fn failed_delivery_publishes_errno_before_pending_handler_runs() {
    let action = Action { handler: handler as *const () as usize, flags: 0x04000000,
        restorer: signal_errno_test_restorer as *const () as usize, mask: 0 };
    let mut old = Action { handler: 0, flags: 0, restorer: 0, mask: 0 };
    let mut old_mask = 0u64;
    let unblock = 1u64 << 9;
    unsafe {
        assert_eq!(raw_syscall::kernel(13, [10, &action as *const _ as i64, &mut old as *mut _ as i64, 8, 0, 0]), 0);
        assert_eq!(raw_syscall::kernel(14, [1, &unblock as *const _ as i64, &mut old_mask as *mut _ as i64, 8, 0, 0]), 0);
    }
    let mut observations = Vec::new();
    for (queue, signal) in [(false, 65), (true, 65), (false, 10), (true, 10)] {
        unsafe { errno::set_errno(77) };
        HANDLER_ERRNO.store(0, Ordering::SeqCst);
        INJECT.store(signal == 65, Ordering::SeqCst);
        let result = if queue {
            // A zeroed union is valid for either public sigval representation.
            signal_execution::sigqueue(process_context::getpid(), signal, unsafe { core::mem::zeroed() })
        } else { signal_execution::raise(signal) };
        observations.push((result, HANDLER_ERRNO.load(Ordering::SeqCst), errno::get_errno()));
    }
    unsafe {
        assert_eq!(raw_syscall::kernel(13, [10, &old as *const _ as i64, 0, 8, 0, 0]), 0);
        assert_eq!(raw_syscall::kernel(14, [2, &old_mask as *const _ as i64, 0, 8, 0, 0]), 0);
    }
    assert_eq!(observations, vec![(-1, 22, 1234), (-1, 22, 1234), (0, 77, 1234), (0, 77, 1234)]);
}
