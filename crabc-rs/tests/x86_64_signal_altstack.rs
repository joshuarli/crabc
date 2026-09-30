#![cfg(target_arch = "x86_64")]

use core::arch::global_asm;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use crabc_rs::{signal, Errno};

static STACK_BASE: AtomicUsize = AtomicUsize::new(0);
static STACK_END: AtomicUsize = AtomicUsize::new(0);
static OBSERVED: AtomicUsize = AtomicUsize::new(0);
static VALUE: AtomicUsize = AtomicUsize::new(0);

global_asm!(
    ".global signal_altstack_test_restorer",
    ".type signal_altstack_test_restorer,@function",
    "signal_altstack_test_restorer:",
    "mov rax, 15",
    "syscall",
);

unsafe extern "C" {
    fn __errno_location() -> *mut i32;
    fn signal_altstack_test_restorer();
}

#[repr(align(16))]
struct StackMemory([u8; 65536]);

unsafe extern "C" fn info_handler(
    received: signal::Signal, info: *mut signal::SigInfo, context: *mut c_void,
) {
    let local = 0_u8;
    let address = core::ptr::addr_of!(local) as usize;
    let mut observations = usize::from(received == signal::Signal::USR1);
    if address >= STACK_BASE.load(Ordering::Relaxed)
        && address < STACK_END.load(Ordering::Relaxed)
    {
        observations |= 2;
    }
    // SAFETY: Linux supplies a live, initialized siginfo record during this
    // three-argument handler invocation; this copy never escapes the handler.
    let info = unsafe { info.read() };
    if info.signal() == Some(received) && info.raw_code() == -1 {
        observations |= 4;
    }
    VALUE.store(info.queued_i32() as usize, Ordering::Relaxed);
    if !context.is_null() {
        observations |= 8;
    }
    if let Ok(mask) = signal::current_mask() {
        if mask.contains(received) && mask.contains(signal::Signal::USR2) {
            observations |= 16;
        }
    }
    // SAFETY: Querying owns no stack memory. Disabling an active alternate
    // stack must fail; the allocated stack remains installed and live.
    unsafe {
        if let Ok(stack) = signal::sigaltstack(None) {
            if stack.flags().contains(signal::StackFlags::ONSTACK) {
                observations |= 32;
            }
        }
        if matches!(signal::sigaltstack(Some(&signal::Stack::disabled())), Err(Errno::PERM)) {
            observations |= 64;
        }
    }
    OBSERVED.store(observations, Ordering::Relaxed);
}

unsafe extern "C" fn simple_handler(received: signal::Signal) {
    let local = 0_u8;
    let address = core::ptr::addr_of!(local) as usize;
    let on_stack = address >= STACK_BASE.load(Ordering::Relaxed)
        && address < STACK_END.load(Ordering::Relaxed);
    OBSERVED.store(usize::from(received == signal::Signal::USR1 && on_stack), Ordering::Relaxed);
}

fn raw_action() -> crabc_core::signal::KernelSigAction {
    let mut action = core::mem::MaybeUninit::uninit();
    // SAFETY: The output is writable compact x86-64 kernel action storage.
    unsafe {
        crabc_core::signal::rt_sigaction_raw(signal::Signal::USR1.as_raw(), core::ptr::null(), action.as_mut_ptr()).unwrap();
        action.assume_init()
    }
}

#[test]
fn x86_64_signal_altstack_action_suspend_composition() {
    let mut blocked = signal::SignalSet::EMPTY;
    blocked.insert(signal::Signal::USR1);
    blocked.insert(signal::Signal::USR2);
    let original_mask = signal::block(&blocked).unwrap();
    if std::env::var_os("CRABC_SIGNAL_ALTSTACK_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "x86_64_signal_altstack_action_suspend_composition", "--test-threads=1"])
            .env("CRABC_SIGNAL_ALTSTACK_CHILD", "1").output().unwrap();
        signal::set_mask(&original_mask).unwrap();
        assert!(output.status.success(), "isolated alt-stack child: {:?}\n{}\n{}",
            output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        return;
    }

    let caller_mask = signal::current_mask().unwrap();
    let mut memory = Box::new(StackMemory([0; 65536]));
    let base = memory.0.as_mut_ptr();
    let stack = signal::Stack::new(base, memory.0.len());
    STACK_BASE.store(base as usize, Ordering::Relaxed);
    STACK_END.store(base as usize + memory.0.len(), Ordering::Relaxed);
    // SAFETY: The child exclusively owns aligned stack memory until the old
    // stack is restored after all handlers have returned. All handlers use
    // only direct kernel calls and lock-free atomics and never unwind.
    unsafe {
        let original_stack = signal::sigaltstack(None).unwrap();
        let tiny = signal::Stack::new(base, 1);
        *__errno_location() = 1234;
        assert_eq!(signal::sigaltstack(Some(&tiny)).unwrap_err(), Errno::NOMEM);
        assert_eq!(*__errno_location(), 1234);
        let unchanged = signal::sigaltstack(None).unwrap();
        assert_eq!(unchanged.as_mut_ptr(), original_stack.as_mut_ptr());
        assert_eq!(unchanged.size(), original_stack.size());
        assert_eq!(unchanged.flags(), original_stack.flags());
        signal::sigaltstack(Some(&stack)).unwrap();
        let enabled = signal::sigaltstack(None).unwrap();
        assert_eq!(enabled.as_mut_ptr(), base);
        assert_eq!(enabled.size(), memory.0.len());
        assert!(enabled.flags().is_empty());

        let mut handler_mask = signal::SignalSet::EMPTY;
        handler_mask.insert(signal::Signal::USR2);
        let action = signal::SigAction::with_mask(signal::SigHandler::SigInfo(info_handler),
            handler_mask, signal::SigActionFlags::ONSTACK);
        assert!(action.flags().contains(signal::SigActionFlags::SIGINFO));
        assert_eq!(action.mask(), handler_mask);
        let original_action = signal::sigaction(signal::Signal::USR1, Some(&action)).unwrap();
        let queried = signal::sigaction(signal::Signal::USR1, None).unwrap();
        assert!(matches!(queried.handler(), Some(signal::SigHandler::SigInfo(_))));
        assert_eq!(queried.mask(), handler_mask);

        // A queried action must retain the restorer and reserved mask bits
        // verbatim. The reserved bits only apply during this test's handler;
        // it performs no runtime work which could use the reserved signals.
        let mut imported = raw_action();
        imported.mask |= (1_u64 << 31) | (1_u64 << 32) | (1_u64 << 33);
        imported.restorer = signal_altstack_test_restorer as *const () as usize;
        crabc_core::signal::rt_sigaction_raw(signal::Signal::USR1.as_raw(), &imported, core::ptr::null_mut()).unwrap();
        let imported = raw_action();
        let saved = signal::sigaction(signal::Signal::USR1, None).unwrap();
        assert_eq!(saved.mask(), handler_mask);
        signal::sigaction(signal::Signal::USR1, Some(&saved)).unwrap();
        let restored = raw_action();
        assert_eq!((restored.handler, restored.flags, restored.restorer, restored.mask),
            (imported.handler, imported.flags, imported.restorer, imported.mask));

        let mut suspended_mask = caller_mask;
        suspended_mask.remove(signal::Signal::USR1);
        signal::queue_process(signal::Pid::from_raw(crabc_core::process::getpid()).unwrap(), signal::Signal::USR1, 7654321).unwrap();
        assert!(signal::pending().unwrap().contains(signal::Signal::USR1));
        *__errno_location() = 1234;
        assert_eq!(signal::suspend(&suspended_mask), Err(Errno::INTR));
        assert_eq!(*__errno_location(), 1234);
        assert_eq!(OBSERVED.load(Ordering::Relaxed), 127);
        assert_eq!(VALUE.load(Ordering::Relaxed), 7654321);
        assert_eq!(signal::current_mask().unwrap(), caller_mask);
        assert!(!signal::pending().unwrap().contains(signal::Signal::USR1));
        assert!(signal::sigaltstack(None).unwrap().flags().is_empty());

        let simple = signal::SigAction::with_mask(signal::SigHandler::Simple(simple_handler),
            handler_mask, signal::SigActionFlags::ONSTACK | signal::SigActionFlags::SIGINFO);
        assert!(!simple.flags().contains(signal::SigActionFlags::SIGINFO));
        signal::sigaction(signal::Signal::USR1, Some(&simple)).unwrap();
        signal::raise(signal::Signal::USR1).unwrap();
        assert_eq!(signal::suspend(&suspended_mask), Err(Errno::INTR));
        assert_eq!(OBSERVED.load(Ordering::Relaxed), 1);
        assert_eq!(signal::current_mask().unwrap(), caller_mask);
        signal::sigaction(signal::Signal::USR1, Some(&original_action)).unwrap();
        signal::sigaltstack(Some(&signal::Stack::disabled())).unwrap();
        assert!(signal::sigaltstack(None).unwrap().flags().contains(signal::StackFlags::DISABLE));
        signal::sigaltstack(Some(&original_stack)).unwrap();
    }
    signal::set_mask(&original_mask).unwrap();
}
