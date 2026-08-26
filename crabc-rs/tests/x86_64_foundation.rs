#![cfg(target_arch = "x86_64")]

use core::arch::global_asm;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use crabc_rs::io;
use crabc_rs::ioctl::{opcode, Direction};
use crabc_rs::pipe;
use crabc_rs::signal::{self, Pid, SigAction, SigActionFlags, SigHandler, Signal};
use crabc_rs::Errno;

const SIG_SETMASK: i32 = 2;
const SIGUSR1_MASK: u64 = 1 << (Signal::USR1.as_raw() - 1);
const MUSL_RESERVED_MASK: u64 = (1 << 31) | (1 << 32) | (1 << 33);

static SIMPLE_HANDLER_RAN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn usr1_handler(_: Signal) {
    SIMPLE_HANDLER_RAN.store(true, Ordering::SeqCst);
}

// This private test trampoline is deliberately distinct from crabc-rs's
// restorer. It lets the raw-action round-trip prove that a queried action keeps
// its original `SA_RESTORER` address rather than replacing it with crabc-rs's.
global_asm!(
    ".global crabc_rs_x86_foundation_restorer",
    ".type crabc_rs_x86_foundation_restorer,@function",
    "crabc_rs_x86_foundation_restorer:",
    "mov rax, 15",
    "syscall",
);

unsafe extern "C" {
    fn crabc_rs_x86_foundation_restorer();
}

struct RestoreKernelSignalAction(crabc_core::signal::KernelSigAction);

impl Drop for RestoreKernelSignalAction {
    fn drop(&mut self) {
        // SAFETY: This record was returned by Linux before the test replaced
        // SIGUSR1. It remains valid byte-for-byte through restoration.
        let _ = unsafe {
            crabc_core::signal::rt_sigaction_raw(
                Signal::USR1.as_raw(),
                &self.0,
                core::ptr::null_mut(),
            )
        };
    }
}

struct RestoreSignalMask(u64);

impl Drop for RestoreSignalMask {
    fn drop(&mut self) {
        // SAFETY: The saved mask was read from this thread before the test
        // changed only its SIGUSR1 bit.
        let _ = unsafe {
            crabc_core::signal::rt_sigprocmask_raw(
                SIG_SETMASK,
                &self.0,
                core::ptr::null_mut(),
            )
        };
    }
}

fn query_kernel_action() -> crabc_core::signal::KernelSigAction {
    let mut action = MaybeUninit::<crabc_core::signal::KernelSigAction>::uninit();
    // SAFETY: `action` is writable compact-kernel-record storage and a null
    // new-action pointer only queries the current disposition.
    unsafe {
        crabc_core::signal::rt_sigaction_raw(
            Signal::USR1.as_raw(),
            core::ptr::null(),
            action.as_mut_ptr(),
        )
        .expect("query raw SIGUSR1 action");
        action.assume_init()
    }
}

fn install_kernel_action(action: &crabc_core::signal::KernelSigAction) {
    // SAFETY: The test supplies Linux/x86-64's exact compact action record.
    // The temporary handler and restorer remain linked until it is replaced.
    unsafe {
        crabc_core::signal::rt_sigaction_raw(
            Signal::USR1.as_raw(),
            action,
            core::ptr::null_mut(),
        )
        .expect("install raw SIGUSR1 action");
    }
}

fn unmask_usr1_without_changing_other_bits() -> RestoreSignalMask {
    let mut saved = 0_u64;
    // SAFETY: A null input merely queries this thread's one-word kernel mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            core::ptr::null(),
            &mut saved,
        )
        .expect("query x86-64 signal mask");
    }

    let unblocked = saved & !SIGUSR1_MASK;
    let mut replaced = 0_u64;
    // SAFETY: `unblocked` differs from the saved kernel mask only at SIGUSR1.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(SIG_SETMASK, &unblocked, &mut replaced)
            .expect("unblock SIGUSR1");
    }
    let restore = RestoreSignalMask(saved);
    assert_eq!(replaced, saved, "signal-mask replacement raced unexpectedly");

    let mut observed = 0_u64;
    // SAFETY: A null input merely queries this thread's one-word kernel mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            core::ptr::null(),
            &mut observed,
        )
        .expect("observe unblocked SIGUSR1 mask");
    }
    assert_eq!(observed & !SIGUSR1_MASK, saved & !SIGUSR1_MASK);
    assert_eq!(observed & SIGUSR1_MASK, 0);

    restore
}

fn assert_same_kernel_action(
    expected: crabc_core::signal::KernelSigAction,
    actual: crabc_core::signal::KernelSigAction,
) {
    assert_eq!(actual.handler, expected.handler);
    assert_eq!(actual.flags, expected.flags);
    assert_eq!(actual.restorer, expected.restorer);
    assert_eq!(actual.mask, expected.mask);
}

#[test]
fn x86_64_direct_signal_and_ioctl_foundation_uses_only_admitted_capabilities() {
    assert_eq!(opcode::none(b'T', 227), 0x54e3);
    assert_eq!(opcode::read::<u32>(b'U', 15), 0x8004_550f);
    assert_eq!(opcode::write::<i32>(b'T', 200), 0x4004_54c8);
    assert_eq!(
        opcode::from_components(Direction::ReadWrite, b'X', 119, core::mem::size_of::<i32>()),
        0xc004_5877
    );

    // SAFETY: The raw ioctl accepts any integer descriptor and must return
    // the kernel's typed EBADF result without crossing C errno state.
    assert_eq!(
        unsafe { crabc_core::io::ioctl_raw(-1, 0x541b, core::ptr::null_mut()) },
        Err(Errno::BADF)
    );

    let mut attempts = 0;
    assert_eq!(
        io::retry_on_intr(|| {
            attempts += 1;
            if attempts == 1 {
                Err(Errno::INTR)
            } else {
                Ok(7)
            }
        }),
        Ok(7)
    );

    let (reader, writer) = pipe::pipe().expect("create direct x86-64 pipe");
    assert_eq!(
        io::write(&writer, b"x86").expect("write through the direct syscall facade"),
        3
    );
    let mut bytes_available = -1_i32;
    // SAFETY: `FIONREAD` (0x541b) writes one `int` to the live output pointer
    // for a pipe descriptor. This proves the successful ioctl pointer path.
    assert_eq!(
        unsafe {
            crabc_core::io::ioctl_raw(
                reader.as_raw_fd(),
                0x541b,
                (&mut bytes_available as *mut i32).cast(),
            )
        },
        Ok(0)
    );
    assert_eq!(bytes_available, 3);
    let mut payload = [0_u8; 3];
    assert_eq!(
        io::read(&reader, &mut payload).expect("read through the direct syscall facade"),
        3
    );
    assert_eq!(payload, *b"x86");

    assert_eq!(Pid::from_raw(-1), None);
    assert_eq!(Pid::from_raw(0), None);
    assert_eq!(Pid::from_raw(1).expect("positive pid").as_raw_pid(), 1);

    let original_action = query_kernel_action();
    let _restore_action = RestoreKernelSignalAction(original_action);

    let raw_action = crabc_core::signal::KernelSigAction {
        handler: usr1_handler as *const () as usize,
        flags: crabc_core::signal::SA_RESTORER,
        restorer: crabc_rs_x86_foundation_restorer as *const () as usize,
        // Signals 32, 33, and 34 are musl-reserved but must survive an action
        // query/reinstall verbatim; public x86 masking APIs are intentionally
        // not admitted yet.
        mask: MUSL_RESERVED_MASK,
    };
    install_kernel_action(&raw_action);

    // SAFETY: This only queries the temporary action. Its handler and custom
    // restorer remain linked until the raw restoration guard runs.
    let queried = unsafe { signal::sigaction(Signal::USR1, None) }
        .expect("query x86-64 action through crabc-rs");
    assert!(queried.handler().is_some());
    // SAFETY: `queried` retains the exact compact record returned above.
    unsafe { signal::sigaction(Signal::USR1, Some(&queried)) }
        .expect("reinstall queried x86-64 action");
    assert_same_kernel_action(raw_action, query_kernel_action());

    let _restore_mask = unmask_usr1_without_changing_other_bits();
    SIMPLE_HANDLER_RAN.store(false, Ordering::SeqCst);
    let action = SigAction::new(
        SigHandler::Simple(usr1_handler),
        SigActionFlags::from_bits_retain(0x0000_0004),
    );
    assert_eq!(action.flags().bits() & 0x0000_0004, 0);
    // SAFETY: `usr1_handler` performs one lock-free atomic store and remains
    // linked until the raw action-restoration guard runs.
    unsafe { signal::sigaction(Signal::USR1, Some(&action)) }
        .expect("install x86-64 simple handler with crabc-rs restorer");
    let installed = query_kernel_action();
    assert_eq!(installed.handler, usr1_handler as *const () as usize);
    assert_ne!(installed.flags & crabc_core::signal::SA_RESTORER, 0);
    assert_ne!(installed.restorer, 0);
    assert_ne!(installed.restorer, raw_action.restorer);
    assert_eq!(installed.mask, 0);

    signal::raise(Signal::USR1).expect("return through x86-64 rt_sigreturn restorer");
    assert!(SIMPLE_HANDLER_RAN.load(Ordering::SeqCst));
}
