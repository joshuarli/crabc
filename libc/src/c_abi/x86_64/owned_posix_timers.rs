//! Owned Linux/x86-64 POSIX timers. Source map: musl 1.2.6, revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417 (MIT), src/time/timer_{create,
//! delete,getoverrun,gettime,settime}.c and src/env/__reset_tls.c.
//!
//! A SIGEV_THREAD timer retains one detached pthread, reusing that task after
//! every notification, including callback pthread_exit and cancellation. Its
//! private mapped TimerWorker replaces musl's pthread.timer_id field; the
//! negative handle tags this mapping, not the public pthread representation.
//! Two stack-resident futex handshakes preserve musl's two-sem argument lifetime
//! and timer-ID publication ordering. The assembly continuation owns setjmp's
//! returns-twice edge; no Rust function resumes a previously returned frame.

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use super::{c_status, errno, pthread_attr, pthread_cancel, pthread_create_join,
    pthread_tsd, raw_syscall, signal_foundation, static_tls};

const SIGTIMER: i64 = 32;
const SYS_TIMER_CREATE: i64 = 222;
const FUTEX_WAIT_PRIVATE: i64 = 128;
const FUTEX_WAKE_PRIVATE: i64 = 129;
const TIMER_MASK: u64 = 1 << 31;
const CALLBACK_MASK: u64 = 0xffff_fffc_ffff_ffff;
const REGION_SIZE: i64 = 4096;
const EINTR: i64 = 4;
const EINVAL: c_int = 22;
const EAGAIN: c_int = 11;

/// The installed x86 union sigval occupies one integer-class machine word.
#[repr(C)]
#[derive(Clone, Copy)]
pub union Sigval { integer: c_int, pointer: *mut c_void }
type Notify = unsafe extern "C" fn(Sigval);

#[repr(C)]
pub struct Sigevent { value: Sigval, signal: c_int, notify: c_int, fields: SigeventFields }
#[repr(C)]
union SigeventFields { thread_id: c_int, thread: ThreadNotification, padding: [u8; 48] }
#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadNotification { function: Notify, attributes: *const [usize; 7] }
#[repr(C)]
struct KernelSigevent { value: Sigval, signal: c_int, notify: c_int, tid: c_int, padding: [u8; 44] }
#[repr(C)]
struct TimerWorker { id: AtomicI32, tid: c_int, notify: Notify, value: Sigval }
struct StartArgs { ready: AtomicI32, consumed: AtomicI32, worker: *mut TimerWorker }

// Do not read SIGEV_THREAD_ID as a native word: its four-byte pid_t leaves
// the following union padding uninitialized in a valid C notification record.
const _: () = {
    assert!(core::mem::size_of::<Sigevent>() == 64);
    assert!(core::mem::size_of::<Sigval>() == 8);
    assert!(core::mem::offset_of!(Sigevent, fields) == 16);
    assert!(core::mem::offset_of!(ThreadNotification, attributes) == 8);
    assert!(core::mem::size_of::<KernelSigevent>() == 64);
};

unsafe fn mask(how: i64, bits: *const u64, old: *mut u64) {
    unsafe { raw_syscall::syscall4(raw_syscall::SYS_RT_SIGPROCMASK, how, bits as i64, old as i64, 8); }
}
// The reverse acknowledgement permits the creator's argument storage to
// retire immediately after the release store. Keep no Rust reference across
// that publication, and never read the futex word afterward.
unsafe fn post(word: *const AtomicI32) {
    let address = word as i64;
    unsafe { (*word).store(1, Ordering::Release); }
    unsafe { raw_syscall::syscall6(raw_syscall::SYS_FUTEX, address, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0); }
}
fn wait(word: &AtomicI32) {
    while word.load(Ordering::Acquire) == 0 {
        unsafe { raw_syscall::syscall6(raw_syscall::SYS_FUTEX, word as *const AtomicI32 as i64, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0); }
    }
}
unsafe extern "C" fn timer_handler(_: c_int, _: *mut c_void, _: *mut c_void) {}

/// Restore the callback's logical thread before resuming the timer loop.
/// The cleanup record is already popped by normal cleanup or pthread_exit.
unsafe extern "C" fn cleanup_callback(jump: *mut c_void) {
    if let Some(values) = pthread_create_join::current_selected_worker_tsd_values() {
        unsafe { pthread_tsd::run_timer_callback_tsd_destructors(values); }
    }
    unsafe { mask(0, &CALLBACK_MASK, core::ptr::null_mut()); }
    pthread_cancel::reset_timer_callback_cancellation();
    // Only ELF TLS bytes are restored. TCB, DTV, cancellation control and the
    // stack continuation remain live, owned by their existing runtime owners.
    // Musl errno lives in struct pthread, outside __reset_tls's ELF images.
    // Our errno is ELF TLS; preserve that same TCB-like callback continuity.
    let callback_errno = unsafe { errno::get_errno() };
    unsafe {
        static_tls::reset_current_thread_images();
        errno::set_errno(callback_errno);
        longjmp(jump, 1);
    }
}

#[no_mangle]
unsafe extern "C" fn __crabc_x86_timer_invoke(worker: *mut TimerWorker, jump: *mut c_void) {
    let mut cleanup = core::mem::MaybeUninit::<pthread_cancel::CleanupNode>::uninit();
    unsafe {
        pthread_cancel::_pthread_cleanup_push(cleanup.as_mut_ptr(), Some(cleanup_callback), jump);
        ((*worker).notify)((*worker).value);
        pthread_cancel::_pthread_cleanup_pop(cleanup.as_mut_ptr(), 1);
    }
}

unsafe extern "C" {
    fn __crabc_x86_timer_dispatch(worker: *mut TimerWorker);
    fn longjmp(jump: *mut c_void, result: c_int) -> !;
}

// Preserve the timer loop's callee-saved registers and its original stack in
// an ordinary single-return ABI. setjmp/longjmp never target a Rust frame.
core::arch::global_asm!(r#"
    .text
    .hidden __crabc_x86_timer_invoke
    .hidden __crabc_x86_timer_dispatch
    .global __crabc_x86_timer_dispatch
    .type __crabc_x86_timer_dispatch,@function
__crabc_x86_timer_dispatch:
    push rbx
    sub rsp, 64
    mov rbx, rdi
    mov rdi, rsp
    call setjmp
    test eax, eax
    jnz .Ltimer_callback_done
    mov rdi, rbx
    mov rsi, rsp
    call __crabc_x86_timer_invoke
.Ltimer_callback_done:
    add rsp, 64
    pop rbx
    ret
    .size __crabc_x86_timer_dispatch, .-__crabc_x86_timer_dispatch
    .section .note.GNU-stack,"",@progbits
"#);

unsafe extern "C" fn start(argument: *mut c_void) -> *mut c_void {
    let args = argument.cast::<StartArgs>();
    let worker = unsafe { (*args).worker };
    unsafe { wait(&(*args).ready); }
    let failed = unsafe { (*worker).id.load(Ordering::Acquire) } < 0;
    unsafe { post(core::ptr::addr_of!((*args).consumed)); }
    // Never access args after acknowledgement: its caller's stack may retire.
    if !failed {
        loop {
            let mut info = [0u64; 16];
            loop {
                let result = unsafe { pthread_cancel::syscall_cp(raw_syscall::SYS_RT_SIGTIMEDWAIT, &TIMER_MASK as *const u64 as i64,
                    info.as_mut_ptr() as i64, 0, 8, 0, 0) };
                // sigwaitinfo -> sigtimedwait retries raw EINTR before
                // __syscall_ret. A handled signal with no pending cancellation
                // must not replace the previous callback's errno with EINTR.
                if result == -EINTR { continue; }
                if c_status(result) >= 0 { break; }
            }
            let code = unsafe { info.as_ptr().cast::<c_int>().add(2).read() };
            if code == -2 { unsafe { __crabc_x86_timer_dispatch(worker); } }
            let id = unsafe { (*worker).id.load(Ordering::Acquire) };
            if id < 0 {
                unsafe { raw_syscall::syscall1(raw_syscall::SYS_TIMER_DELETE, (id & c_int::MAX) as i64); }
                break;
            }
        }
    }
    unsafe { raw_syscall::syscall2(raw_syscall::SYS_MUNMAP, worker as i64, REGION_SIZE); }
    core::ptr::null_mut()
}

/// Create a POSIX timer using a valid clock and optional notification record.
/// # Safety
/// `event` is null or a readable initialized installed struct sigevent.
/// `output` is writable timer_t storage; thread callback and attributes follow
/// POSIX pthread lifetime requirements. The returned timer has one deletion owner.
#[no_mangle]
pub unsafe extern "C" fn timer_create(clock: c_int, event: *const Sigevent, output: *mut *mut c_void) -> c_int {
    let notify = if event.is_null() { 0 } else { unsafe { (*event).notify } };
    if matches!(notify, 0 | 1 | 4) {
        let mut kernel = KernelSigevent { value: Sigval { integer: 0 }, signal: 0, notify, tid: 0, padding: [0; 44] };
        let pointer = if event.is_null() { core::ptr::null() } else {
            kernel.value = unsafe { (*event).value }; kernel.signal = unsafe { (*event).signal };
            if notify == 4 { kernel.tid = unsafe { (*event).fields.thread_id }; }
            &kernel as *const KernelSigevent
        };
        let mut id = 0;
        let result = unsafe { raw_syscall::syscall3(SYS_TIMER_CREATE, clock as i64, pointer as i64, &mut id as *mut c_int as i64) };
        if c_status(result) < 0 { return -1; }
        unsafe { output.write(id as usize as *mut c_void); }
        return 0;
    }
    if notify != 2 { unsafe { errno::set_errno(EINVAL); } return -1; }
    // Reinstalling the same reserved handler is idempotent, including after
    // fork. The signal is never available to the public sigaction namespace.
    let action = signal_foundation::KernelSigAction { handler: timer_handler as *const () as usize,
        flags: 0x1400_0004, restorer: signal_foundation::restorer_address(), mask: 0 };
    unsafe { raw_syscall::syscall4(raw_syscall::SYS_RT_SIGACTION, SIGTIMER, &action as *const _ as i64, 0, 8); }
    let mapping = unsafe { raw_syscall::syscall6(raw_syscall::SYS_MMAP, 0, REGION_SIZE, 3, 0x22, -1, 0) };
    if (-4095..0).contains(&mapping) { unsafe { errno::set_errno(EAGAIN); } return -1; }
    let worker = mapping as *mut TimerWorker;
    let notification = unsafe { (*event).fields.thread };
    unsafe { worker.write(TimerWorker { id: AtomicI32::new(-1), tid: 0,
        notify: notification.function, value: (*event).value }); }
    let mut attr = [0usize; 7];
    let attr_source = notification.attributes;
    unsafe {
        if attr_source.is_null() { pthread_attr::pthread_attr_init(attr.as_mut_ptr().cast()); }
        else { attr = attr_source.read(); }
        pthread_attr::pthread_attr_setdetachstate(attr.as_mut_ptr().cast(), 1);
    }
    let args = StartArgs { ready: AtomicI32::new(0), consumed: AtomicI32::new(0), worker };
    let mut previous = 0u64;
    let mut thread = core::ptr::null_mut();
    unsafe { mask(0, &CALLBACK_MASK, &mut previous); }
    let error = unsafe { pthread_create_join::pthread_create(&mut thread, attr.as_ptr().cast(), Some(start), &args as *const _ as *mut c_void) };
    unsafe { mask(2, &previous, core::ptr::null_mut()); }
    if error != 0 {
        unsafe { raw_syscall::syscall2(raw_syscall::SYS_MUNMAP, mapping, REGION_SIZE); }
        unsafe { errno::set_errno(error); } return -1;
    }
    let tid = pthread_create_join::selected_worker_linux_thread_id(thread).unwrap_or(0);
    unsafe { (*worker).tid = tid; }
    let kernel = KernelSigevent { value: Sigval { integer: 0 }, signal: SIGTIMER as c_int, notify: 4, tid, padding: [0; 44] };
    let mut id = -1;
    let result = unsafe { raw_syscall::syscall3(SYS_TIMER_CREATE, clock as i64, &kernel as *const _ as i64, &mut id as *mut c_int as i64) };
    // Source syscall() publishes a creation error before the sem2
    // cancellation point, so creator cleanup handlers observe that errno.
    let status = c_status(result);
    if status < 0 { id = -1; }
    unsafe { (*worker).id.store(id, Ordering::Release); }
    unsafe { post(&args.ready); }
    wait(&args.consumed);
    // sem_wait(sem2) checks cancellation even when its token is available.
    // Defer that check until the reverse acknowledgement: only now may user
    // cleanup retire the creator's stack without invalidating worker args.
    pthread_cancel::test_current_selected_pthread_cancellation();
    if status < 0 { return -1; }
    unsafe { output.write(((1usize << 63) | ((worker as usize) >> 1)) as *mut c_void); }
    0
}

unsafe fn kernel_id(timer: *mut c_void) -> i64 {
    if (timer as isize) < 0 {
        unsafe { (*( (timer as usize).wrapping_shl(1) as *const TimerWorker)).id.load(Ordering::Acquire) as i64 }
    } else { timer as i64 }
}

/// Delete one live timer. Nonnegative handles preserve musl's raw -errno ABI.
/// # Safety
/// `timer` is a live timer returned by timer_create and is deleted exactly once;
/// no other thread may use its handle after deletion.
#[no_mangle]
pub unsafe extern "C" fn timer_delete(timer: *mut c_void) -> c_int {
    if (timer as isize) < 0 {
        let worker = (timer as usize).wrapping_shl(1) as *mut TimerWorker;
        let tid = unsafe { (*worker).tid };
        unsafe { (*worker).id.fetch_or(c_int::MIN, Ordering::AcqRel); raw_syscall::syscall2(raw_syscall::SYS_TKILL, tid as i64, SIGTIMER); }
        0
    } else { unsafe { raw_syscall::syscall1(raw_syscall::SYS_TIMER_DELETE, timer as i64) as c_int } }
}

/// Query overruns for one live timer.
/// # Safety
/// `timer` is live and not concurrently deleted.
#[no_mangle]
pub unsafe extern "C" fn timer_getoverrun(timer: *mut c_void) -> c_int {
    c_status(unsafe { raw_syscall::syscall1(raw_syscall::SYS_TIMER_GETOVERRUN, kernel_id(timer)) })
}
/// Read the current interval and remaining time.
/// # Safety
/// `timer` is live; `value` points to writable installed struct itimerspec storage.
#[no_mangle]
pub unsafe extern "C" fn timer_gettime(timer: *mut c_void, value: *mut c_void) -> c_int {
    c_status(unsafe { raw_syscall::syscall2(raw_syscall::SYS_TIMER_GETTIME, kernel_id(timer), value as i64) })
}
/// Arm or disarm one live timer.
/// # Safety
/// `timer` is live; `value` is readable struct itimerspec storage and `old` is
/// null or writable storage of that same installed layout for this call.
#[no_mangle]
pub unsafe extern "C" fn timer_settime(timer: *mut c_void, flags: c_int, value: *const c_void, old: *mut c_void) -> c_int {
    c_status(unsafe { raw_syscall::syscall4(raw_syscall::SYS_TIMER_SETTIME, kernel_id(timer), flags as i64, value as i64, old as i64) })
}
