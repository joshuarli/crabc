//! Owned POSIX message queues, including the SIGEV_THREAD notification worker.
//!
//! Pinned musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, MIT (`COPYRIGHT`):
//! src/mq/mq_open.c, mq_close.c, mq_unlink.c, mq_getattr.c, mq_send.c,
//! mq_receive.c, mq_timedsend.c, mq_timedreceive.c, and mq_notify.c map to
//! the corresponding entries below. The existing mq_setattr leaf retains
//! its shared record/syscall boundary. Linux/x86-64 has one native 64-bit
//! time ABI, so the source's 32-bit/time64 compatibility branch is absent.
//!
//! Notification uses the source per-registration netlink socket and one
//! pthread. A stack-resident semaphore transfers registration completion to
//! the caller after the worker copies callback/value. Failed registration
//! joins the still-joinable worker; success makes the worker detach itself,
//! receive the kernel cookie, close its socket, and invoke the callback only
//! for the source's 32-byte notification/tag-1 message. No worker registry,
//! queue-size cap, or callback dispatch fallback is introduced.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr;

use super::{c_result, c_status, errno, mq_setattr, posix_semaphore, pthread_attr,
    pthread_cancel, pthread_create_join, pthread_identity, raw_syscall,
    signal_control, signal_set_mutation, socket_transport};

const O_CREAT: c_int = 0x40;
const EPERM: i64 = 1;
const EACCES: i64 = 13;
const EAGAIN: c_int = 11;
const SIGEV_THREAD: c_int = 2;
const AF_NETLINK: c_int = 16;
const SOCK_RAW_CLOEXEC: c_int = 3 | 0x80000;
const MSG_WAITALL_NOSIGNAL: c_int = 0x100 | 0x4000;

/// Musl strips exactly one optional leading slash, then delegates namespace
/// validation and error precedence to the Linux mq syscall.
unsafe fn kernel_name(name: *const c_char) -> *const c_char {
    if unsafe { name.read() } == b'/' as c_char { unsafe { name.add(1) } } else { name }
}

// The C caller supplies a live NUL-terminated name. O_CREAT also supplies a
// mode_t and null or readable mq_attr pointer and owns creation effects.
// Two-argument callers do not supply mode/attribute registers. The O_CREAT
// branch alone admits the promoted mode_t and pointer varargs in edx/rcx.
core::arch::global_asm!(
    r#"
    .section .text.mq_open,"ax",@progbits
    .p2align 4
    .global mq_open
    .type mq_open,@function
mq_open:
    test esi, {o_create}
    jnz {create}
    jmp {existing}
    .size mq_open, .-mq_open
    .section .note.GNU-stack,"",@progbits
"#,
    o_create = const O_CREAT,
    create = sym open_create,
    existing = sym open_existing,
);

#[inline(never)]
unsafe extern "C" fn open_existing(name: *const c_char, flags: c_int) -> c_int {
    unsafe { open_create(name, flags, 0, ptr::null()) }
}
#[inline(never)]
unsafe extern "C" fn open_create(name: *const c_char, flags: c_int, mode: c_uint, attributes: *const c_void) -> c_int {
    c_status(unsafe { raw_syscall::syscall4(raw_syscall::SYS_MQ_OPEN,
        kernel_name(name) as i64, flags as i64, mode as i64, attributes as i64) })
}

/// Close a message-queue descriptor without making a cancellation point.
/// # Safety
/// The caller owns this descriptor and must coordinate its final close with
/// concurrent users. Linux validates its current value.
#[no_mangle]
pub unsafe extern "C" fn mq_close(queue: c_int) -> c_int {
    c_status(unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, queue as i64) })
}

/// Remove a queue name while preserving already-open descriptors.
/// # Safety
/// `name` must be a readable NUL-terminated C string for this call. The caller
/// owns the requested namespace mutation.
#[no_mangle]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    let result = unsafe { raw_syscall::syscall1(raw_syscall::SYS_MQ_UNLINK, kernel_name(name) as i64) };
    c_status(if result == -EPERM { -EACCES } else { result })
}

/// Query queue attributes through the existing mq_getsetattr owner.
/// # Safety
/// `attributes` must designate writable LP64 `struct mq_attr` storage and the
/// descriptor must remain open during the call. Invalid kernel inputs retain
/// their direct errors.
#[no_mangle]
pub unsafe extern "C" fn mq_getattr(queue: c_int, attributes: *mut c_void) -> c_int {
    unsafe { mq_setattr::mq_setattr(queue, ptr::null(), attributes) }
}

/// Send one message, waiting for space as a pthread cancellation point.
/// # Safety
/// `message` must designate `length` readable bytes for the call. The caller
/// owns descriptor lifetime and shared queue synchronization.
#[no_mangle]
pub unsafe extern "C" fn mq_send(queue: c_int, message: *const c_char, length: usize, priority: c_uint) -> c_int {
    unsafe { mq_timedsend(queue, message, length, priority, ptr::null()) }
}

/// Receive one message, waiting for availability as a cancellation point.
/// # Safety
/// `message` must designate `length` writable bytes; `priority` must be null
/// or writable unsigned-int storage. The caller owns descriptor lifetime and
/// any concurrent accesses to the queue or destination storage.
#[no_mangle]
pub unsafe extern "C" fn mq_receive(queue: c_int, message: *mut c_char, length: usize, priority: *mut c_uint) -> isize {
    unsafe { mq_timedreceive(queue, message, length, priority, ptr::null()) }
}

/// Send with an optional absolute CLOCK_REALTIME deadline.
/// # Safety
/// `message` must designate `length` readable bytes; `deadline` must be null
/// or a readable native 16-byte timespec. The caller keeps the descriptor and
/// inputs live for this cancellation point.
#[no_mangle]
pub unsafe extern "C" fn mq_timedsend(queue: c_int, message: *const c_char, length: usize, priority: c_uint, deadline: *const c_void) -> c_int {
    c_status(unsafe { pthread_cancel::syscall_cp(raw_syscall::SYS_MQ_TIMEDSEND,
        queue as i64, message as i64, length as i64, priority as i64, deadline as i64, 0) })
}

/// Receive with an optional absolute CLOCK_REALTIME deadline.
/// # Safety
/// `message` must designate `length` writable bytes; `priority` must be null
/// or writable unsigned-int storage; `deadline` must be null or a readable
/// native 16-byte timespec. All buffers and the descriptor stay live for this
/// cancellation point and cannot have conflicting concurrent accesses.
#[no_mangle]
pub unsafe extern "C" fn mq_timedreceive(queue: c_int, message: *mut c_char, length: usize, priority: *mut c_uint, deadline: *const c_void) -> isize {
    c_result(unsafe { pthread_cancel::syscall_cp(raw_syscall::SYS_MQ_TIMEDRECEIVE,
        queue as i64, message as i64, length as i64, priority as i64, deadline as i64, 0) }) as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
union SignalValue { integer: c_int, pointer: *mut c_void }
type NotifyFunction = unsafe extern "C" fn(SignalValue);
#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadNotification { function: Option<NotifyFunction>, attributes: *const c_void }
#[repr(C)]
#[derive(Clone, Copy)]
union NotificationPayload { thread: ThreadNotification, thread_id: c_int, padding: [u8; 48] }
#[repr(C)]
struct SignalEvent { value: SignalValue, signal: c_int, notification: c_int, payload: NotificationPayload }
const _: () = {
    assert!(size_of::<SignalEvent>() == 64);
    assert!(align_of::<SignalEvent>() == 8);
    assert!(offset_of!(SignalEvent, value) == 0);
    assert!(offset_of!(SignalEvent, signal) == 8);
    assert!(offset_of!(SignalEvent, notification) == 12);
    assert!(offset_of!(SignalEvent, payload) == 16);
    assert!(offset_of!(ThreadNotification, attributes) == 8);
};

/// Source `struct args` lives on the mq_notify caller's stack until the
/// private semaphore is posted. The worker must copy every caller-owned value
/// before posting and never access this record afterward.
struct NotifyArguments {
    semaphore: [u64; 4],
    socket: c_int,
    queue: c_int,
    error: c_int,
    event: *const SignalEvent,
}
static NOTIFICATION_COOKIE: [u8; 32] = [0; 32];

unsafe extern "C" fn notify_start(argument: *mut c_void) -> *mut c_void {
    let args = argument.cast::<NotifyArguments>();
    let socket = unsafe { (*args).socket };
    let event = unsafe { (*args).event };
    let function = unsafe { (*event).payload.thread.function };
    let value = unsafe { (*event).value };
    let kernel_event = SignalEvent {
        value: SignalValue { pointer: NOTIFICATION_COOKIE.as_ptr() as *mut c_void },
        signal: socket,
        notification: SIGEV_THREAD,
        payload: NotificationPayload { padding: [0; 48] },
    };
    // The kernel copies the 32-byte cookie now. Registering from this worker
    // retains the source task/notification lifecycle, then the semaphore
    // publishes both the error and the completed callback/value copy.
    let error = -unsafe { raw_syscall::syscall2(raw_syscall::SYS_MQ_NOTIFY,
        (*args).queue as i64, ptr::addr_of!(kernel_event) as i64) } as c_int;
    unsafe {
        (*args).error = error;
        posix_semaphore::sem_post(ptr::addr_of_mut!((*args).semaphore).cast());
    }
    if error != 0 { return ptr::null_mut(); }
    unsafe { pthread_create_join::pthread_detach(pthread_identity::current_thread_pointer().cast()); }
    let mut cookie = [0_u8; 32];
    let length = unsafe { socket_transport::recv(socket, cookie.as_mut_ptr().cast(), cookie.len(), MSG_WAITALL_NOSIGNAL) };
    super::descriptor_io::close(socket);
    if length == cookie.len() as isize && cookie[31] == 1 {
        // SIGEV_THREAD requires a valid callback. The public C caller owns
        // callback code/value pointee lifetime beyond mq_notify's return.
        unsafe { function.unwrap_unchecked()(value) };
    }
    ptr::null_mut()
}

/// Register or remove a queue notification using musl's netlink
/// worker protocol for SIGEV_THREAD and a direct syscall for other selectors.
/// # Safety
/// `event` must be null or a readable initialized native `struct sigevent`.
/// For SIGEV_THREAD, its callback must be valid and callable on the created
/// pthread, its optional pthread_attr_t must be initialized and readable, and
/// any callback code, value pointee, or supplied stack must outlive the
/// asynchronous callback. The caller owns descriptor and notification lifetime.
#[no_mangle]
pub unsafe extern "C" fn mq_notify(queue: c_int, event: *const c_void) -> c_int {
    let event = event.cast::<SignalEvent>();
    if event.is_null() || unsafe { (*event).notification } != SIGEV_THREAD {
        return c_status(unsafe { raw_syscall::syscall2(raw_syscall::SYS_MQ_NOTIFY, queue as i64, event as i64) });
    }
    let socket = socket_transport::socket(AF_NETLINK, SOCK_RAW_CLOEXEC, 0);
    if socket < 0 { return -1; }
    let mut args = NotifyArguments { semaphore: [0; 4], socket, queue, error: 0, event };
    // pthread_attr_t is the existing 56-byte, align-8 public record. Copy the
    // caller's complete image, then let its owner override detach state.
    let mut attributes = [0_usize; 7];
    let requested_attributes = unsafe { (*event).payload.thread.attributes };
    if requested_attributes.is_null() {
        unsafe { pthread_attr::pthread_attr_init(attributes.as_mut_ptr().cast()); }
    } else {
        unsafe { ptr::copy_nonoverlapping(requested_attributes.cast::<usize>(), attributes.as_mut_ptr(), attributes.len()); }
    }
    unsafe {
        pthread_attr::pthread_attr_setdetachstate(attributes.as_mut_ptr().cast(), 0);
        posix_semaphore::sem_init(args.semaphore.as_mut_ptr().cast(), 0, 0);
    }
    let mut all_signals = [0_u64; 16];
    let mut previous_signals = [0_u64; 16];
    unsafe {
        signal_set_mutation::sigfillset(all_signals.as_mut_ptr().cast());
        signal_control::pthread_sigmask(0, all_signals.as_ptr().cast(), previous_signals.as_mut_ptr().cast());
    }
    let mut thread = ptr::null_mut();
    let created = unsafe { pthread_create_join::pthread_create(&mut thread,
        attributes.as_ptr().cast(), Some(notify_start), ptr::addr_of_mut!(args).cast()) };
    if created != 0 {
        unsafe {
            raw_syscall::syscall1(raw_syscall::SYS_CLOSE, socket as i64);
            signal_control::pthread_sigmask(2, previous_signals.as_ptr().cast(), ptr::null_mut());
            errno::set_errno(EAGAIN);
        }
        return -1;
    }
    unsafe { signal_control::pthread_sigmask(2, previous_signals.as_ptr().cast(), ptr::null_mut()); }
    let mut previous_cancellation = 0;
    unsafe {
        pthread_cancel::pthread_setcancelstate(1, &mut previous_cancellation);
        posix_semaphore::sem_wait(args.semaphore.as_mut_ptr().cast());
        posix_semaphore::sem_destroy(args.semaphore.as_mut_ptr().cast());
    }
    if args.error != 0 {
        unsafe {
            raw_syscall::syscall1(raw_syscall::SYS_CLOSE, socket as i64);
            pthread_create_join::pthread_join(thread, ptr::null_mut());
            pthread_cancel::pthread_setcancelstate(previous_cancellation, ptr::null_mut());
            errno::set_errno(args.error);
        }
        return -1;
    }
    unsafe { pthread_cancel::pthread_setcancelstate(previous_cancellation, ptr::null_mut()); }
    0
}
