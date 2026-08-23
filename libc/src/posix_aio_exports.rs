// POSIX AIO exports.
//
// The musl aiocb has private fields for its completion state.  Keep this
// layout in lockstep with include/aio.h so that completion is visible to C
// callers without an out-of-band allocation or a process-global table.  The
// implementation completes each request before returning from submission,
// but it still transitions through EINPROGRESS and records the real syscall
// result in the aiocb.  That gives aio_error/aio_return/aio_cancel the same
// observable lifecycle for successful and failed requests.

const CABI_AIO_NOTCANCELED: c_int = 1;
const CABI_AIO_ALLDONE: c_int = 2;

const CABI_LIO_READ: c_int = 0;
const CABI_LIO_WRITE: c_int = 1;
const CABI_LIO_NOP: c_int = 2;
const CABI_LIO_WAIT: c_int = 0;
const CABI_LIO_NOWAIT: c_int = 1;

const CABI_AIO_ENOENT: c_int = 2;
const CABI_AIO_EINVAL: c_int = 22;
const CABI_AIO_EINTR: c_int = 4;
const CABI_AIO_EAGAIN: c_int = 11;
const CABI_AIO_EINPROGRESS: c_int = 115;
const CABI_AIO_EIO: c_int = 5;
const CABI_AIO_O_DSYNC: c_int = 0x1000;
const CABI_AIO_O_SYNC: c_int = 0x101000;
const CABI_AIO_SEEK_CUR: c_int = 1;

#[repr(C)]
struct CabiAioCb {
    aio_fildes: c_int,
    aio_lio_opcode: c_int,
    aio_reqprio: c_int,
    aio_buf: *mut c_void,
    aio_nbytes: usize,
    // struct sigevent is 64 bytes and 8-byte aligned on the supported
    // Linux ABIs.  Its contents are not needed for the I/O syscall itself.
    aio_sigevent: [u8; 64],
    __td: *mut c_void,
    __lock: [c_int; 2],
    __err: c_int,
    __ret: isize,
    aio_offset: i64,
    __next: *mut c_void,
    __prev: *mut c_void,
    __dummy4: [u8; 32 - 2 * core::mem::size_of::<*mut c_void>()],
}

#[repr(C)]
#[derive(Copy, Clone)]
union CabiAioSigval {
    sival_int: c_int,
    sival_ptr: *mut c_void,
}

#[repr(C)]
struct CabiAioSigevent {
    sigev_value: CabiAioSigval,
    sigev_signo: c_int,
    sigev_notify: c_int,
    // The SIGEV_THREAD function pointer is the first member of this tail.
    __tail: [u8; 48],
}

const CABI_AIO_SIGEV_SIGNAL: c_int = 0;
const CABI_AIO_SIGEV_THREAD: c_int = 2;

type CabiAioNotifyFn = unsafe extern "C" fn(CabiAioSigval);

// A SIGEV_THREAD notification outlives the aio_submit call.  Do not pass the
// caller's sigevent (which is commonly embedded in a stack aiocb) to the
// detached thread; copy the callback and value into an owned mapping instead.
#[repr(C)]
struct CabiAioNotifyTask {
    notify: CabiAioNotifyFn,
    value: CabiAioSigval,
}

const CABI_AIO_NOTIFY_MAPPING_SIZE: usize = core::mem::size_of::<CabiAioNotifyTask>();

#[inline]
unsafe fn cabi_aio_cb(cb: *mut c_void) -> *mut CabiAioCb {
    cb as *mut CabiAioCb
}

#[inline]
unsafe fn cabi_aio_errno(result: i64) -> c_int {
    if result < 0 && result >= -4095 {
        (-result) as c_int
    } else {
        CABI_AIO_EIO
    }
}

#[inline]
unsafe fn cabi_aio_set_completion(cb: *mut CabiAioCb, err: c_int, ret: isize) {
    // __ret precedes __err in the completion protocol used by musl.  Volatile
    // accesses preserve the C header's volatile __err contract for callers
    // which poll from another thread.
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*cb).__ret), ret);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*cb).__err), err);
}

#[inline]
unsafe fn cabi_aio_error_value(cb: *const CabiAioCb) -> c_int {
    core::ptr::read_volatile(core::ptr::addr_of!((*cb).__err)) & 0x7fff_ffff
}

#[inline]
unsafe fn cabi_aio_return_value(cb: *const CabiAioCb) -> isize {
    core::ptr::read_volatile(core::ptr::addr_of!((*cb).__ret))
}

unsafe extern "C" fn cabi_aio_notify_thread(arg: *mut c_void) -> *mut c_void {
    let task = arg as *mut CabiAioNotifyTask;
    let notify = (*task).notify;
    let value = (*task).value;
    // The callback and sigval have been copied out, so the task's mapping can
    // be released before entering user code.  This also makes the ownership
    // boundary explicit if the callback blocks or retains its sigval pointer.
    let _ = sys_munmap(task as *mut u8, CABI_AIO_NOTIFY_MAPPING_SIZE);
    notify(value);
    core::ptr::null_mut()
}

// Notify the optional per-request sigevent after the completion fields have
// become visible.  SIGEV_THREAD is dispatched through a detached pthread so
// the callback never runs inline on the submitting thread.
// SIGEV_SIGNAL uses the real process signal path.  A zeroed sigevent has signo
// 0, for which raise is the required harmless validation syscall, matching the
// usual zero-initialized aiocb use case.
unsafe fn cabi_aio_notify(event: *const u8) {
    if event.is_null() {
        return;
    }
    let event = event as *const CabiAioSigevent;
    match (*event).sigev_notify {
        CABI_AIO_SIGEV_SIGNAL => {
            let _ = raise((*event).sigev_signo);
        }
        CABI_AIO_SIGEV_THREAD => {
            let notify = core::ptr::read_unaligned(
                (*event).__tail.as_ptr() as *const Option<CabiAioNotifyFn>,
            );
            let Some(notify) = notify else {
                return;
            };
            let attributes = core::ptr::read_unaligned(
                (*event).__tail.as_ptr().add(core::mem::size_of::<*mut c_void>())
                    as *const *const pthread_attr_t,
            );
            let task = sys_mmap(
                core::ptr::null_mut(),
                CABI_AIO_NOTIFY_MAPPING_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if task == MMAP_FAILED {
                return;
            }
            let task = task as *mut CabiAioNotifyTask;
            (*task).notify = notify;
            (*task).value = (*event).sigev_value;

            let mut thread: PthreadT = 0;
            let result = pthread_create(
                &mut thread,
                attributes,
                cabi_aio_notify_thread as *const () as usize,
                task as *mut c_void,
            );
            if result != 0 {
                let _ = sys_munmap(task as *mut u8, CABI_AIO_NOTIFY_MAPPING_SIZE);
                return;
            }
            // Ownership transferred to the child with a successful create;
            // never reclaim task here, even if detach races an already-exited
            // child and reports an error.  The child always unmaps its task.
            // SIGEV_THREAD notifications are detached by definition.  The
            // existing pthread implementation safely handles both a live and
            // an already-exited child here.
            let _ = pthread_detach(thread);
        }
        _ => {}
    }
}

unsafe fn cabi_aio_submit(cb: *mut CabiAioCb, op: c_int) -> c_int {
    let fd = (*cb).aio_fildes;
    let check = sys_fcntl(fd, F_GETFD, 0);
    if check < 0 {
        let err = cabi_aio_errno(check);
        cabi_aio_set_completion(cb, err, -1);
        ERRNO = err;
        return -1;
    }

    // Preserve the state transition even though the underlying syscall is
    // issued synchronously.  This makes polling and cancellation observe the
    // same state machine as an asynchronous implementation.
    cabi_aio_set_completion(cb, CABI_AIO_EINPROGRESS, -1);

    let result = match op {
        CABI_LIO_READ => {
            // Like musl, use positional I/O for seekable descriptors and the
            // descriptor's current position for pipes and other streams.
            if sys_lseek(fd as i64, 0, CABI_AIO_SEEK_CUR as i64) >= 0 {
                sys_pread64(fd, (*cb).aio_buf as *mut u8, (*cb).aio_nbytes, (*cb).aio_offset)
            } else {
                sys_read(fd as i64, (*cb).aio_buf as *mut u8, (*cb).aio_nbytes)
            }
        }
        CABI_LIO_WRITE => {
            let flags = sys_fcntl(fd, F_GETFL, 0);
            let seekable = sys_lseek(fd as i64, 0, CABI_AIO_SEEK_CUR as i64) >= 0;
            if !seekable || (flags >= 0 && (flags as c_int & O_APPEND) != 0) {
                sys_write(fd as i64, (*cb).aio_buf as *const u8, (*cb).aio_nbytes)
            } else {
                sys_pwrite64(fd, (*cb).aio_buf as *const u8, (*cb).aio_nbytes, (*cb).aio_offset)
            }
        }
        CABI_AIO_O_SYNC => match crabc_core::fs::fsync(fd) {
            Ok(()) => 0,
            Err(errno) => -(errno.raw() as i64),
        },
        CABI_AIO_O_DSYNC => match crabc_core::fs::fdatasync(fd) {
            Ok(()) => 0,
            Err(errno) => -(errno.raw() as i64),
        },
        _ => return CABI_AIO_EINVAL,
    };

    if result < 0 {
        cabi_aio_set_completion(cb, cabi_aio_errno(result), -1);
    } else {
        cabi_aio_set_completion(cb, 0, result as isize);
    }
    cabi_aio_notify((*cb).aio_sigevent.as_ptr());
    0
}

#[no_mangle]
pub unsafe extern "C" fn aio_read(cb: *mut c_void) -> c_int {
    if cb.is_null() {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }
    cabi_aio_submit(cabi_aio_cb(cb), CABI_LIO_READ)
}

#[no_mangle]
pub unsafe extern "C" fn aio_write(cb: *mut c_void) -> c_int {
    if cb.is_null() {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }
    cabi_aio_submit(cabi_aio_cb(cb), CABI_LIO_WRITE)
}

#[no_mangle]
pub unsafe extern "C" fn aio_fsync(op: c_int, cb: *mut c_void) -> c_int {
    if op != CABI_AIO_O_SYNC && op != CABI_AIO_O_DSYNC {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }
    if cb.is_null() {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }
    cabi_aio_submit(cabi_aio_cb(cb), op)
}

#[no_mangle]
pub unsafe extern "C" fn aio_error(cb: *const c_void) -> c_int {
    if cb.is_null() {
        ERRNO = CABI_AIO_EINVAL;
        return CABI_AIO_EINVAL;
    }
    cabi_aio_error_value(cb as *const CabiAioCb)
}

#[no_mangle]
pub unsafe extern "C" fn aio_return(cb: *mut c_void) -> isize {
    if cb.is_null() {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }
    cabi_aio_return_value(cb as *const CabiAioCb)
}

#[no_mangle]
pub unsafe extern "C" fn aio_cancel(fd: c_int, cb: *mut c_void) -> c_int {
    let cb = cb as *mut CabiAioCb;
    if !cb.is_null() && fd != (*cb).aio_fildes {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }

    let check = sys_fcntl(fd, F_GETFD, 0);
    if check < 0 {
        ERRNO = cabi_aio_errno(check);
        return -1;
    }

    // musl initializes errno to ENOENT while looking for the descriptor's
    // queue.  A completed request has no queue left, so preserve that errno
    // while returning AIO_ALLDONE; it is also the value exposed for a queue
    // that remains active but contains no matching request.
    ERRNO = CABI_AIO_ENOENT;

    if cb.is_null() {
        return CABI_AIO_ALLDONE;
    }

    // Immediate completion leaves no worker that can be cancelled.  Retain
    // the not-cancelled result for a genuinely in-progress aiocb supplied by
    // a concurrent caller, and report all-done for every completed request.
    if cabi_aio_error_value(cb) == CABI_AIO_EINPROGRESS {
        CABI_AIO_NOTCANCELED
    } else {
        CABI_AIO_ALLDONE
    }
}

#[inline]
unsafe fn cabi_aio_list_entry(
    list: *const *mut c_void,
    index: usize,
) -> *mut CabiAioCb {
    *list.add(index) as *mut CabiAioCb
}

unsafe fn cabi_aio_valid_timeout(timeout: *const timespec) -> bool {
    timeout.is_null()
        || ((*timeout).tv_sec >= 0 && (*timeout).tv_nsec >= 0 && (*timeout).tv_nsec < 1_000_000_000)
}

#[no_mangle]
pub unsafe extern "C" fn aio_suspend(
    list: *const *const c_void,
    nent: c_int,
    timeout: *const timespec,
) -> c_int {
    if nent < 0 || (nent > 0 && list.is_null()) {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }

    let mut pending = nent == 0;
    let mut i = 0usize;
    while i < nent as usize {
        let cb = *list.add(i) as *const CabiAioCb;
        if !cb.is_null() {
            if cabi_aio_error_value(cb) != CABI_AIO_EINPROGRESS {
                return 0;
            }
            pending = true;
        }
        i += 1;
    }
    if !pending {
        return 0;
    }

    if !cabi_aio_valid_timeout(timeout) {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }

    if timeout.is_null() {
        // With no timeout musl waits until a signal or a real completion.  A
        // submitted request cannot remain pending after our synchronous
        // submit returns, but a concurrent caller can observe the brief
        // EINPROGRESS window, so preserve the blocking contract here.
        let result = sys_pause();
        ERRNO = if result < 0 {
            cabi_aio_errno(result)
        } else {
            CABI_AIO_EINTR
        };
        return -1;
    }

    let result = sys_nanosleep(timeout, core::ptr::null_mut());
    if result < 0 {
        ERRNO = cabi_aio_errno(result);
        return -1;
    }
    // musl maps the timed-wait ETIMEDOUT result to EAGAIN at this API
    // boundary (aio_suspend returns -1 and publishes errno directly).
    ERRNO = CABI_AIO_EAGAIN;
    -1
}

#[no_mangle]
pub unsafe extern "C" fn lio_listio(
    mode: c_int,
    list: *const *mut c_void,
    nent: c_int,
    sevp: *mut c_void,
) -> c_int {
    if (mode != CABI_LIO_WAIT && mode != CABI_LIO_NOWAIT)
        || nent < 0
        || (nent > 0 && list.is_null())
    {
        ERRNO = CABI_AIO_EINVAL;
        return -1;
    }

    let mut i = 0usize;
    while i < nent as usize {
        let cb = cabi_aio_list_entry(list, i);
        if cb.is_null()
            || (*cb).aio_lio_opcode == CABI_LIO_NOP
            // musl treats an unrecognized lio opcode as an ignored entry.
            || ((*cb).aio_lio_opcode != CABI_LIO_READ
                && (*cb).aio_lio_opcode != CABI_LIO_WRITE)
        {
            i += 1;
            continue;
        }
        let result = match (*cb).aio_lio_opcode {
            CABI_LIO_READ => cabi_aio_submit(cb, CABI_LIO_READ),
            CABI_LIO_WRITE => cabi_aio_submit(cb, CABI_LIO_WRITE),
            _ => 0,
        };
        if result < 0 {
            // musl stops submitting at the first request-level failure.
            ERRNO = CABI_AIO_EAGAIN;
            return -1;
        }
        i += 1;
    }

    if mode == CABI_LIO_WAIT {
        // The real musl lio_wait helper returns EIO when any submitted
        // operation completed with an error.  Immediate completion lets us
        // perform the same scan without allocating a wait state.
        let mut operation_error = false;
        let mut j = 0usize;
        while j < nent as usize {
            let cb = cabi_aio_list_entry(list, j);
            if !cb.is_null()
                && ((*cb).aio_lio_opcode == CABI_LIO_READ
                    || (*cb).aio_lio_opcode == CABI_LIO_WRITE)
                && cabi_aio_error_value(cb) != 0
            {
                operation_error = true;
            }
            j += 1;
        }
        if operation_error {
            ERRNO = CABI_AIO_EIO;
            return -1;
        }
        return 0;
    }

    // LIO_NOWAIT delivers the list-level event only after all entries have
    // completed.  Since completion is synchronous here, this is the return
    // boundary.  NULL and SIGEV_NONE both mean no notification.
    if !sevp.is_null() {
        cabi_aio_notify(sevp as *const u8);
    }
    0
}
