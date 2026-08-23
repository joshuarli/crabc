// C11 threads entry points backed by the existing pthread and TLS machinery.
//
// The musl C11 types are ABI-compatible aliases of their pthread counterparts
// on the targets supported by this crate.  Keep the adapters explicit here:
// pthread APIs return errno values, while C11 mutex/condition APIs return the
// small thrd_* status enum and have a few void-returning destruction APIs.

const C11_THRD_SUCCESS: c_int = 0;
const C11_THRD_BUSY: c_int = 1;
const C11_THRD_ERROR: c_int = 2;
const C11_THRD_NOMEM: c_int = 3;
const C11_THRD_TIMEDOUT: c_int = 4;

// musl's <threads.h> uses zero for plain mutexes; recursive and timed are
// independent bits that may be combined (1 | 2).
const C11_MTX_PLAIN: c_int = 0x0;
const C11_MTX_RECURSIVE: c_int = 0x1;
const C11_MTX_TIMED: c_int = 0x2;

type c11_thrd_start_t = unsafe extern "C" fn(*mut c_void) -> c_int;
type c11_tss_dtor_t = unsafe extern "C" fn(*mut c_void);
type c11_once_func_t = unsafe extern "C" fn();

#[inline]
fn c11_pthread_result(ret: c_int) -> c_int {
    match ret {
        0 => C11_THRD_SUCCESS,
        ENOMEM => C11_THRD_NOMEM,
        _ => C11_THRD_ERROR,
    }
}

#[inline]
fn c11_mutex_result(ret: c_int) -> c_int {
    match ret {
        0 => C11_THRD_SUCCESS,
        EBUSY => C11_THRD_BUSY,
        _ => C11_THRD_ERROR,
    }
}

#[inline]
fn c11_timed_result(ret: c_int) -> c_int {
    match ret {
        0 => C11_THRD_SUCCESS,
        ETIMEDOUT => C11_THRD_TIMEDOUT,
        _ => C11_THRD_ERROR,
    }
}

#[no_mangle]
pub unsafe extern "C" fn thrd_create(
    thread: *mut PthreadT,
    func: Option<c11_thrd_start_t>,
    arg: *mut c_void,
) -> c_int {
    // C11's callback returns int while pthread_create's callback is represented
    // by the same one-word return register on the supported ABIs.  musl uses
    // this ABI-compatible cast directly, preserving the int through join.
    let start = func.map(|f| f as usize).unwrap_or(0);
    match pthread_create(thread, core::ptr::null(), start, arg) {
        0 => C11_THRD_SUCCESS,
        EAGAIN => C11_THRD_NOMEM,
        _ => C11_THRD_ERROR,
    }
}

#[no_mangle]
pub unsafe extern "C" fn thrd_join(thread: PthreadT, result: *mut c_int) -> c_int {
    let mut pthread_result: *mut c_void = core::ptr::null_mut();
    let ret = pthread_join(thread, &mut pthread_result);
    if ret != 0 {
        return C11_THRD_ERROR;
    }
    if !result.is_null() {
        *result = (pthread_result as isize) as c_int;
    }
    C11_THRD_SUCCESS
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn thrd_detach(thread: PthreadT) -> c_int {
    c11_pthread_result(pthread_detach(thread))
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn thrd_current() -> PthreadT {
    pthread_self()
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn thrd_equal(left: PthreadT, right: PthreadT) -> c_int {
    pthread_equal(left, right)
}

#[no_mangle]
pub unsafe extern "C" fn thrd_exit(result: c_int) -> ! {
    pthread_exit((result as isize) as *mut c_void)
}

// Linux sched_yield syscall numbers (the libc tree does not yet export the
// POSIX sched_yield wrapper, so use the same raw syscall abstraction directly).
const C11_SYS_SCHED_YIELD: i64 = 124;

#[no_mangle]
pub unsafe extern "C" fn thrd_yield() {
    let _ = aarch64_syscall::syscall0(C11_SYS_SCHED_YIELD);
}

#[no_mangle]
pub unsafe extern "C" fn thrd_sleep(
    duration: *const timespec,
    remaining: *mut timespec,
) -> c_int {
    // C11 specifies -1 for interruption and -2 for all other failures.  The
    // clock_nanosleep wrapper returns the errno value directly on failure.
    match clock_nanosleep(CLOCK_REALTIME, 0, duration, remaining) {
        0 => 0,
        EINTR => -1,
        _ => -2,
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtx_init(mutex: *mut pthread_mutex_t, kind: c_int) -> c_int {
    if kind & !(C11_MTX_PLAIN | C11_MTX_RECURSIVE | C11_MTX_TIMED) != 0 {
        return C11_THRD_ERROR;
    }

    if kind & C11_MTX_RECURSIVE == 0 {
        return c11_pthread_result(pthread_mutex_init(mutex, core::ptr::null()));
    }

    let mut attr: pthread_mutexattr_t = core::mem::zeroed();
    let ret = pthread_mutexattr_init(&mut attr);
    if ret != 0 {
        return C11_THRD_ERROR;
    }
    let ret = pthread_mutexattr_settype(&mut attr, PTHREAD_MUTEX_RECURSIVE);
    if ret == 0 {
        let init_ret = pthread_mutex_init(mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);
        c11_pthread_result(init_ret)
    } else {
        pthread_mutexattr_destroy(&mut attr);
        C11_THRD_ERROR
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtx_destroy(mutex: *mut pthread_mutex_t) {
    let _ = pthread_mutex_destroy(mutex);
}

#[no_mangle]
pub unsafe extern "C" fn mtx_lock(mutex: *mut pthread_mutex_t) -> c_int {
    c11_pthread_result(pthread_mutex_lock(mutex))
}

#[no_mangle]
pub unsafe extern "C" fn mtx_trylock(mutex: *mut pthread_mutex_t) -> c_int {
    c11_mutex_result(pthread_mutex_trylock(mutex))
}

#[no_mangle]
pub unsafe extern "C" fn mtx_timedlock(
    mutex: *mut pthread_mutex_t,
    abstime: *const timespec,
) -> c_int {
    c11_timed_result(pthread_mutex_timedlock(mutex, abstime))
}

#[no_mangle]
pub unsafe extern "C" fn mtx_unlock(mutex: *mut pthread_mutex_t) -> c_int {
    c11_pthread_result(pthread_mutex_unlock(mutex))
}

#[no_mangle]
pub unsafe extern "C" fn cnd_init(condition: *mut pthread_cond_t) -> c_int {
    c11_pthread_result(pthread_cond_init(condition, core::ptr::null()))
}

#[no_mangle]
pub unsafe extern "C" fn cnd_destroy(condition: *mut pthread_cond_t) {
    let _ = pthread_cond_destroy(condition);
}

#[no_mangle]
pub unsafe extern "C" fn cnd_wait(
    condition: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
) -> c_int {
    c11_pthread_result(pthread_cond_wait(condition, mutex))
}

#[no_mangle]
pub unsafe extern "C" fn cnd_timedwait(
    condition: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    abstime: *const timespec,
) -> c_int {
    c11_timed_result(pthread_cond_timedwait(condition, mutex, abstime))
}

#[no_mangle]
pub unsafe extern "C" fn cnd_signal(condition: *mut pthread_cond_t) -> c_int {
    c11_pthread_result(pthread_cond_signal(condition))
}

#[no_mangle]
pub unsafe extern "C" fn cnd_broadcast(condition: *mut pthread_cond_t) -> c_int {
    c11_pthread_result(pthread_cond_broadcast(condition))
}

#[no_mangle]
pub unsafe extern "C" fn call_once(
    flag: *mut pthread_once_t,
    function: Option<c11_once_func_t>,
) {
    let _ = pthread_once(flag, function);
}

#[no_mangle]
pub unsafe extern "C" fn tss_create(
    key: *mut pthread_key_t,
    destructor: Option<c11_tss_dtor_t>,
) -> c_int {
    c11_pthread_result(pthread_key_create(key, destructor))
}

#[no_mangle]
pub unsafe extern "C" fn tss_delete(key: pthread_key_t) {
    let _ = pthread_key_delete(key);
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn tss_get(key: pthread_key_t) -> *mut c_void {
    pthread_getspecific(key)
}

#[no_mangle]
pub unsafe extern "C" fn tss_set(key: pthread_key_t, value: *mut c_void) -> c_int {
    c11_pthread_result(pthread_setspecific(key, value))
}
