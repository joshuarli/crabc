// non-portable pthread extensions.
//
// These are the Linux/GNU interfaces which are not part of the core pthread
// implementation.  pthread error returns are deliberately returned directly
// (rather than through errno), matching musl's ABI and the POSIX pthread API.
// This file is included by libc/src/lib.rs after the pthread data structures
// and helpers have been defined.

const CABI_PTHREAD_DEFAULT_STACK_MAX: usize = 8 * 1024 * 1024;
const CABI_PTHREAD_DEFAULT_GUARD_MAX: usize = 1024 * 1024;
const CABI_PTHREAD_DEFAULT_STACK_SIZE: usize = STACK_SIZE;
const CABI_PTHREAD_DEFAULT_GUARD_SIZE: usize = 4096;
const CABI_PTHREAD_EIO: c_int = 5;
const CABI_PTHREAD_ERANGE: c_int = 34;
const CABI_PTHREAD_ENAMETOOLONG: c_int = 36;
const CABI_PTHREAD_ESRCH: c_int = 3;

// The existing pthread_attr_t uses the x86_64 musl field positions.  Keep the
// offsets named here so this extension does not depend on a C-only union
// layout or accidentally turn an ABI field into a Rust implementation detail.
const CABI_ATTR_STACK_SIZE: usize = 0;
const CABI_ATTR_GUARD_SIZE: usize = 2;
const CABI_ATTR_STACK_ADDR: usize = 4;
const CABI_ATTR_DETACH: usize = 6;
const CABI_ATTR_INHERIT_SCHED: usize = 7;
const CABI_ATTR_POLICY: usize = 8;
const CABI_ATTR_PRIORITY: usize = 9;

static CABI_DEFAULT_STACK_SIZE: AtomicUsize = AtomicUsize::new(CABI_PTHREAD_DEFAULT_STACK_SIZE);
static CABI_DEFAULT_GUARD_SIZE: AtomicUsize = AtomicUsize::new(CABI_PTHREAD_DEFAULT_GUARD_SIZE);

// pthread_attr_init in the pre-implementation currently has its defaults
// inlined.  The parent integration should use these accessors there so
// pthread_setattr_default_np affects subsequently-created attributes too.
#[inline]
fn cabi_pthread_default_stack_size() -> usize {
    CABI_DEFAULT_STACK_SIZE.load(Ordering::Acquire)
}

#[inline]
fn cabi_pthread_default_guard_size() -> usize {
    CABI_DEFAULT_GUARD_SIZE.load(Ordering::Acquire)
}

#[inline]
unsafe fn cabi_pthread_attr_zero_except_sizes(attr: *const pthread_attr_t) -> bool {
    let fields = &(*attr).__i;
    for i in 0..fields.len() {
        if i != CABI_ATTR_STACK_SIZE && i != CABI_ATTR_GUARD_SIZE && fields[i] != 0 {
            return false;
        }
    }
    true
}

#[inline]
unsafe fn cabi_pthread_attr_set_sizes(attr: *mut pthread_attr_t, stack_size: usize, guard_size: usize) {
    *((*attr).__i.as_mut_ptr() as *mut usize) = stack_size;
    *((*attr).__i.as_mut_ptr().add(CABI_ATTR_GUARD_SIZE) as *mut usize) = guard_size;
}

#[inline]
unsafe fn cabi_pthread_attr_stack_size(attr: *const pthread_attr_t) -> usize {
    *((*attr).__i.as_ptr() as *const usize)
}

#[inline]
unsafe fn cabi_pthread_attr_guard_size(attr: *const pthread_attr_t) -> usize {
    *((*attr).__i.as_ptr().add(CABI_ATTR_GUARD_SIZE) as *const usize)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getattr_default_np(attr: *mut pthread_attr_t) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    core::ptr::write_bytes(attr, 0, 1);
    cabi_pthread_attr_set_sizes(
        attr,
        cabi_pthread_default_stack_size(),
        cabi_pthread_default_guard_size(),
    );
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_setattr_default_np(attr: *const pthread_attr_t) -> c_int {
    if attr.is_null() || !cabi_pthread_attr_zero_except_sizes(attr) {
        return EINVAL;
    }

    // musl permits callers to request a larger default, caps the request, and
    // never lowers an already-selected process default.
    let stack_size = core::cmp::min(cabi_pthread_attr_stack_size(attr), CABI_PTHREAD_DEFAULT_STACK_MAX);
    let guard_size = core::cmp::min(cabi_pthread_attr_guard_size(attr), CABI_PTHREAD_DEFAULT_GUARD_MAX);
    loop {
        let old = CABI_DEFAULT_STACK_SIZE.load(Ordering::Acquire);
        let new = core::cmp::max(old, stack_size);
        if CABI_DEFAULT_STACK_SIZE
            .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    loop {
        let old = CABI_DEFAULT_GUARD_SIZE.load(Ordering::Acquire);
        let new = core::cmp::max(old, guard_size);
        if CABI_DEFAULT_GUARD_SIZE
            .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    0
}

#[inline]
unsafe fn cabi_pthread_slot_in_range(thread: PthreadT) -> Option<*mut Thread> {
    if thread == 0 {
        return None;
    }
    let first = core::ptr::addr_of_mut!(THREADS[0]) as usize;
    let slot_size = core::mem::size_of::<Thread>();
    let last = first + slot_size * MAX_THREADS;
    let address = thread as usize;
    if address < first || address >= last || (address - first) % slot_size != 0 {
        return None;
    }
    Some(thread as *mut Thread)
}

#[inline]
unsafe fn cabi_pthread_live_tid(thread: PthreadT) -> Result<( *mut Thread, c_int), c_int> {
    let Some(slot) = cabi_pthread_slot_in_range(thread) else {
        return Err(CABI_PTHREAD_ESRCH);
    };
    let tid = core::ptr::read_volatile(core::ptr::addr_of!((*slot).tid));
    if tid <= 0 {
        Err(CABI_PTHREAD_ESRCH)
    } else {
        Ok((slot, tid))
    }
}

#[inline]
unsafe fn cabi_pthread_join_slot(thread: PthreadT) -> Result<*mut Thread, c_int> {
    let Some(slot) = cabi_pthread_slot_in_range(thread) else {
        return Err(EINVAL);
    };
    let tid = core::ptr::read_volatile(core::ptr::addr_of!((*slot).tid));
    let state = core::ptr::read_volatile(core::ptr::addr_of!((*slot).detach_state));
    // A live slot, or an exited joinable slot whose resources have not yet
    // been reclaimed, is a valid target.  pthread_join changes tid to -1
    // after reclaiming it, making stale handles fail on the next call.
    if tid > 0 || (state == DT_EXITED && !(*slot).stack.is_null()) {
        Ok(slot)
    } else {
        Err(EINVAL)
    }
}

#[inline]
unsafe fn cabi_pthread_append_decimal(path: &mut [u8], at: &mut usize, value: c_int) -> bool {
    if value < 0 {
        return false;
    }
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    let mut n = value as u32;
    if n == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while n != 0 {
            digits[count] = b'0' + (n % 10) as u8;
            count += 1;
            n /= 10;
        }
    }
    if *at + count >= path.len() {
        return false;
    }
    while count != 0 {
        count -= 1;
        path[*at] = digits[count];
        *at += 1;
    }
    true
}

#[inline]
unsafe fn cabi_pthread_comm_path(tid: c_int, path: &mut [u8; 64]) -> bool {
    let prefix = b"/proc/self/task/";
    let suffix = b"/comm";
    let mut at = 0usize;
    for byte in prefix {
        path[at] = *byte;
        at += 1;
    }
    if !cabi_pthread_append_decimal(path, &mut at, tid) {
        return false;
    }
    for byte in suffix {
        if at >= path.len() {
            return false;
        }
        path[at] = *byte;
        at += 1;
    }
    if at >= path.len() {
        return false;
    }
    path[at] = 0;
    true
}

#[inline]
unsafe fn cabi_pthread_name_length(name: *const c_char) -> Result<usize, c_int> {
    if name.is_null() {
        return Err(EINVAL);
    }
    let bytes = name as *const u8;
    for length in 0..16usize {
        if *bytes.add(length) == 0 {
            return Ok(length);
        }
    }
    Err(CABI_PTHREAD_ERANGE)
}


const CABI_PTHREAD_SYS_PRCTL: i64 = 167;

const CABI_PTHREAD_PR_SET_NAME: i64 = 15;
const CABI_PTHREAD_PR_GET_NAME: i64 = 16;
const CABI_PTHREAD_O_RDONLY: c_int = 0;
const CABI_PTHREAD_O_WRONLY: c_int = 1;
const CABI_PTHREAD_O_CLOEXEC: c_int = 0x80000;

#[inline]
unsafe fn cabi_pthread_prctl_name(option: i64, name: *mut c_char) -> c_int {
    let result = aarch64_syscall::syscall5(
        CABI_PTHREAD_SYS_PRCTL,
        option,
        name as i64,
        0,
        0,
        0,
    );
    if result < 0 && result >= -4095 {
        (-result) as c_int
    } else if result < 0 {
        EINVAL
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_setname_np(thread: PthreadT, name: *const c_char) -> c_int {
    let length = match cabi_pthread_name_length(name) {
        Ok(length) if length <= 15 => length,
        Ok(_) | Err(CABI_PTHREAD_ERANGE) => return CABI_PTHREAD_ERANGE,
        Err(error) => return error,
    };
    let (_, tid) = match cabi_pthread_live_tid(thread) {
        Ok(value) => value,
        Err(error) => return error,
    };

    if thread == pthread_self() {
        return cabi_pthread_prctl_name(CABI_PTHREAD_PR_SET_NAME, name as *mut c_char);
    }

    let mut path = [0u8; 64];
    if !cabi_pthread_comm_path(tid, &mut path) {
        return CABI_PTHREAD_ENAMETOOLONG;
    }
    let fd = sys_open(path.as_ptr(), (CABI_PTHREAD_O_WRONLY | CABI_PTHREAD_O_CLOEXEC) as i64, 0);
    if fd < 0 {
        return (-fd) as c_int;
    }
    let result = sys_write(fd, name as *const u8, length);
    let close_result = sys_close(fd);
    if result < 0 {
        (-result) as c_int
    } else if close_result < 0 {
        (-close_result) as c_int
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getname_np(
    thread: PthreadT,
    name: *mut c_char,
    length: usize,
) -> c_int {
    if length < 16 {
        return CABI_PTHREAD_ERANGE;
    }
    if name.is_null() {
        return EINVAL;
    }
    let (_, tid) = match cabi_pthread_live_tid(thread) {
        Ok(value) => value,
        Err(error) => return error,
    };

    if thread == pthread_self() {
        return cabi_pthread_prctl_name(CABI_PTHREAD_PR_GET_NAME, name);
    }

    let mut path = [0u8; 64];
    if !cabi_pthread_comm_path(tid, &mut path) {
        return CABI_PTHREAD_ENAMETOOLONG;
    }
    let fd = sys_open(path.as_ptr(), (CABI_PTHREAD_O_RDONLY | CABI_PTHREAD_O_CLOEXEC) as i64, 0);
    if fd < 0 {
        return (-fd) as c_int;
    }
    let result = sys_read(fd, name as *mut u8, length);
    let close_result = sys_close(fd);
    if result < 0 {
        return (-result) as c_int;
    }
    if close_result < 0 {
        return (-close_result) as c_int;
    }
    if result == 0 {
        return CABI_PTHREAD_EIO;
    }
    let count = result as usize;
    let end = if * (name as *const u8).add(count - 1) == b'\n' {
        count - 1
    } else {
        count
    };
    if end < length {
        *(name as *mut u8).add(end) = 0;
    } else {
        *(name as *mut u8).add(length - 1) = 0;
    }
    0
}

// /proc/self/maps is used only for the main thread, for which the compact
// Thread record has no stack mapping.  Worker threads use their exact mmap
// range recorded in Thread by pthread_create.
unsafe fn cabi_pthread_main_stack(attr: *mut pthread_attr_t) -> c_int {
    let path = b"/proc/self/maps\0";
    let fd = sys_open(path.as_ptr(), CABI_PTHREAD_O_RDONLY as i64, 0);
    if fd < 0 {
        return (-fd) as c_int;
    }
    let mut bytes = [0u8; 8192];
    let count = sys_read(fd, bytes.as_mut_ptr(), bytes.len());
    let _ = sys_close(fd);
    if count <= 0 {
        return if count < 0 { (-count) as c_int } else { CABI_PTHREAD_EIO };
    }
    let count = count as usize;
    let marker = b"[stack]";
    let mut line = 0usize;
    while line < count {
        let mut end = line;
        while end < count && bytes[end] != b'\n' {
            end += 1;
        }
        if end >= marker.len() {
            let marker_start = end - marker.len();
            if bytes[marker_start..end] == *marker {
                let mut split = line;
                while split < end && bytes[split] != b'-' {
                    split += 1;
                }
                if split > line && split + 1 < end {
                    let mut start = 0usize;
                    let mut i = line;
                    while i < split {
                        let digit = match bytes[i] {
                            b'0'..=b'9' => bytes[i] - b'0',
                            b'a'..=b'f' => bytes[i] - b'a' + 10,
                            b'A'..=b'F' => bytes[i] - b'A' + 10,
                            _ => break,
                        };
                        start = (start << 4) | digit as usize;
                        i += 1;
                    }
                    let mut finish = 0usize;
                    i = split + 1;
                    while i < end && bytes[i] != b' ' {
                        let digit = match bytes[i] {
                            b'0'..=b'9' => bytes[i] - b'0',
                            b'a'..=b'f' => bytes[i] - b'a' + 10,
                            b'A'..=b'F' => bytes[i] - b'A' + 10,
                            _ => break,
                        };
                        finish = (finish << 4) | digit as usize;
                        i += 1;
                    }
                    if finish > start {
                        cabi_pthread_attr_set_sizes(attr, finish - start, cabi_pthread_default_guard_size());
                        *((*attr).__i.as_mut_ptr().add(CABI_ATTR_STACK_ADDR) as *mut usize) = start;
                        (*attr).__i[CABI_ATTR_DETACH] = PTHREAD_CREATE_JOINABLE;
                        return 0;
                    }
                }
            }
        }
        line = if end < count { end + 1 } else { count };
    }
    CABI_PTHREAD_EIO
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getattr_np(
    thread: PthreadT,
    attr: *mut pthread_attr_t,
) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    let Some(slot) = cabi_pthread_slot_in_range(thread) else {
        return CABI_PTHREAD_ESRCH;
    };
    let tid = core::ptr::read_volatile(core::ptr::addr_of!((*slot).tid));
    if tid <= 0 {
        return CABI_PTHREAD_ESRCH;
    }
    core::ptr::write_bytes(attr, 0, 1);
    if (*slot).stack.is_null() {
        return cabi_pthread_main_stack(attr);
    }
    cabi_pthread_attr_set_sizes(attr, (*slot).stack_size, cabi_pthread_default_guard_size());
    *((*attr).__i.as_mut_ptr().add(CABI_ATTR_STACK_ADDR) as *mut usize) = (*slot).stack as usize;
    let detach_state = a_load(&raw const (*slot).detach_state);
    (*attr).__i[CABI_ATTR_DETACH] = if detach_state_kind(detach_state) >= DT_DETACHED {
        PTHREAD_CREATE_DETACHED
    } else {
        PTHREAD_CREATE_JOINABLE
    };
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getconcurrency() -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_setconcurrency(value: c_int) -> c_int {
    if value < 0 {
        EINVAL
    } else if value > 0 {
        EAGAIN
    } else {
        0
    }
}





const CABI_PTHREAD_SYS_SCHED_SETPARAM: i64 = 142;
const CABI_PTHREAD_SYS_SCHED_GETPARAM: i64 = 143;
const CABI_PTHREAD_SYS_SCHED_SETSCHEDULER: i64 = 144;
const CABI_PTHREAD_SYS_SCHED_GETSCHEDULER: i64 = 145;

#[inline]
fn cabi_pthread_syscall_errno(result: i64) -> c_int {
    if result < 0 && result >= -4095 {
        (-result) as c_int
    } else if result < 0 {
        EINVAL
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getschedparam(
    thread: PthreadT,
    policy: *mut c_int,
    param: *mut sched_param,
) -> c_int {
    if policy.is_null() || param.is_null() {
        return EINVAL;
    }
    let (_, tid) = match cabi_pthread_live_tid(thread) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let result = aarch64_syscall::syscall2(CABI_PTHREAD_SYS_SCHED_GETPARAM, tid as i64, param as i64);
    let error = cabi_pthread_syscall_errno(result);
    if error != 0 {
        return error;
    }
    let scheduler = aarch64_syscall::syscall1(CABI_PTHREAD_SYS_SCHED_GETSCHEDULER, tid as i64);
    let error = cabi_pthread_syscall_errno(scheduler);
    if error != 0 {
        return error;
    }
    *policy = scheduler as c_int;
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_setschedparam(
    thread: PthreadT,
    policy: c_int,
    param: *const sched_param,
) -> c_int {
    let (_, tid) = match cabi_pthread_live_tid(thread) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let result = aarch64_syscall::syscall3(
        CABI_PTHREAD_SYS_SCHED_SETSCHEDULER,
        tid as i64,
        policy as i64,
        param as i64,
    );
    cabi_pthread_syscall_errno(result)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_setschedprio(thread: PthreadT, priority: c_int) -> c_int {
    let (_, tid) = match cabi_pthread_live_tid(thread) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let param = sched_param { sched_priority: priority };
    let result = aarch64_syscall::syscall2(
        CABI_PTHREAD_SYS_SCHED_SETPARAM,
        tid as i64,
        &param as *const sched_param as i64,
    );
    cabi_pthread_syscall_errno(result)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_getprioceiling(
    _mutex: *const pthread_mutex_t,
    _ceiling: *mut c_int,
) -> c_int {
    // musl has no priority-protect mutex implementation and intentionally
    // reports this operation as invalid rather than claiming success.
    EINVAL
}

#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_setprioceiling(
    _mutex: *mut pthread_mutex_t,
    _ceiling: c_int,
    _old_ceiling: *mut c_int,
) -> c_int {
    EINVAL
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn pthread_tryjoin_np(thread: PthreadT, retval: *mut *mut c_void) -> c_int {
    let slot = match cabi_pthread_join_slot(thread) {
        Ok(slot) => slot,
        Err(error) => return error,
    };
    let state = a_load(&raw const (*slot).detach_state);
    if detach_state_kind(state) == DT_JOINABLE {
        return EBUSY;
    }
    if detach_state_kind(state) == DT_DETACHED {
        return EINVAL;
    }
    pthread_join(thread, retval)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn pthread_timedjoin_np(
    thread: PthreadT,
    retval: *mut *mut c_void,
    abstime: *const timespec,
) -> c_int {
    let slot = match cabi_pthread_join_slot(thread) {
        Ok(slot) => slot,
        Err(error) => return error,
    };
    let mut state = match mark_timed_join_waiter(slot) {
        Ok(state) => state,
        Err(error) => return error,
    };
    while state != DT_EXITED {
        let expected = state;
        let error = futex_timedwait(&raw mut (*slot).detach_state, expected, abstime);
        if error != 0 {
            return error;
        }
        state = a_load(&raw const (*slot).detach_state);
    }
    pthread_join(thread, retval)
}
