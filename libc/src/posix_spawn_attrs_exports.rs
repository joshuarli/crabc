// POSIX spawn attributes and file-action extensions.
//
// The spawn objects themselves are declared in lib.rs with musl's public
// layout.  Attribute accessors therefore copy the complete public sigset_t
// storage (rather than the libc-internal one-word signal mask) and return
// POSIX error numbers directly.  File actions added here use the opaque
// __actions pointer as an ordered heap list; cabi_spawn_apply_linked_actions and
// cabi_spawn_destroy_linked_actions are kept private to this crate so the
// existing spawn child path can apply and release that list.

const CABI_POSIX_SPAWN_VALID_FLAGS: c_int =
    1 | 2 | 4 | 8 | 16 | 32 | 64;

const CABI_SPAWN_ACTION_OPEN: c_int = 0;
const CABI_SPAWN_ACTION_CHDIR: c_int = 1;
const CABI_SPAWN_ACTION_FCHDIR: c_int = 2;


const CABI_SPAWN_SYS_FCHDIR: i64 = 50;

#[repr(C)]
struct CabiSpawnLinkedAction {
    kind: c_int,
    fd: c_int,
    oflag: c_int,
    mode: c_uint,
    path: *mut c_char,
    next: *mut CabiSpawnLinkedAction,
}

#[inline]
unsafe fn cabi_spawn_attr_valid(attr: *const posix_spawnattr_t) -> bool {
    !attr.is_null()
}

#[inline]
unsafe fn cabi_spawn_copy_sigset(dst: *mut c_ulong, src: *const c_ulong) {
    core::ptr::copy_nonoverlapping(src, dst, 16);
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setflags(
    attr: *mut posix_spawnattr_t,
    flags: i16,
) -> c_int {
    if attr.is_null() || (flags as c_int & !CABI_POSIX_SPAWN_VALID_FLAGS) != 0 {
        return EINVAL;
    }
    (*attr).__flags = flags as c_int;
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getflags(
    attr: *const posix_spawnattr_t,
    flags: *mut i16,
) -> c_int {
    if !cabi_spawn_attr_valid(attr) || flags.is_null() {
        return EINVAL;
    }
    *flags = (*attr).__flags as i16;
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setpgroup(
    attr: *mut posix_spawnattr_t,
    pgroup: c_int,
) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    (*attr).__pgrp = pgroup;
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getpgroup(
    attr: *const posix_spawnattr_t,
    pgroup: *mut c_int,
) -> c_int {
    if !cabi_spawn_attr_valid(attr) || pgroup.is_null() {
        return EINVAL;
    }
    *pgroup = (*attr).__pgrp;
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setsigmask(
    attr: *mut posix_spawnattr_t,
    mask: *const c_ulong,
) -> c_int {
    if attr.is_null() || mask.is_null() {
        return EINVAL;
    }
    cabi_spawn_copy_sigset((*attr).__mask.as_mut_ptr(), mask);
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getsigmask(
    attr: *const posix_spawnattr_t,
    mask: *mut c_ulong,
) -> c_int {
    if !cabi_spawn_attr_valid(attr) || mask.is_null() {
        return EINVAL;
    }
    cabi_spawn_copy_sigset(mask, (*attr).__mask.as_ptr());
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setsigdefault(
    attr: *mut posix_spawnattr_t,
    default: *const c_ulong,
) -> c_int {
    if attr.is_null() || default.is_null() {
        return EINVAL;
    }
    cabi_spawn_copy_sigset((*attr).__def.as_mut_ptr(), default);
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getsigdefault(
    attr: *const posix_spawnattr_t,
    default: *mut c_ulong,
) -> c_int {
    if !cabi_spawn_attr_valid(attr) || default.is_null() {
        return EINVAL;
    }
    cabi_spawn_copy_sigset(default, (*attr).__def.as_ptr());
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setschedparam(
    attr: *mut posix_spawnattr_t,
    param: *const sched_param,
) -> c_int {
    if attr.is_null() || param.is_null() {
        return EINVAL;
    }
    (*attr).__prio = (*param).sched_priority;
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getschedparam(
    attr: *const posix_spawnattr_t,
    param: *mut sched_param,
) -> c_int {
    if !cabi_spawn_attr_valid(attr) || param.is_null() {
        return EINVAL;
    }
    (*param).sched_priority = (*attr).__prio;
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setschedpolicy(
    attr: *mut posix_spawnattr_t,
    policy: c_int,
) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    (*attr).__pol = policy;
    0
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getschedpolicy(
    attr: *const posix_spawnattr_t,
    policy: *mut c_int,
) -> c_int {
    if !cabi_spawn_attr_valid(attr) || policy.is_null() {
        return EINVAL;
    }
    *policy = (*attr).__pol;
    0
}

#[inline]
unsafe fn cabi_spawn_action_alloc(
    kind: c_int,
    fd: c_int,
    oflag: c_int,
    mode: c_uint,
    path: *const c_char,
) -> Result<*mut CabiSpawnLinkedAction, c_int> {
    let path_len = if path.is_null() { 0 } else { strlen(path) + 1 };
    if (kind == CABI_SPAWN_ACTION_OPEN || kind == CABI_SPAWN_ACTION_CHDIR)
        && path.is_null()
    {
        return Err(EINVAL);
    }

    let bytes = core::mem::size_of::<CabiSpawnLinkedAction>()
        .checked_add(path_len)
        .ok_or(ENOMEM)?;
    let action = malloc(bytes) as *mut CabiSpawnLinkedAction;
    if action.is_null() {
        return Err(ENOMEM);
    }

    (*action).kind = kind;
    (*action).fd = fd;
    (*action).oflag = oflag;
    (*action).mode = mode;
    (*action).next = core::ptr::null_mut();
    if path_len != 0 {
        (*action).path = action.add(1) as *mut c_char;
        core::ptr::copy_nonoverlapping(path as *const u8, (*action).path as *mut u8, path_len);
    } else {
        (*action).path = core::ptr::null_mut();
    }
    Ok(action)
}

#[inline]
unsafe fn cabi_spawn_action_append(
    fa: *mut posix_spawn_file_actions_t,
    action: *mut CabiSpawnLinkedAction,
) -> c_int {
    if fa.is_null() || action.is_null() {
        return EINVAL;
    }
    let mut tail = (*fa).__actions as *mut CabiSpawnLinkedAction;
    if tail.is_null() {
        (*fa).__actions = action as *mut c_void;
        return 0;
    }
    while !(*tail).next.is_null() {
        tail = (*tail).next;
    }
    (*tail).next = action;
    0
}

#[inline]
unsafe fn cabi_spawn_action_add(
    fa: *mut posix_spawn_file_actions_t,
    kind: c_int,
    fd: c_int,
    oflag: c_int,
    mode: c_uint,
    path: *const c_char,
) -> c_int {
    if fa.is_null() {
        return EINVAL;
    }
    let action = match cabi_spawn_action_alloc(kind, fd, oflag, mode, path) {
        Ok(action) => action,
        Err(error) => return error,
    };
    let result = cabi_spawn_action_append(fa, action);
    if result != 0 {
        free(action as *mut c_void);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addopen(
    fa: *mut posix_spawn_file_actions_t,
    fd: c_int,
    path: *const c_char,
    oflag: c_int,
    mode: c_uint,
) -> c_int {
    cabi_spawn_action_add(fa, CABI_SPAWN_ACTION_OPEN, fd, oflag, mode, path)
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(
    fa: *mut posix_spawn_file_actions_t,
    path: *const c_char,
) -> c_int {
    cabi_spawn_action_add(fa, CABI_SPAWN_ACTION_CHDIR, -1, 0, 0, path)
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addfchdir_np(
    fa: *mut posix_spawn_file_actions_t,
    fd: c_int,
) -> c_int {
    cabi_spawn_action_add(
        fa,
        CABI_SPAWN_ACTION_FCHDIR,
        fd,
        0,
        0,
        core::ptr::null(),
    )
}

// Called by the spawn child path after its existing inline close/dup2 list.
// It returns the positive errno required by posix_spawn's child setup path;
// the caller decides how to report that error to the parent.
unsafe fn cabi_spawn_apply_linked_actions(
    fa: *const posix_spawn_file_actions_t,
) -> c_int {
    if fa.is_null() {
        return 0;
    }
    let mut action = (*fa).__actions as *mut CabiSpawnLinkedAction;
    while !action.is_null() {
        let result = match (*action).kind {
            CABI_SPAWN_ACTION_OPEN => {
                let opened = sys_open(
                    (*action).path as *const u8,
                    (*action).oflag as i64,
                    (*action).mode as i64,
                );
                if opened < 0 {
                    (-opened) as c_int
                } else {
                    let duplicated = if opened as c_int == (*action).fd {
                        0
                    } else {
                        sys_dup2(opened as c_int, (*action).fd)
                    };
                    if opened as c_int != (*action).fd {
                        let _ = sys_close(opened);
                    }
                    if duplicated < 0 {
                        (-duplicated) as c_int
                    } else {
                        0
                    }
                }
            }
            CABI_SPAWN_ACTION_CHDIR => {
                let result = sys_chdir((*action).path as *const u8);
                if result < 0 { (-result) as c_int } else { 0 }
            }
            CABI_SPAWN_ACTION_FCHDIR => {
                let result = aarch64_syscall::syscall1(CABI_SPAWN_SYS_FCHDIR, (*action).fd as i64);
                if result < 0 { (-result) as c_int } else { 0 }
            }
            _ => EINVAL,
        };
        if result != 0 {
            return result;
        }
        action = (*action).next;
    }
    0
}

unsafe fn cabi_spawn_destroy_linked_actions(fa: *mut posix_spawn_file_actions_t) {
    if fa.is_null() {
        return;
    }
    let mut action = (*fa).__actions as *mut CabiSpawnLinkedAction;
    while !action.is_null() {
        let next = (*action).next;
        free(action as *mut c_void);
        action = next;
    }
    (*fa).__actions = core::ptr::null_mut();
}
