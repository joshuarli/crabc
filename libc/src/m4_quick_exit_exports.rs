// M4 C11 quick-exit support.
//
// Quick-exit handlers are deliberately separate from the `atexit` chain:
// `quick_exit` runs them in reverse registration order and then terminates
// without flushing stdio or invoking ordinary exit handlers.

use core::sync::atomic::AtomicPtr;

struct M4QuickExitNode {
    next: *mut M4QuickExitNode,
    callback: unsafe extern "C" fn(),
}

static M4_QUICK_EXIT_HEAD: AtomicPtr<M4QuickExitNode> = AtomicPtr::new(core::ptr::null_mut());

#[no_mangle]
pub unsafe extern "C" fn at_quick_exit(callback: Option<unsafe extern "C" fn()>) -> c_int {
    let Some(callback) = callback else {
        ERRNO = EINVAL;
        return -1;
    };
    let node = malloc(core::mem::size_of::<M4QuickExitNode>()) as *mut M4QuickExitNode;
    if node.is_null() {
        return -1;
    }
    (*node).callback = callback;
    loop {
        let head = M4_QUICK_EXIT_HEAD.load(Ordering::Acquire);
        (*node).next = head;
        if M4_QUICK_EXIT_HEAD
            .compare_exchange_weak(head, node, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            return 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn quick_exit(status: c_int) -> ! {
    let mut node = M4_QUICK_EXIT_HEAD.swap(core::ptr::null_mut(), Ordering::AcqRel);
    while !node.is_null() {
        let next = (*node).next;
        let callback = (*node).callback;
        free(node as *mut c_void);
        callback();
        node = next;
    }
    _Exit(status)
}
