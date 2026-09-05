use super::*;
use super::super::x86_64_runtime_lock::{isolated_mapping_probe, RuntimeGuard};

#[test]
fn library_search_secure_auxv_disables_environment_and_untrusted_origin() {
    unsafe fn probe(_: &RuntimeGuard) -> bool {
        let environment = b"LD_LIBRARY_PATH=/application\0";
        // argc, argv terminator, environ, terminator, UID/EUID/GID/EGID,
        // AT_SECURE, auxv terminator. Each case owns its complete stack.
        let mut stack = [0, 0, environment.as_ptr() as usize, 0,
            11, 1000, 12, 1000, 13, 1000, 14, 1000, 23, 0, 0, 0];
        unsafe { initialize(stack.as_ptr() as usize); }
        if unsafe { SECURE || ENVIRONMENT_PATH.is_null() } { return false; }
        stack[13] = 1;
        unsafe { initialize(stack.as_ptr() as usize); }
        if unsafe { !SECURE || !ENVIRONMENT_PATH.is_null() } { return false; }
        stack[13] = 0;
        stack[7] = 0;
        unsafe { initialize(stack.as_ptr() as usize); }
        if unsafe { !SECURE || !ENVIRONMENT_PATH.is_null() } { return false; }
        let path = b"$ORIGIN/sub\0";
        let mut object = Object { role: ObjectRole::Library, runpath: path.as_ptr(), runpath_len: path.len() - 1, ..EMPTY_OBJECT };
        object.search_name[..9].copy_from_slice(b"relative\0");
        let mut expanded = [0; PATH_CAPACITY];
        if unsafe { object_paths(&object, &mut expanded) } != Ok(0) { return false; }
        object.search_name[..12].copy_from_slice(b"/app/lib.so\0");
        let length = unsafe { object_paths(&object, &mut expanded) }.unwrap_or(0);
        if &expanded[..length] != b"/app/sub" { return false; }
        object.search_name[..8].copy_from_slice(b"/lib.so\0");
        let length = unsafe { object_paths(&object, &mut expanded) }.unwrap_or(0);
        &expanded[..length] == b"/sub"
    }
    unsafe { isolated_mapping_probe(probe); }
}

#[test]
fn library_search_unknown_expansion_discards_whole_object_path() {
    unsafe fn probe(_: &RuntimeGuard) -> bool {
        let path = b"/otherwise/valid:$LIB/plugins\0";
        let object = Object { role: ObjectRole::Library, runpath: path.as_ptr(), runpath_len: path.len() - 1, ..EMPTY_OBJECT };
        unsafe { object_paths(&object, &mut [0; PATH_CAPACITY]) == Ok(0) }
    }
    unsafe { isolated_mapping_probe(probe); }
}
