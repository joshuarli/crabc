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
        let expand = |name: &[u8], expected: Option<&[u8]>| -> bool {
            let Some(name) = LoadedName::new(name) else { return false; };
            let object = Object { role: ObjectRole::Library, runpath: path.as_ptr(), runpath_len: path.len() - 1,
                search_name: name.view(), ..EMPTY_OBJECT };
            match (unsafe { object_paths(&object) }, expected) {
                (Ok(ObjectPaths::None), None) => true,
                (Ok(paths @ ObjectPaths::Expanded(_)), Some(expected)) => paths.bytes() == expected,
                _ => false,
            }
        };
        expand(b"relative", None) && expand(b"/app/lib.so", Some(b"/app/sub")) && expand(b"/lib.so", Some(b"/sub"))
    }
    unsafe { isolated_mapping_probe(probe); }
}

#[test]
fn library_search_unknown_expansion_discards_whole_object_path() {
    unsafe fn probe(_: &RuntimeGuard) -> bool {
        let path = b"/otherwise/valid:$LIB/plugins\0";
        let object = Object { role: ObjectRole::Library, runpath: path.as_ptr(), runpath_len: path.len() - 1, ..EMPTY_OBJECT };
        matches!(unsafe { object_paths(&object) }, Ok(ObjectPaths::None))
    }
    unsafe { isolated_mapping_probe(probe); }
}

#[test]
fn library_search_origin_expansion_is_sized_to_a_deep_origin() {
    unsafe fn probe(_: &RuntimeGuard) -> bool {
        unsafe { SECURE = false; }
        // Three expansions of a 2999-byte directory exceed PATH_MAX.
        let mut name = [b'd'; 3010];
        for index in (0..2999).step_by(200) { name[index] = b'/'; }
        name[2999] = b'/';
        let path = b"$ORIGIN:${ORIGIN}/x:/short:$ORIGIN\0";
        let Some(stored) = LoadedName::new(&name) else { return false; };
        let object = Object { role: ObjectRole::Library, runpath: path.as_ptr(), runpath_len: path.len() - 1,
            search_name: stored.view(), ..EMPTY_OBJECT };
        let Ok(paths @ ObjectPaths::Expanded(_)) = (unsafe { object_paths(&object) }) else { return false; };
        let origin = &name[..2999];
        let bytes = paths.bytes();
        let mut expected = [0u8; 3 * 2999 + 11];
        let mut used = 0;
        for part in [origin, b":", origin, b"/x:/short:", origin] {
            expected[used..used + part.len()].copy_from_slice(part);
            used += part.len();
        }
        used == expected.len() && bytes == &expected[..]
    }
    unsafe { isolated_mapping_probe(probe); }
}

