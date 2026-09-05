//! Library pathname selection shared by installed initial and runtime loads.
//!
//! musl 1.2.6 `ldso/dynlink.c` path_open, fixup_rpath and load_library
//! (MIT, 9fa28ece75d8a2191de7c5bb53bed224c5947417): environment first,
//! first-load ancestors next, installed system directory last. Empty colon
//! and newline components are skipped; unexpected open errors stop search.
//! The installed product owns /usr/lib; musl path configuration files and
//! ambient host directories are not candidate inputs.
use super::*;

const PATH_CAPACITY: usize = 4096;
static mut ENVIRONMENT_PATH: *const u8 = core::ptr::null();
static mut SECURE: bool = true;

/// Initial stack strings have process lifetime, as in musl's env_path. This
/// is initialized once before discovery and never refreshed from environ.
pub(super) unsafe fn initialize(sp: usize) {
    let argc = unsafe { *(sp as *const usize) };
    let mut cursor = (sp + 8 + (argc + 1) * 8) as *const usize;
    let mut environment: *const u8 = core::ptr::null();
    while unsafe { *cursor } != 0 {
        let value = unsafe { *cursor } as *const u8;
        let key = b"LD_LIBRARY_PATH=";
        if environment.is_null() && key.iter().enumerate().all(|(index, byte)| unsafe { *value.add(index) == *byte }) {
            environment = unsafe { value.add(key.len()) };
        }
        cursor = unsafe { cursor.add(1) };
    }
    cursor = unsafe { cursor.add(1) };
    let mut ids = [None; 4];
    let mut secure = false;
    while unsafe { *cursor } != 0 {
        let tag = unsafe { *cursor };
        let value = unsafe { *cursor.add(1) };
        if (11..=14).contains(&tag) { ids[tag - 11] = Some(value); }
        if tag == 23 { secure |= value != 0; }
        cursor = unsafe { cursor.add(2) };
    }
    secure |= ids.iter().any(Option::is_none) || ids[0] != ids[1] || ids[2] != ids[3];
    unsafe { SECURE = secure; ENVIRONMENT_PATH = if secure { core::ptr::null() } else { environment }; }
}

pub(super) type Opened = (i64, [u8; MAX_PATH], usize);

unsafe fn direct(name: &[u8]) -> Result<Opened, i32> {
    if name.is_empty() { return Err(22); }
    if name.len() >= MAX_PATH { return Err(36); }
    let mut path = [0; MAX_PATH];
    path[..name.len()].copy_from_slice(name);
    let fd = unsafe { syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as i64, 0x80000, 0) };
    if fd < 0 { Err((-fd) as i32) } else { Ok((fd, path, name.len())) }
}

unsafe fn path_open(paths: &[u8], name: &[u8]) -> Result<Option<Opened>, i32> {
    for directory in paths.split(|byte| matches!(byte, b':' | b'\n')).filter(|part| !part.is_empty()) {
        let length = directory.len().checked_add(1).and_then(|n| n.checked_add(name.len())).ok_or(36)?;
        if length >= MAX_PATH { continue; }
        let mut path = [0; MAX_PATH];
        path[..directory.len()].copy_from_slice(directory);
        path[directory.len()] = b'/';
        path[directory.len() + 1..length].copy_from_slice(name);
        match unsafe { direct(&path[..length]) } {
            Ok(opened) => return Ok(Some(opened)),
            Err(2 | 20 | 13 | 36) => (),
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

unsafe fn object_paths(object: &Object, output: &mut [u8; PATH_CAPACITY]) -> Result<usize, i32> {
    if object.runpath.is_null() { return Ok(0); }
    let paths = unsafe { core::slice::from_raw_parts(object.runpath, object.runpath_len) };
    if !paths.contains(&b'$') {
        if paths.len() >= output.len() { return Err(36); }
        output[..paths.len()].copy_from_slice(paths);
        return Ok(paths.len());
    }
    // Musl ignores the whole path on any unrecognized expansion.
    let mut remaining = paths;
    while let Some(index) = remaining.iter().position(|byte| *byte == b'$') {
        remaining = &remaining[index..];
        let skip = if remaining.starts_with(b"${ORIGIN}") { 9 }
            else if remaining.starts_with(b"$ORIGIN") { 7 } else { return Ok(0); };
        remaining = &remaining[skip..];
    }
    let mut executable = [0; MAX_PATH];
    let name = if !object.mapped {
        if unsafe { SECURE } { return Ok(0); }
        let size = unsafe { syscall3(89, b"/proc/self/exe\0".as_ptr() as i64, executable.as_mut_ptr() as i64, MAX_PATH as i64) };
        if size < 0 {
            return match -size { 2 | 20 | 13 => Ok(0), error => Err(error as i32) };
        }
        if size as usize >= MAX_PATH { return Ok(0); }
        &executable[..size as usize]
    } else {
        let length = unsafe { bounded_nul(object.search_name.as_ptr(), MAX_PATH) }.ok_or(36)?;
        &object.search_name[..length]
    };
    let origin = name.iter().rposition(|byte| *byte == b'/').map_or(b".".as_slice(), |index| &name[..index]);
    if unsafe { SECURE } && !name.starts_with(b"/") { return Ok(0); }
    let mut count = 0;
    let mut input = paths;
    while !input.is_empty() {
        let (part, skip) = if input.starts_with(b"${ORIGIN}") { (origin, 9) }
            else if input.starts_with(b"$ORIGIN") { (origin, 7) } else { (&input[..1], 1) };
        let end = count + part.len();
        if end >= output.len() { return Err(36); }
        output[count..end].copy_from_slice(part);
        count = end;
        input = &input[skip..];
    }
    Ok(count)
}

/// The iterator starts at the requesting object and follows only its first
/// load ancestry. dlopen itself starts at the main executable, as musl does.
pub(super) unsafe fn open<'a>(name: &[u8], ancestors: impl Iterator<Item = &'a Object>) -> Result<Opened, i32> {
    if name.is_empty() || name.contains(&b'/') { return unsafe { direct(name) }; }
    if name.len() > 255 { return Err(36); }
    let environment = unsafe { ENVIRONMENT_PATH };
    if !environment.is_null() {
        let length = unsafe { bounded_nul(environment, PATH_CAPACITY) }.ok_or(36)?;
        if let Some(opened) = unsafe { path_open(core::slice::from_raw_parts(environment, length), name) }? { return Ok(opened); }
    }
    let mut paths = [0; PATH_CAPACITY];
    for object in ancestors {
        let length = unsafe { object_paths(object, &mut paths) }?;
        if let Some(opened) = unsafe { path_open(&paths[..length], name) }? { return Ok(opened); }
    }
    unsafe { path_open(b"/usr/lib", name) }?.ok_or(2)
}

#[cfg(test)]
#[path = "x86_64_library_search_tests.rs"]
mod tests;
