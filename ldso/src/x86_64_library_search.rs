//! Library pathname selection shared by installed initial and runtime loads.
//!
//! musl 1.2.6 `ldso/dynlink.c` path_open, fixup_rpath and load_library
//! (MIT, 9fa28ece75d8a2191de7c5bb53bed224c5947417): environment first,
//! first-load ancestors next, configured/default system directories last.
//! Empty colon and newline components are skipped; unexpected open errors stop search.
//! A name containing '/' is opened as given, so only the kernel's PATH_MAX
//! applies; a bare name longer than NAME_MAX fails; search candidates are
//! composed in musl's `2*NAME_MAX+2` buffer, skipping any that do not fit;
//! `$ORIGIN` expansion and every admitted pathname are sized to their bytes.
//! The canonical installed interpreter has installation prefix "". Direct
//! entry derives the prefix from its invocation name, or from the executable's
//! PT_INTERP in listing mode. Test roots supply only declared application
//! DSOs and the installed libc.
use super::*;
use super::x86_64_runtime_memory::LoaderBuffer;
use core::cell::UnsafeCell;

/// Linux PATH_MAX, including the terminator. Musl only uses it to reject an
/// installation prefix; every other length here is sized to its bytes.
const PATH_CAPACITY: usize = 4096;
/// Musl `load_library`'s `char buf[2*NAME_MAX+2]`, shared by `path_open`
/// candidates and `fixup_rpath`'s `/proc/self/exe` readlink.
const SEARCH_BUFFER: usize = 2 * NAME_MAX + 2;
const NAME_MAX: usize = 255;
static mut ENVIRONMENT_PATH: *const u8 = core::ptr::null();
static mut ENVIRONMENT_PRELOAD: *const u8 = core::ptr::null();
static mut SECURE: bool = true;
static mut INTERPRETER_NAME: *const u8 = b"/lib/ld-crabc-x86_64.so.1\0".as_ptr();
static mut APPLICATION_NAME: *const u8 = b"\0".as_ptr();

/// Initial stack strings have process lifetime, as in musl's env_path. This
/// is initialized once before discovery and never refreshed from environ.
pub(super) unsafe fn initialize(sp: usize) {
    let argc = unsafe { *(sp as *const usize) };
    let first_argument = if argc == 0 { core::ptr::null() } else { unsafe { *((sp + 8) as *const *const u8) } };
    let mut cursor = (sp + 8 + (argc + 1) * 8) as *const usize;
    let mut environment: *const u8 = core::ptr::null();
    let mut preload: *const u8 = core::ptr::null();
    while unsafe { *cursor } != 0 {
        let value = unsafe { *cursor } as *const u8;
        let key = b"LD_LIBRARY_PATH=";
        if environment.is_null() && key.iter().enumerate().all(|(index, byte)| unsafe { *value.add(index) == *byte }) {
            environment = unsafe { value.add(key.len()) };
        }
        let key = b"LD_PRELOAD=";
        if preload.is_null() && key.iter().enumerate().all(|(index, byte)| unsafe { *value.add(index) == *byte }) {
            preload = unsafe { value.add(key.len()) };
        }
        cursor = unsafe { cursor.add(1) };
    }
    cursor = unsafe { cursor.add(1) };
    let mut ids = [None; 4];
    let mut secure = false;
    let mut executable_name: *const u8 = core::ptr::null();
    while unsafe { *cursor } != 0 {
        let tag = unsafe { *cursor };
        let value = unsafe { *cursor.add(1) };
        if (11..=14).contains(&tag) { ids[tag - 11] = Some(value); }
        if tag == 23 { secure |= value != 0; }
        if tag == 31 { executable_name = value as *const u8; }
        cursor = unsafe { cursor.add(2) };
    }
    secure |= ids.iter().any(Option::is_none) || ids[0] != ids[1] || ids[2] != ids[3];
    // musl __dls3 names a kernel-mapped application by AT_EXECFN unless it
    // is a /proc/ spelling, otherwise by argv[0]. Both strings live on the
    // initial stack for the process lifetime.
    let proc_prefix = b"/proc/";
    let use_executable_name = !executable_name.is_null()
        && !proc_prefix.iter().enumerate().all(|(index, byte)| unsafe { *executable_name.add(index) == *byte });
    let application = if use_executable_name { executable_name } else { first_argument };
    unsafe {
        if !application.is_null() { APPLICATION_NAME = application; }
        SECURE = secure;
        ENVIRONMENT_PATH = if secure { core::ptr::null() } else { environment };
        ENVIRONMENT_PRELOAD = if secure { core::ptr::null() } else { preload };
    }
}

/// Kernel-mapped application name for dladdr, dl_iterate_phdr and link maps.
/// Direct loader entry names its main object by the opened program path.
pub(super) unsafe fn application_name() -> *const u8 { unsafe { APPLICATION_NAME } }

/// Command options are explicit input, independent of environment filtering.
pub(super) unsafe fn command_interpreter(name: *const u8) { unsafe { INTERPRETER_NAME = name; } }
pub(super) unsafe fn interpreter_name() -> &'static [u8] {
    unsafe { c_string(INTERPRETER_NAME) }
}

/// A process-lifetime C string from the initial stack, argv, PT_INTERP or a
/// static literal. Like musl, none of these is length-limited here.
unsafe fn c_string(pointer: *const u8) -> &'static [u8] {
    let length = unsafe { bounded_nul(pointer, isize::MAX as usize) }.unwrap_or(0);
    unsafe { core::slice::from_raw_parts(pointer, length) }
}

/// The installation prefix already used for system-path discovery.
///
/// This chooses the path-file location, not a mandatory root for every
/// configured library directory. Canonical libc identity selection considers
/// the declared aliases under both this prefix and the process root; it never
/// grants startup authority to an arbitrary library-search result.
pub(super) unsafe fn installation_prefix() -> &'static [u8] {
    let name = unsafe { interpreter_name() };
    if !name.starts_with(b"/") {
        return b"";
    }
    let length = name
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .rev()
        .nth(1)
        .map_or(0, |(index, _)| index);
    // Musl ignores a prefix that could not form a pathname.
    if length >= PATH_CAPACITY { return b""; }
    &name[..length]
}
pub(super) unsafe fn command_path(path: *const u8) { unsafe { ENVIRONMENT_PATH = path; } }
pub(super) unsafe fn command_preload(path: *const u8) { unsafe { ENVIRONMENT_PRELOAD = path; } }

/// A missing or malformed optional preload is ignored by musl load_preload;
/// successful admissions still participate in the complete initial graph.
pub(super) unsafe fn preloads() -> &'static [u8] {
    let preload = unsafe { ENVIRONMENT_PRELOAD };
    if preload.is_null() { return &[]; }
    unsafe { c_string(preload) }
}

// The initial transaction is single-threaded; runtime selection holds the
// loader lock. The snapshot is initialized only on the first system-tier
// search and never reopened, including after later chdir/setenv/unlink calls.
enum SystemPath { Uninitialized, Defaults, Disabled, File(LoaderBuffer<u8>) }
struct SystemPathOwner(UnsafeCell<SystemPath>);
unsafe impl Sync for SystemPathOwner {}
static SYSTEM_PATH: SystemPathOwner = SystemPathOwner(UnsafeCell::new(SystemPath::Uninitialized));

unsafe fn load_system_path() -> SystemPath {
    // musl derives the installation prefix from the second-last slash of
    // an absolute interpreter name. Relative names retain the root prefix.
    let prefix = unsafe { installation_prefix() };
    let prefix_len = prefix.len();
    let suffix = b"/etc/ld-musl-x86_64.path\0";
    let mut path = [0u8; PATH_CAPACITY + 32];
    path[..prefix_len].copy_from_slice(prefix);
    path[prefix_len..prefix_len + suffix.len()].copy_from_slice(suffix);
    let fd = unsafe { syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as i64, 0x80000, 0) };
    if fd < 0 { return if fd == -2 { SystemPath::Defaults } else { SystemPath::Disabled }; }
    // Musl uses zero bytes when fstat fails, and never retries with defaults
    // after a present configuration cannot be read or allocated.
    let size = unsafe { file_size_from_fd(fd) }.unwrap_or(0);
    let length = usize::try_from(size).ok().and_then(|size| size.checked_add(1));
    let loaded = (|| {
        let mut contents = LoaderBuffer::new(length?, 0u8)?;
        let bytes = contents.as_mut_slice();
        let mut count = 0;
        while count + 1 < bytes.len() {
            let read = unsafe { syscall3(0, fd, bytes.as_mut_ptr().add(count) as i64, (bytes.len() - count - 1) as i64) };
            if read == -4 { continue; }
            if read < 0 { return None; }
            if read == 0 { break; }
            count += read as usize;
        }
        Some(SystemPath::File(contents))
    })();
    unsafe { syscall1(SYS_CLOSE, fd); }
    loaded.unwrap_or(SystemPath::Disabled)
}

unsafe fn system_paths() -> &'static [u8] {
    let state = unsafe { &mut *SYSTEM_PATH.0.get() };
    if matches!(state, SystemPath::Uninitialized) {
        *state = unsafe { load_system_path() };
    }
    match state {
        SystemPath::Defaults => b"/lib:/usr/local/lib:/usr/lib",
        SystemPath::File(contents) => {
            let bytes = contents.as_slice();
            // Embedded NUL and early EOF terminate the file's C string.
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            &bytes[..end]
        }
        SystemPath::Disabled | SystemPath::Uninitialized => &[],
    }
}

/// One admitted object's pathname: NUL-terminated in a loader mapping sized
/// to it, as musl copies `pathname` into the DSO allocation. Its owner (the
/// initial object table or a runtime registry node) outlives every
/// [`ObjectName`] view of it.
pub(super) struct LoadedName(LoaderBuffer<u8>);

impl LoadedName {
    /// Copy `bytes` and a terminator; `None` when the kernel refuses the map.
    pub(super) fn new(bytes: &[u8]) -> Option<Self> {
        let mut buffer = LoaderBuffer::new(bytes.len().checked_add(1)?, 0u8)?;
        buffer.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
        Some(Self(buffer))
    }

    pub(super) fn view(&self) -> ObjectName {
        let bytes = self.0.as_slice();
        ObjectName { pointer: bytes.as_ptr(), length: bytes.len() - 1 }
    }
}

/// A copyable view of an object's NUL-terminated pathname. Object records
/// are plain copies, so the bytes belong to a [`LoadedName`] or to a
/// process-lifetime string such as the direct command's program argument.
#[derive(Clone, Copy)]
pub(super) struct ObjectName { pointer: *const u8, length: usize }

impl ObjectName {
    /// The kernel-mapped executable has no search name.
    pub(super) const EMPTY: Self = Self { pointer: b"\0".as_ptr(), length: 0 };

    /// # Safety
    /// `bytes` is followed by a NUL byte and outlives every copy of the view.
    pub(super) unsafe fn borrowed(bytes: &[u8]) -> Self { Self { pointer: bytes.as_ptr(), length: bytes.len() } }

    /// The terminated C string, for link maps and diagnostics.
    pub(super) fn as_ptr(self) -> *const u8 { self.pointer }

    /// # Safety
    /// The owner of the viewed bytes is still live.
    pub(super) unsafe fn bytes<'a>(self) -> &'a [u8] { unsafe { core::slice::from_raw_parts(self.pointer, self.length) } }
}

pub(super) type Opened = (i64, LoadedName);

/// The error of a selection that failed without a syscall setting errno;
/// musl's diagnostic then shows the caller's errno.
pub(super) const UNSET_ERRNO: i32 = -1;

unsafe fn direct(name: &[u8]) -> Result<Opened, i32> {
    if name.is_empty() { return Err(22); }
    // The name is stored as given; the kernel alone limits its length.
    let path = LoadedName::new(name).ok_or(12)?;
    let fd = unsafe { syscall4(SYS_OPENAT, AT_FDCWD, path.view().as_ptr() as i64, 0x80000, 0) };
    if fd < 0 { Err((-fd) as i32) } else { Ok((fd, path)) }
}

unsafe fn path_open(paths: &[u8], name: &[u8]) -> Result<Option<Opened>, i32> {
    for directory in paths.split(|byte| matches!(byte, b':' | b'\n')).filter(|part| !part.is_empty()) {
        // snprintf(buf, sizeof buf, "%.*s/%s") < sizeof buf: skip what does not fit.
        let length = directory.len().saturating_add(1).saturating_add(name.len());
        if length >= SEARCH_BUFFER { continue; }
        let mut path = [0; SEARCH_BUFFER];
        path[..directory.len()].copy_from_slice(directory);
        path[directory.len()] = b'/';
        path[directory.len() + 1..length].copy_from_slice(name);
        let fd = unsafe { syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as i64, 0x80000, 0) };
        if fd >= 0 {
            let Some(stored) = LoadedName::new(&path[..length]) else {
                unsafe { syscall1(SYS_CLOSE, fd); }
                return Err(12);
            };
            return Ok(Some((fd, stored)));
        }
        match (-fd) as i32 {
            2 | 20 | 13 | 36 => (),
            error => return Err(error),
        }
    }
    Ok(None)
}

/// An object's search path: its DT_RUNPATH bytes, or musl fixup_rpath's
/// `$ORIGIN` expansion in a loader mapping sized to the result.
enum ObjectPaths<'a> { None, Borrowed(&'a [u8]), Expanded(LoaderBuffer<u8>) }

impl ObjectPaths<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::None => &[],
            Self::Borrowed(bytes) => bytes,
            Self::Expanded(buffer) => buffer.as_slice(),
        }
    }
}

unsafe fn object_paths(object: &Object) -> Result<ObjectPaths<'_>, i32> {
    if object.runpath.is_null() { return Ok(ObjectPaths::None); }
    let paths = unsafe { core::slice::from_raw_parts(object.runpath, object.runpath_len) };
    if !paths.contains(&b'$') { return Ok(ObjectPaths::Borrowed(paths)); }
    // Musl ignores the whole path on any unrecognized expansion.
    let mut remaining = paths;
    let (mut expansions, mut token_bytes) = (0usize, 0usize);
    while let Some(index) = remaining.iter().position(|byte| *byte == b'$') {
        remaining = &remaining[index..];
        let skip = if remaining.starts_with(b"${ORIGIN}") { 9 }
            else if remaining.starts_with(b"$ORIGIN") { 7 } else { return Ok(ObjectPaths::None); };
        remaining = &remaining[skip..];
        expansions += 1;
        token_bytes += skip;
    }
    let mut executable = [0; SEARCH_BUFFER];
    let name = if object.map_provenance == ObjectMapProvenance::KernelMain {
        if unsafe { SECURE } { return Ok(ObjectPaths::None); }
        let size = unsafe { syscall3(89, b"/proc/self/exe\0".as_ptr() as i64, executable.as_mut_ptr() as i64, SEARCH_BUFFER as i64) };
        if size < 0 {
            return match -size { 2 | 20 | 13 => Ok(ObjectPaths::None), error => Err(error as i32) };
        }
        if size as usize >= SEARCH_BUFFER { return Ok(ObjectPaths::None); }
        &executable[..size as usize]
    } else {
        unsafe { object.search_name.bytes() }
    };
    let origin = name.iter().rposition(|byte| *byte == b'/').map_or(b".".as_slice(), |index| &name[..index]);
    // Musl disallows a non-absolute origin name for AT_SECURE.
    if unsafe { SECURE } && !name.starts_with(b"/") { return Ok(ObjectPaths::None); }
    let length = expansions.checked_mul(origin.len())
        .and_then(|bytes| bytes.checked_add(paths.len() - token_bytes)).ok_or(12)?;
    let mut output = LoaderBuffer::new(length, 0u8).ok_or(12)?;
    let bytes = output.as_mut_slice();
    let mut count = 0;
    let mut input = paths;
    while !input.is_empty() {
        let (part, skip) = if input.starts_with(b"${ORIGIN}") { (origin, 9) }
            else if input.starts_with(b"$ORIGIN") { (origin, 7) } else { (&input[..1], 1) };
        bytes[count..count + part.len()].copy_from_slice(part);
        count += part.len();
        input = &input[skip..];
    }
    Ok(ObjectPaths::Expanded(output))
}

/// The iterator starts at the requesting object and follows only its first
/// load ancestry. dlopen itself starts at the main executable, as musl does.
pub(super) unsafe fn open<'a>(name: &[u8], ancestors: impl Iterator<Item = &'a Object>) -> Result<Opened, i32> {
    if name.is_empty() || name.contains(&b'/') { return unsafe { direct(name) }; }
    // Musl returns before any open without setting errno.
    if name.len() > NAME_MAX { return Err(UNSET_ERRNO); }
    let environment = unsafe { ENVIRONMENT_PATH };
    if !environment.is_null() {
        if let Some(opened) = unsafe { path_open(c_string(environment), name) }? { return Ok(opened); }
    }
    for object in ancestors {
        let paths = unsafe { object_paths(object) }?;
        if let Some(opened) = unsafe { path_open(paths.bytes(), name) }? { return Ok(opened); }
    }
    unsafe { path_open(system_paths(), name) }?.ok_or(2)
}

#[cfg(test)]
#[path = "x86_64_library_search_tests.rs"]
mod tests;
