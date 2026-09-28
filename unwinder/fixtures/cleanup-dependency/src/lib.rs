use std::backtrace::{Backtrace, BacktraceStatus};
use std::ffi::c_void;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BacktraceTarget {
    pub marker: usize,
    pub start: usize,
    pub end: usize,
}

#[repr(C)]
struct ElfProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    physical: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

#[repr(C)]
struct DlProgramHeaders {
    base: usize,
    name: *const u8,
    headers: *const ElfProgramHeader,
    count: u16,
}

unsafe extern "C" {
    fn dl_iterate_phdr(callback: extern "C" fn(*mut DlProgramHeaders, usize, *mut c_void) -> i32,
                       data: *mut c_void) -> i32;
    fn _Unwind_Backtrace(callback: extern "C" fn(*mut c_void, *mut c_void) -> i32,
                         data: *mut c_void) -> i32;
    fn _Unwind_GetIP(context: *mut c_void) -> usize;
    fn pthread_self() -> usize;
}

extern "C" fn find_executable_target(info: *mut DlProgramHeaders, _: usize, data: *mut c_void) -> i32 {
    // The loader owns these callback pointers only for this invocation; copy
    // the numeric code interval before returning to the caller.
    let (info, target) = unsafe { (&*info, &mut *(data as *mut BacktraceTarget)) };
    if info.headers.is_null() || info.count > 128 {
        return 0;
    }
    for index in 0..usize::from(info.count) {
        let header = unsafe { &*info.headers.add(index) };
        if header.kind != 1 || header.flags & 1 == 0 {
            continue;
        }
        let Some(start) = info.base.checked_add(header.address as usize) else { continue };
        let Some(end) = start.checked_add(header.memory_size as usize) else { continue };
        if start <= target.marker && target.marker < end {
            target.start = start;
            target.end = end;
            return 1;
        }
    }
    0
}

pub fn executable_target(marker: usize) -> BacktraceTarget {
    let mut target = BacktraceTarget { marker, start: 0, end: 0 };
    let found = unsafe { dl_iterate_phdr(find_executable_target, (&mut target as *mut BacktraceTarget).cast()) };
    assert_eq!(found, 1, "linked code marker has no executable load range");
    target
}

const MAX_FRAMES: usize = 64;

struct Trace {
    pcs: [usize; MAX_FRAMES],
    count: usize,
    stop_after: usize,
}

extern "C" fn collect_pc(context: *mut c_void, data: *mut c_void) -> i32 {
    // The provider calls this synchronously with the address of the local
    // Trace. Returning a nonzero code at the bound stops further callbacks.
    let trace = unsafe { &mut *(data as *mut Trace) };
    if trace.count == trace.stop_after {
        return 1;
    }
    trace.pcs[trace.count] = unsafe { _Unwind_GetIP(context) };
    trace.count += 1;
    i32::from(trace.count == trace.stop_after)
}

#[inline(never)]
pub fn probe_backtrace(label: &str, target: BacktraceTarget, host: Option<BacktraceTarget>) {
    let thread = unsafe { pthread_self() };
    assert_ne!(thread, 0);
    assert!(target.start <= target.marker && target.marker < target.end);
    if let Some(host) = host {
        assert!(host.start <= host.marker && host.marker < host.end);
        assert!(host.end <= target.start || target.end <= host.start);
    }
    let mut full = Trace { pcs: [0; MAX_FRAMES], count: 0, stop_after: MAX_FRAMES };
    let status = unsafe { _Unwind_Backtrace(collect_pc, (&mut full as *mut Trace).cast()) };
    assert_eq!(status, 5, "complete backtrace did not end at the stack boundary");
    assert!(full.count > 0 && full.count < MAX_FRAMES);
    assert!(full.pcs[..full.count].iter().any(|pc| target.start <= *pc && *pc < target.end));
    if let Some(host) = host {
        assert!(full.pcs[..full.count].iter().any(|pc| host.start <= *pc && *pc < host.end));
    }
    let mut bounded = Trace { pcs: [0; MAX_FRAMES], count: 0, stop_after: 3 };
    let cutoff = unsafe { _Unwind_Backtrace(collect_pc, (&mut bounded as *mut Trace).cast()) };
    assert_eq!((cutoff, bounded.count), (3, 3), "callback bound did not stop unwinding");
    let host_record = host.map_or_else(|| "none".to_owned(), |value| {
        format!("{}:{}:{}", value.marker, value.start, value.end)
    });
    let pcs = full.pcs[..full.count].iter().map(usize::to_string).collect::<Vec<_>>().join(",");
    println!("backtrace {label} thread={thread} status={status} cutoff={cutoff} cutoff_frames={} target={}:{}:{} host={host_record} pcs={pcs}",
             bounded.count, target.marker, target.start, target.end);
}

struct DependencyCleanup(Arc<AtomicUsize>);

impl Drop for DependencyCleanup {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[inline(never)]
pub fn panic_with_cleanup(count: Arc<AtomicUsize>) -> ! {
    let _cleanup = DependencyCleanup(count);
    assert_eq!(Backtrace::force_capture().status(), BacktraceStatus::Captured);
    let payload = std::panic::catch_unwind(|| {
        std::panic::panic_any(73usize);
    })
        .expect_err("dependency panic must reach its local catch boundary");
    std::panic::resume_unwind(payload)
}

pub const fn dependency_marker() -> usize {
    73
}
