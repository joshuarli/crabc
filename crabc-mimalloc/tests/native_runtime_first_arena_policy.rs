// This focused native witness compiles `crabc-mimalloc` as an ordinary
// dependency, so x86-64 uses the non-test `RuntimeProcessStorage` route:
// `process_backing` -> `begin_for_process` -> policy-bound first arena.
// The scalar audit remains default-off and exposes no allocation address or
// owner capability.
#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;



use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;

use crabc_mimalloc::__crabc_runtime::{
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    native_runtime_lifecycle_test_audit, ticket_zero_allocate, ticket_zero_free,
};

const CHILD_MARKER: &str = "CRABC_M2_NATIVE_RUNTIME_FIRST_ARENA_POLICY_CHILD";
const ARENA_RESERVE_BYTES: usize = 128 * 1024 * 1024;
const TEST_NAME: &str =
    "runtime_process_uses_source_vm_policy_for_ticket_zero_first_arena_and_client_cleanup";
const CHILD_TRACE_PATH: &str = "CRABC_M2_NATIVE_RUNTIME_INITIAL_TLD_NUMA_TRACE_PATH";
const INITIAL_TLD_NUMA_TRACE_BEGIN: &str = "CRABC_MI_RUNTIME_INITIAL_TLD_NUMA_TRACE_BEGIN";
const INITIAL_TLD_NUMA_TRACE_END: &str = "CRABC_MI_RUNTIME_INITIAL_TLD_NUMA_TRACE_END";
const RUNTIME_THP_CHILD_MARKER: &str = "CRABC_M2_NATIVE_RUNTIME_THP_CONFIGURATION_CHILD";
const RUNTIME_THP_CHILD_IMAGE: &str = "CRABC_M2_NATIVE_RUNTIME_THP_CONFIGURATION_IMAGE";
const RUNTIME_THP_TRACE_PATH: &str = "CRABC_M2_NATIVE_RUNTIME_THP_CONFIGURATION_TRACE_PATH";
const RUNTIME_THP_TEST_NAME: &str =
    "runtime_process_admits_source_allow_thp_images_with_retained_ready_configuration";
const RUNTIME_THP_DISABLED_TRACE_BEGIN: &str = "CRABC_MI_RUNTIME_THP_DISABLED_TRACE_BEGIN";
const RUNTIME_THP_DISABLED_TRACE_END: &str = "CRABC_MI_RUNTIME_THP_DISABLED_TRACE_END";
const RUNTIME_THP_MODE_TWO_TRACE_BEGIN: &str = "CRABC_MI_RUNTIME_THP_MODE_TWO_TRACE_BEGIN";
const RUNTIME_THP_MODE_TWO_TRACE_END: &str = "CRABC_MI_RUNTIME_THP_MODE_TWO_TRACE_END";

/// One short-lived parent-owned scalar trace file below the runner's `TMPDIR`.
///
/// The parent creates it exclusively and removes it on every return/unwind.
/// The child gets only its path and writes no allocation address or lifecycle
/// capability. This avoids forwarding the nested libtest summary into the
/// outer evidence parser while preserving the exact normal-runtime values.
struct ChildTraceFile {
    path: PathBuf,
}

impl ChildTraceFile {
    fn create() -> Self {
        Self::create_named("initial-tld-numa")
    }

    fn create_named(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "crabc-mimalloc-{name}-{}.trace",
            std::process::id()
        ));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("the parent creates one exclusive initial-TLD NUMA trace file");
        Self { path }
    }

    fn path(&self) -> &Path { &self.path }

    fn read(&self) -> String {
        fs::read_to_string(&self.path)
            .expect("the successful source-policy child writes its initial-TLD NUMA trace")
    }
}

#[derive(Clone, Copy)]
enum RuntimeThpImage {
    Disabled,
    ModeTwo,
}

impl RuntimeThpImage {
    const ALL: [Self; 2] = [Self::Disabled, Self::ModeTwo];

    const fn environment_value(self) -> &'static str {
        match self {
            Self::Disabled => "0",
            Self::ModeTwo => "2",
        }
    }

    const fn selected_raw(self) -> i64 {
        match self {
            Self::Disabled => 0,
            Self::ModeTwo => 2,
        }
    }

    const fn trace_begin(self) -> &'static str {
        match self {
            Self::Disabled => RUNTIME_THP_DISABLED_TRACE_BEGIN,
            Self::ModeTwo => RUNTIME_THP_MODE_TWO_TRACE_BEGIN,
        }
    }

    const fn trace_end(self) -> &'static str {
        match self {
            Self::Disabled => RUNTIME_THP_DISABLED_TRACE_END,
            Self::ModeTwo => RUNTIME_THP_MODE_TWO_TRACE_END,
        }
    }
}

impl Drop for ChildTraceFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux witness has a validated page size")
}

#[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(feature = "mi-secure-3")))]
#[test]
fn cold_native_guarded_first_request_preserves_empty_sampler_decision() {
    use crabc_mimalloc::__crabc_runtime as native;
    // The process owner initializes irreversibly. Run this cold entry alone,
    // with source options published before any native allocator operation.
    std::env::set_var("mimalloc_guarded_sample_rate", "1");
    std::env::set_var("mimalloc_guarded_min", "0");
    std::env::set_var("mimalloc_guarded_max", "1024");
    let page_size = current_page_size();
    // SAFETY: this hosted fixture supplies its own live environment and a
    // process-lifetime musl FILE output provider, without initializing owners.
    let facts = unsafe { native::NativeProcessStartupFacts::new(
        page_size, native_runtime_test_support::host_environment,
        native_runtime_test_support::stderr_output(),
    ) }.unwrap();
    assert!(native::publish_native_process_startup_facts(facts));
    let permissions = |address: usize| {
        fs::read_to_string("/proc/self/maps").unwrap().lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next()?.split_once('-')?;
            let start = usize::from_str_radix(start, 16).ok()?;
            let end = usize::from_str_radix(end, 16).ok()?;
            (start <= address && address < end).then(|| fields.next().unwrap().to_owned())
        })
    };
    let mut clients = std::vec::Vec::new();
    for (guarded, pattern) in [(false, 0x31u8), (true, 0x72)] {
        let native::NativePageAllocationResult::Allocated(client) =
            native::native_allocate_aligned(8, 16, false)
        else { panic!("the cold native request and its initialized successor allocate"); };
        assert_eq!(client.as_ptr().addr() % 16, 0);
        // SAFETY: the exact client stays live through its capacity query,
        // bounded payload writes, and eventual matching native free.
        let usable = unsafe { native::native_usable_size(client) }.unwrap();
        assert!(usable >= 8);
        let tail = client.as_ptr().addr().checked_add(usable).unwrap();
        let tail_permissions = permissions(tail).unwrap();
        if guarded {
            assert_eq!(tail % page_size, 0);
            assert!(tail_permissions.starts_with("---"));
        } else {
            assert!(tail_permissions.starts_with("rw"),
                "the original empty-Theap decision keeps the first client ordinary");
        }
        // SAFETY: the whole reported usable extent is writable. Neither the
        // protected successor mapping nor any other allocation is accessed.
        unsafe { client.as_ptr().write_bytes(pattern, usable); }
        clients.push((client, usable, pattern));
    }
    for (client, usable, pattern) in clients {
        // SAFETY: both exact clients remained live while their sibling was
        // allocated; each payload is checked and then consumed once.
        unsafe {
            assert!(core::slice::from_raw_parts(client.as_ptr(), usable)
                .iter().all(|byte| *byte == pattern));
            assert_eq!(native::native_free(client), native::NativePageFreeResult::Freed);
        }
    }
    let selected = crabc_mimalloc::source_heap_api::theap_get_default();
    assert!(!selected.is_null());
    // SAFETY: lazy startup installed this thread's actual retained Theap;
    // all clients are freed and no allocation overlaps the sampler reset.
    unsafe { crabc_mimalloc::source_heap_api::theap_guarded_set_sample_rate(selected, 0, 0); }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn cold_native_aligned_size_refusal_preserves_uninitialized_source() {
    use crabc_mimalloc::__crabc_runtime as native;
    // Process initialization is irreversible; this cold refusal runs alone.
    assert!(!native::process_is_active());
    assert!(native::native_runtime_process_options_test_audit().is_none());
    assert!(native::native_runtime_lifecycle_test_audit().is_none());
    assert!(native::native_runtime_take_source_error_test_audit().is_none());
    // SAFETY: the hosted environment and musl FILE remain valid for the
    // process lifetime. Publishing these providers initializes no owner.
    let facts = unsafe { native::NativeProcessStartupFacts::new(
        current_page_size(), native_runtime_test_support::host_environment,
        native_runtime_test_support::stderr_output(),
    ) }.unwrap();
    assert!(native::publish_native_process_startup_facts(facts));
    assert!(!native::process_is_active());

    // A valid alignment with an impossible size is a legal allocation
    // refusal. No client or memory access follows this request.
    let result = native::native_allocate_aligned(usize::MAX, 16, false);
    let active = native::process_is_active();
    let options = native::native_runtime_process_options_test_audit();
    let policy = native::native_runtime_first_arena_policy_test_audit();
    let lifecycle = native::native_runtime_lifecycle_test_audit();
    let source_error = native::native_runtime_take_source_error_test_audit();
    println!("cold aligned refusal: active={active}, options={options:?}, policy={policy:?}, lifecycle={lifecycle:?}, source_error={source_error:?}");
    assert!(matches!(result, native::NativePageAllocationResult::AllocationFailed));
    assert_eq!(source_error, Some(native::NativeSourceErrorAudit {
        code: crabc_core::Errno::INVAL.raw(),
        default_errno: crabc_core::Errno::INVAL.raw(),
    }));
    assert!(!active, "source aligned-size refusal precedes process and owner initialization");
    assert!(options.is_none());
    assert!(policy.is_none());
    assert!(lifecycle.is_none());
}

fn run_in_clean_source_environment() {
    let trace_file = ChildTraceFile::create();
    let output = Command::new(
        std::env::current_exe().expect("the focused native witness has its executable path"),
    )
    .arg("--exact")
    .arg(TEST_NAME)
    .arg("--test-threads=1")
    // The child receives only the selected lower-case source variables plus
    // its parent-owned trace path. This prevents an inherited `mimalloc_*`
    // value from supplying the observation the runtime must read through its
    // raw `environ` binding.
    .env_clear()
    .env(CHILD_MARKER, "1")
    .env("mimalloc_arena_reserve", "128M")
    .env("mimalloc_arena_eager_commit", "2")
    .env("mimalloc_allow_large_os_pages", "0")
    .env("mimalloc_allow_thp", "0")
    .env("mimalloc_use_numa_nodes", "3")
    .env("mimalloc_arena_is_numa_local", "1")
    .env(CHILD_TRACE_PATH, trace_file.path())
    .output()
    .expect("the source-policy child starts");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the source-policy child completes the native runtime witness\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let trace = trace_file.read();
    let begin = trace
        .lines()
        .position(|line| line == INITIAL_TLD_NUMA_TRACE_BEGIN)
        .unwrap_or_else(|| {
            panic!(
                "the successful source-policy child emits its initial-TLD NUMA trace\ntrace:\n{trace}"
            )
        });
    let end = trace
        .lines()
        .position(|line| line == INITIAL_TLD_NUMA_TRACE_END)
        .unwrap_or_else(|| {
            panic!(
                "the successful source-policy child terminates its initial-TLD NUMA trace\ntrace:\n{trace}"
            )
        });
    assert!(begin < end, "the source-policy child orders its NUMA trace boundaries");
    assert_eq!(
        trace
            .lines()
            .filter(|line| *line == INITIAL_TLD_NUMA_TRACE_BEGIN)
            .count(),
        1,
        "the source-policy child emits one initial-TLD NUMA trace",
    );
    assert_eq!(
        trace
            .lines()
            .filter(|line| *line == INITIAL_TLD_NUMA_TRACE_END)
            .count(),
        1,
        "the source-policy child terminates one initial-TLD NUMA trace",
    );
    // Libtest writes its `test ...` prefix without a newline under
    // `--nocapture`; separate it from the first machine-readable marker.
    println!();
    for line in trace.lines().skip(begin).take(end - begin + 1) {
        println!("{line}");
    }
}

fn run_in_clean_source_thp_environment() {
    for image in RuntimeThpImage::ALL {
        let trace_file = ChildTraceFile::create_named("runtime-thp-configuration");
        let output = Command::new(
            std::env::current_exe()
                .expect("the focused native THP witness has its executable path"),
        )
        .arg("--exact")
        .arg(RUNTIME_THP_TEST_NAME)
        .arg("--test-threads=1")
        // This child starts from only the selected source option and one
        // parent-owned scalar trace path. Its normal RuntimeProcessStorage
        // initialization therefore reads raw `environ`, rather than an
        // inherited mimalloc setting or a synthetic option fixture.
        .env_clear()
        .env(RUNTIME_THP_CHILD_MARKER, "1")
        .env(RUNTIME_THP_CHILD_IMAGE, image.environment_value())
        .env("mimalloc_allow_thp", image.environment_value())
        .env(RUNTIME_THP_TRACE_PATH, trace_file.path())
        .output()
        .expect("the source-THP child starts");
        assert_eq!(
            output.status.code(),
            Some(0),
            "the source-THP child completes its normal runtime witness\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let trace = trace_file.read();
        let lines: Vec<_> = trace.lines().collect();
        let begin = lines
            .iter()
            .position(|line| *line == image.trace_begin())
            .expect("the source-THP child emits its image trace");
        let end = lines
            .iter()
            .position(|line| *line == image.trace_end())
            .expect("the source-THP child terminates its image trace");
        assert_eq!(
            lines.iter().filter(|line| **line == image.trace_begin()).count(),
            1,
            "the source-THP child emits one image trace",
        );
        assert_eq!(
            lines.iter().filter(|line| **line == image.trace_end()).count(),
            1,
            "the source-THP child terminates one image trace",
        );
        assert!(begin < end, "the source-THP child orders its image trace boundaries");
        println!();
        for line in &lines[begin..=end] {
            println!("{line}");
        }
    }
}

#[test]
fn runtime_process_uses_source_vm_policy_for_ticket_zero_first_arena_and_client_cleanup() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        run_in_clean_source_environment();
        return;
    }

    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime accepts one source-policy process image"
    );
    assert!(
        native_runtime_lifecycle_test_audit().is_none(),
        "process startup does not reserve an arena before its first ticket-zero request"
    );

    let block = match ticket_zero_allocate(79, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("the first ticket-zero request maps its source-policy arena")
        }
    };
    // SAFETY: this fresh child owns the exact current ticket-zero allocation
    // until the matching `ticket_zero_free` below.
    unsafe {
        block.as_ptr().write(0x5a);
        assert_eq!(block.as_ptr().read(), 0x5a);
    }

    let live = native_runtime_lifecycle_test_audit()
        .expect("the active policy-bound first arena exposes a scalar audit");
    assert_eq!(live.process_active, 1);
    assert_eq!(live.process_backing_first_arena_begin_count, 1);
    assert_eq!(live.process_backing_published_os_arena_count, 1);
    assert_eq!(live.vm_policy_arena_reserve_bytes, ARENA_RESERVE_BYTES);
    assert_eq!(live.vm_policy_arena_eager_commit, 2);
    assert_eq!(live.vm_policy_allow_large_os_pages, 0);
    assert_eq!(live.vm_policy_allow_thp, 0);
    assert_eq!(live.vm_policy_arena_is_numa_local, 1);
    assert_eq!(live.vm_policy_use_numa_nodes, 3);
    assert_eq!(
        live.vm_policy_numa_node_count_cache, 3,
        "the actual ticket-zero TLD initialization resolves its retained source NUMA policy"
    );
    assert!(
        (0..3).contains(&live.ticket_zero_tld_numa_node),
        "the actual ticket-zero TLD stores the source-normalized node from that policy"
    );
    assert!(
        (0..3).contains(&live.process_arena_numa_node),
        "the real policy-bound first regular arena stores its source-normalized node"
    );
    let trace_path = std::env::var_os(CHILD_TRACE_PATH)
        .expect("the source-policy child receives its parent-owned scalar trace path");
    fs::write(
        trace_path,
        format!(
            "{INITIAL_TLD_NUMA_TRACE_BEGIN}\nvm_policy_arena_is_numa_local={}\nvm_policy_use_numa_nodes={}\nvm_policy_numa_node_count_cache={}\nticket_zero_tld_numa_node={}\nprocess_arena_numa_node={}\n{INITIAL_TLD_NUMA_TRACE_END}\n",
            live.vm_policy_arena_is_numa_local,
            live.vm_policy_use_numa_nodes,
            live.vm_policy_numa_node_count_cache,
            live.ticket_zero_tld_numa_node,
            live.process_arena_numa_node,
        ),
    )
    .expect("the source-policy child writes its scalar initial-TLD NUMA trace");
    assert_eq!(live.process_arena_size, ARENA_RESERVE_BYTES);
    assert_eq!(live.process_arena_initially_committed, 1);
    assert_eq!(live.arena_registry_count, 1);
    assert!(
        live.page_map_registered_entry_count > 0,
        "the live client has one current PageMap registration"
    );

    // SAFETY: `block` is the current unique result above and has not crossed a
    // thread or any other allocation boundary.
    assert_eq!(unsafe { ticket_zero_free(block) }, TicketZeroPageFreeResult::Freed);

    let after = native_runtime_lifecycle_test_audit()
        .expect("the freed first-arena client leaves the runtime auditable");
    assert_eq!(after.process_backing_first_arena_begin_count, 1);
    assert_eq!(after.process_backing_published_os_arena_count, 1);
    assert_eq!(after.vm_policy_arena_reserve_bytes, ARENA_RESERVE_BYTES);
    assert_eq!(after.vm_policy_arena_is_numa_local, 1);
    assert_eq!(after.process_arena_size, ARENA_RESERVE_BYTES);
    assert_eq!(after.process_arena_initially_committed, 1);
    assert!(
        (0..3).contains(&after.process_arena_numa_node),
        "the retained process arena keeps its source-selected NUMA relation after client free"
    );
    assert_eq!(after.arena_registry_count, 1);
    assert_eq!(
        after.page_map_registered_entry_count, 0,
        "the exact client free releases its PageMap registration while the process arena remains owned"
    );
    assert_eq!(after.main_heap_abandoned_page_count, 0);
    assert_eq!(after.main_heap_os_abandoned_pages_empty, 1);
}

#[test]
fn runtime_process_admits_source_allow_thp_images_with_retained_ready_configuration() {
    if std::env::var_os(RUNTIME_THP_CHILD_MARKER).is_none() {
        run_in_clean_source_thp_environment();
        return;
    }

    let image = match std::env::var(RUNTIME_THP_CHILD_IMAGE)
        .expect("the source-THP child receives its fixed image identifier")
        .as_str()
    {
        "0" => RuntimeThpImage::Disabled,
        "2" => RuntimeThpImage::ModeTwo,
        other => panic!("the source-THP child receives one fixed image, observed {other:?}"),
    };
    assert_eq!(
        std::env::var("mimalloc_allow_thp").as_deref(),
        Ok(image.environment_value()),
        "the normal runtime child receives its selected raw source option",
    );
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime accepts one source-THP process image"
    );
    let block = match ticket_zero_allocate(79, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("the first ticket-zero request maps the source-THP runtime arena")
        }
    };
    let live = native_runtime_lifecycle_test_audit()
        .expect("the first source-THP ticket-zero allocation exposes one scalar READY audit");
    let selected_raw = image.selected_raw();
    assert_eq!(live.vm_policy_allow_thp_raw, selected_raw);
    assert_eq!(live.vm_policy_allow_thp, usize::from(selected_raw != 0));
    if matches!(image, RuntimeThpImage::Disabled) {
        assert!(
            !live.ready_memory_config_has_transparent_huge_pages,
            "allow_thp=0 clears the retained READY configuration before the ordinary runtime uses it",
        );
    }
    // This audit is a retained configuration observation after normal startup;
    // it does not invoke a fresh detector or infer THP state from purge size.
    let trace_path = std::env::var_os(RUNTIME_THP_TRACE_PATH)
        .expect("the source-THP child receives its parent-owned scalar trace path");
    fs::write(
        trace_path,
        format!(
            "{}\nselected_allow_thp_raw={}\nvm_policy_allow_thp={}\nready_memory_config_has_transparent_huge_pages={}\n{}\n",
            image.trace_begin(),
            live.vm_policy_allow_thp_raw,
            live.vm_policy_allow_thp,
            usize::from(live.ready_memory_config_has_transparent_huge_pages),
            image.trace_end(),
        ),
    )
    .expect("the source-THP child writes its scalar READY trace");

    // SAFETY: `block` is the exact fresh ticket-zero result retained above.
    assert_eq!(unsafe { ticket_zero_free(block) }, TicketZeroPageFreeResult::Freed);
}
