// This focused native witness compiles `crabc-mimalloc` as an ordinary
// dependency. It observes the real process route from source startup's
// `mimalloc_reserve_os_memory` reservation through ticket-zero allocation;
// it does not fabricate an ArenaView or call a private policy helper.
#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;



use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crabc_mimalloc::__crabc_runtime::{
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    native_runtime_first_arena_policy_test_audit,
    native_runtime_live_client_page_test_audit,
    native_runtime_live_client_uses_startup_regular_arena_test_audit,
    ticket_zero_allocate, ticket_zero_free,
};

const CHILD_MARKER: &str = "CRABC_M2_NATIVE_RUNTIME_STARTUP_REGULAR_ARENA_CHILD";
const CHILD_SCENARIO: &str = "CRABC_M2_NATIVE_RUNTIME_STARTUP_REGULAR_ARENA_SCENARIO";
const CHILD_TRACE_PATH: &str = "CRABC_M2_NATIVE_RUNTIME_STARTUP_REGULAR_ARENA_TRACE_PATH";
const TEST_NAME: &str =
    "runtime_ticket_zero_uses_source_startup_regular_arena_and_source_fallbacks";
const TRACE_BEGIN: &str = "CRABC_MI_RUNTIME_STARTUP_REGULAR_ARENA_TRACE_BEGIN";
const TRACE_END: &str = "CRABC_MI_RUNTIME_STARTUP_REGULAR_ARENA_TRACE_END";
const STARTUP_RESERVE_BYTES: usize = 64 * 1024 * 1024;
const LAZY_RESERVE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    ReuseStartupRegular,
    ReuseStartupRegularDisallowOs,
    FailedStartupRegularFallsBack,
    AbsentStartupRegularFallsBack,
    AbsentStartupRegularDisallowOsFails,
    IneligibleStartupRegularUsesDirectOs,
    IneligibleStartupRegularDisallowOsFails,
}

impl Scenario {
    const ALL: [Self; 7] = [
        Self::ReuseStartupRegular,
        Self::ReuseStartupRegularDisallowOs,
        Self::FailedStartupRegularFallsBack,
        Self::AbsentStartupRegularFallsBack,
        Self::AbsentStartupRegularDisallowOsFails,
        Self::IneligibleStartupRegularUsesDirectOs,
        Self::IneligibleStartupRegularDisallowOsFails,
    ];

    fn key(self) -> &'static str {
        match self {
            Self::ReuseStartupRegular => "reuse",
            Self::ReuseStartupRegularDisallowOs => "reuse-disallow-os",
            Self::FailedStartupRegularFallsBack => "failed",
            Self::AbsentStartupRegularFallsBack => "absent",
            Self::AbsentStartupRegularDisallowOsFails => "absent-disallow-os",
            Self::IneligibleStartupRegularUsesDirectOs => "ineligible",
            Self::IneligibleStartupRegularDisallowOsFails => "ineligible-disallow-os",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scenario| scenario.key() == value)
    }

    fn startup_option(self) -> Option<&'static str> {
        match self {
            Self::ReuseStartupRegular
            | Self::ReuseStartupRegularDisallowOs
            | Self::IneligibleStartupRegularUsesDirectOs
            | Self::IneligibleStartupRegularDisallowOsFails => Some("64M"),
            // Pinned `mi_reserve_os_memory_ex2` aligns this to one slice, then
            // `mi_manage_os_memory_ex2` rejects it below `MI_ARENA_MIN_SIZE`.
            // init.c ignores that error and the later first allocation may
            // take the ordinary fresh-arena fallback.
            Self::FailedStartupRegularFallsBack => Some("1K"),
            Self::AbsentStartupRegularFallsBack | Self::AbsentStartupRegularDisallowOsFails => None,
        }
    }

    fn expected_startup_outcome(self) -> usize {
        match self {
            Self::ReuseStartupRegular
            | Self::ReuseStartupRegularDisallowOs
            | Self::IneligibleStartupRegularUsesDirectOs
            | Self::IneligibleStartupRegularDisallowOsFails => 1,
            Self::FailedStartupRegularFallsBack => 2,
            Self::AbsentStartupRegularFallsBack | Self::AbsentStartupRegularDisallowOsFails => 0,
        }
    }

    fn expects_startup_parent(self) -> bool {
        matches!(
            self,
            Self::ReuseStartupRegular
                | Self::ReuseStartupRegularDisallowOs
                | Self::IneligibleStartupRegularUsesDirectOs
                | Self::IneligibleStartupRegularDisallowOsFails
        )
    }

    fn disallows_arena_alloc(self) -> bool {
        matches!(
            self,
            Self::IneligibleStartupRegularUsesDirectOs
                | Self::IneligibleStartupRegularDisallowOsFails
        )
    }

    fn expects_direct_os_client(self) -> bool {
        matches!(self, Self::IneligibleStartupRegularUsesDirectOs)
    }

    fn disallows_os_alloc(self) -> bool {
        matches!(
            self,
            Self::ReuseStartupRegularDisallowOs
                | Self::AbsentStartupRegularDisallowOsFails
                | Self::IneligibleStartupRegularDisallowOsFails
        )
    }

    fn expects_allocation_failure(self) -> bool {
        matches!(
            self,
            Self::AbsentStartupRegularDisallowOsFails
                | Self::IneligibleStartupRegularDisallowOsFails
        )
    }
}

/// One short-lived parent-owned scalar trace file below the runner's `TMPDIR`.
///
/// The parent creates it exclusively and removes it on every return/unwind.
/// Each child gets only its path and appends no allocation address or lifecycle
/// capability. This preserves observations from seven fresh process images
/// without forwarding nested libtest summaries into the evidence parser.
struct ChildTraceFile {
    path: PathBuf,
}

impl ChildTraceFile {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "crabc-mimalloc-startup-regular-arena-{}.trace",
            std::process::id()
        ));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("the parent creates one exclusive startup-regular trace");
        Self { path }
    }

    fn path(&self) -> &Path { &self.path }

    fn read(&self) -> String {
        fs::read_to_string(&self.path)
            .expect("successful source-start children append their scalar trace")
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

fn run_in_clean_source_environment() {
    let trace_file = ChildTraceFile::create();
    for scenario in Scenario::ALL {
        let mut command = Command::new(
            std::env::current_exe().expect("the focused native witness has its executable path"),
        );
        command
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--test-threads=1")
            // Each child receives only the source inputs its one route needs.
            // A parent-owned trace path carries scalar results without
            // importing an ambient option image into the child.
            .env_clear()
            .env(CHILD_MARKER, "1")
            .env(CHILD_SCENARIO, scenario.key())
            .env(CHILD_TRACE_PATH, trace_file.path())
            .env("mimalloc_arena_reserve", "128M")
            .env("mimalloc_arena_eager_commit", "1")
            .env("mimalloc_allow_large_os_pages", "0")
            .env("mimalloc_allow_thp", "0")
            .env("mimalloc_use_numa_nodes", "1");
        if let Some(value) = scenario.startup_option() {
            command.env("mimalloc_reserve_os_memory", value);
        }
        if scenario.disallows_arena_alloc() {
            command.env("mimalloc_disallow_arena_alloc", "1");
        }
        if scenario.disallows_os_alloc() {
            command.env("mimalloc_disallow_os_alloc", "1");
        }
        let output = command
            .output()
            .expect("the source-startup regular-arena child starts");
        assert_eq!(
            output.status.code(),
            Some(0),
            "the {} child completes\nstdout:\n{}\nstderr:\n{}",
            scenario.key(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let trace = trace_file.read();
    let expected_rows = Scenario::ALL.len() * 11;
    assert_eq!(
        trace.lines().count(),
        expected_rows,
        "each process-isolated source route writes its eleven scalar observations\ntrace:\n{trace}",
    );
    println!();
    println!("{TRACE_BEGIN}");
    print!("{trace}");
    println!("{TRACE_END}");
}

fn startup_identity_scalar(
    block: core::ptr::NonNull<u8>,
) -> usize {
    // SAFETY: the caller owns `block` and samples before any free, worker, or
    // other PageMap mutation. The default-off audit only compares identities.
    match unsafe { native_runtime_live_client_uses_startup_regular_arena_test_audit(block) } {
        Some(true) => 1,
        Some(false) => 0,
        None => 2,
    }
}

fn append_trace(scenario: Scenario, values: [usize; 11]) {
    let path = std::env::var_os(CHILD_TRACE_PATH)
        .expect("the source-startup child receives its parent-owned trace path");
    let names = [
        "ticket_zero_result",
        "startup_outcome",
        "registry_after_init",
        "client_is_arena_backed",
        "client_startup_identity",
        "sidecar_vm_reservations",
        "registry_after_allocation",
        "arena_size_after_allocation",
        "arena_initially_committed",
        "registry_after_free",
        "page_map_entries_after_free",
    ];
    let mut output = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("the parent-owned trace remains appendable to the child");
    for (name, value) in names.into_iter().zip(values) {
        writeln!(output, "{}_{}={value}", scenario.key(), name)
            .expect("the child appends one scalar source-start observation");
    }
    output.sync_all().expect("the child synchronizes its scalar trace");
}

#[test]
fn runtime_ticket_zero_uses_source_startup_regular_arena_and_source_fallbacks() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        run_in_clean_source_environment();
        return;
    }
    let scenario = std::env::var(CHILD_SCENARIO)
        .ok()
        .and_then(|value| Scenario::parse(&value))
        .expect("the child names one fixed source-start route");

    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime accepts the source startup option image"
    );
    let initial = native_runtime_first_arena_policy_test_audit()
        .expect("the active process exposes its zero-or-one first-arena policy state");
    let registry_after_init = initial.arena_registry_count;
    assert_eq!(
        registry_after_init != 0,
        scenario.expects_startup_parent(),
        "only a successful 64-MiB source startup reservation publishes before ticket-zero allocation",
    );

    let allocation = ticket_zero_allocate(79, false);
    let ticket_zero_result = match &allocation {
        TicketZeroPageAllocationResult::Allocated(_) => 1,
        TicketZeroPageAllocationResult::AllocationFailed => 0,
        TicketZeroPageAllocationResult::Unavailable => 2,
        TicketZeroPageAllocationResult::Retained => 3,
    };
    assert_eq!(
        ticket_zero_result,
        usize::from(!scenario.expects_allocation_failure()),
        "the source disallow-OS path has a typed allocation failure, while an existing startup parent remains searchable",
    );

    if scenario.expects_allocation_failure() {
        assert!(
            matches!(&allocation, TicketZeroPageAllocationResult::AllocationFailed),
            "the source direct-OS refusal must not become unavailable or terminally retained",
        );
        let retry = ticket_zero_allocate(79, false);
        assert!(
            matches!(&retry, TicketZeroPageAllocationResult::AllocationFailed),
            "the source policy refusal remains retryable and must not retain a fresh sidecar owner",
        );
        let after = native_runtime_first_arena_policy_test_audit()
            .expect("a failed first allocation leaves the process policy auditable");
        assert_eq!(after.process_active, 1);
        assert_eq!(after.startup_regular_reservation_outcome, scenario.expected_startup_outcome());
        assert_eq!(after.vm_policy_disallow_arena_alloc, usize::from(scenario.disallows_arena_alloc()));
        assert_eq!(after.vm_policy_disallow_os_alloc, 1);
        assert_eq!(after.process_backing_first_arena_begin_count, 1);
        assert_eq!(after.process_backing_vm_reservation_count, 0);
        assert_eq!(after.arena_registry_count, usize::from(scenario.expects_startup_parent()));
        assert_eq!(
            after.process_arena_size,
            if scenario.expects_startup_parent() { STARTUP_RESERVE_BYTES } else { 0 },
        );
        assert_eq!(
            after.process_arena_initially_committed,
            usize::from(scenario.expects_startup_parent()),
        );
        assert_eq!(after.page_map_registered_entry_count, 0);
        append_trace(
            scenario,
            [
                ticket_zero_result,
                after.startup_regular_reservation_outcome,
                registry_after_init,
                0,
                2,
                after.process_backing_vm_reservation_count,
                after.arena_registry_count,
                after.process_arena_size,
                after.process_arena_initially_committed,
                after.arena_registry_count,
                after.page_map_registered_entry_count,
            ],
        );
        return;
    }

    let block = match allocation {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("the source-selected ticket-zero route supplies its first client")
        }
    };
    // SAFETY: this fresh child owns the current ticket-zero allocation until
    // the exact matching free below.
    unsafe {
        block.as_ptr().write(0x6d);
        assert_eq!(block.as_ptr().read(), 0x6d);
    }

    // SAFETY: `block` is current and unique; this process-isolated child has
    // no other allocator worker or PageMap mutation in flight.
    let client_is_arena_backed = usize::from(
        unsafe { native_runtime_live_client_page_test_audit(block) }.is_some(),
    );
    let client_startup_identity = startup_identity_scalar(block);
    let live = native_runtime_first_arena_policy_test_audit()
        .expect("the active source route exposes scalar first-arena facts");
    assert_eq!(
        live.startup_regular_reservation_outcome,
        scenario.expected_startup_outcome(),
        "the retained startup result distinguishes absent, published, and ignored failed source reservation",
    );
    assert_eq!(live.process_active, 1);
    assert_eq!(live.vm_policy_disallow_arena_alloc, usize::from(scenario.expects_direct_os_client()));
    assert_eq!(live.vm_policy_disallow_os_alloc, usize::from(scenario.disallows_os_alloc()));
    assert_eq!(live.process_backing_first_arena_begin_count, 1);
    assert!(live.page_map_registered_entry_count > 0);
    assert_eq!(live.process_arena_initially_committed, 1);
    assert_eq!(live.arena_registry_count, 1);

    if scenario.expects_startup_parent() {
        assert_eq!(live.process_backing_vm_reservation_count, 0);
        assert_eq!(live.process_arena_size, STARTUP_RESERVE_BYTES);
    } else {
        assert_eq!(live.process_backing_vm_reservation_count, 1);
        assert_eq!(live.process_arena_size, LAZY_RESERVE_BYTES);
    }
    if scenario.expects_direct_os_client() {
        assert_eq!(client_is_arena_backed, 0);
        assert_eq!(client_startup_identity, 2);
    } else {
        assert_eq!(client_is_arena_backed, 1);
        assert_eq!(
            client_startup_identity,
            if scenario.expects_startup_parent() { 1 } else { 2 },
        );
    }

    // SAFETY: `block` is the current unique result above and has not crossed
    // a thread or another allocation boundary.
    assert_eq!(unsafe { ticket_zero_free(block) }, TicketZeroPageFreeResult::Freed);
    let after = native_runtime_first_arena_policy_test_audit()
        .expect("the retained process arena remains auditable after client free");
    assert_eq!(after.startup_regular_reservation_outcome, scenario.expected_startup_outcome());
    assert_eq!(after.process_backing_vm_reservation_count, live.process_backing_vm_reservation_count);
    assert_eq!(after.process_arena_size, live.process_arena_size);
    assert_eq!(after.process_arena_initially_committed, 1);
    assert_eq!(after.arena_registry_count, 1);
    assert_eq!(after.page_map_registered_entry_count, 0);

    append_trace(
        scenario,
        [
            ticket_zero_result,
            live.startup_regular_reservation_outcome,
            registry_after_init,
            client_is_arena_backed,
            client_startup_identity,
            live.process_backing_vm_reservation_count,
            live.arena_registry_count,
            live.process_arena_size,
            live.process_arena_initially_committed,
            after.arena_registry_count,
            after.page_map_registered_entry_count,
        ],
    );
}
