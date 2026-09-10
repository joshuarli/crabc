// This focused native witness compiles `crabc-mimalloc` as an ordinary
// dependency, so x86-64 uses the non-test `RuntimeProcessStorage` route:
// `process_backing` -> `begin_for_process` -> policy-bound first arena.
// The scalar audit remains default-off and exposes no allocation address or
// owner capability.
#![cfg(feature = "native-runtime-test-audit")]

use std::process::Command;

use crabc_mimalloc::__crabc_runtime::{
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, initialize_process,
    native_runtime_lifecycle_test_audit, ticket_zero_allocate, ticket_zero_free,
};

const CHILD_MARKER: &str = "CRABC_M2_NATIVE_RUNTIME_FIRST_ARENA_POLICY_CHILD";
const ARENA_RESERVE_BYTES: usize = 128 * 1024 * 1024;
const TEST_NAME: &str =
    "runtime_process_uses_source_vm_policy_for_ticket_zero_first_arena_and_client_cleanup";

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux witness has a validated page size")
}

fn run_in_clean_source_environment() {
    let output = Command::new(
        std::env::current_exe().expect("the focused native witness has its executable path"),
    )
    .arg("--exact")
    .arg(TEST_NAME)
    .arg("--test-threads=1")
    // The child receives only the selected lower-case source variables. This
    // prevents an inherited `mimalloc_*` value from supplying the observation
    // the runtime must read through its raw `environ` binding.
    .env_clear()
    .env(CHILD_MARKER, "1")
    .env("mimalloc_arena_reserve", "128M")
    .env("mimalloc_arena_eager_commit", "2")
    .env("mimalloc_allow_large_os_pages", "0")
    .env("mimalloc_allow_thp", "0")
    .output()
    .expect("the source-policy child starts");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the source-policy child completes the native runtime witness\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn runtime_process_uses_source_vm_policy_for_ticket_zero_first_arena_and_client_cleanup() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        run_in_clean_source_environment();
        return;
    }

    assert!(
        initialize_process(current_page_size()),
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
    assert_eq!(live.process_backing_vm_reservation_count, 1);
    assert_eq!(live.vm_policy_arena_reserve_bytes, ARENA_RESERVE_BYTES);
    assert_eq!(live.vm_policy_arena_eager_commit, 2);
    assert_eq!(live.vm_policy_allow_large_os_pages, 0);
    assert_eq!(live.vm_policy_allow_thp, 0);
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
    assert_eq!(after.process_backing_vm_reservation_count, 1);
    assert_eq!(after.vm_policy_arena_reserve_bytes, ARENA_RESERVE_BYTES);
    assert_eq!(after.process_arena_size, ARENA_RESERVE_BYTES);
    assert_eq!(after.process_arena_initially_committed, 1);
    assert_eq!(after.arena_registry_count, 1);
    assert_eq!(
        after.page_map_registered_entry_count, 0,
        "the exact client free releases its PageMap registration while the process arena remains owned"
    );
    assert_eq!(after.main_heap_abandoned_page_count, 0);
    assert_eq!(after.main_heap_os_abandoned_pages_empty, 1);
}
