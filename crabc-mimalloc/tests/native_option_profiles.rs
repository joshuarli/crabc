// Rust half of the M7 option-profile differential driven by
// `compat/allocator/x86_64_m7_gate.py --option-profiles-differential`. The
// pinned C probe `x86_64_m7_option_profiles_oracle.c` runs the same
// allocations under the same `mimalloc_*` environment image and prints the
// same keys: the process PageMap's reserved size and full commitment, the
// arena count after startup, the process THP state, then whether each
// request failed, its page's `mi_memkind_t` and `slice_pcommitted`, and the
// size, eager commitment and NUMA node of the first arena.
#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, native_allocate, native_free,
    native_runtime_lifecycle_test_audit, native_runtime_live_client_memory_kind_test_audit,
    native_runtime_live_client_slice_pcommitted_test_audit, native_runtime_process_options_test_audit,
};

fn report(name: &str, size: usize) {
    match native_allocate(size, false) {
        NativePageAllocationResult::Allocated(block) => {
            // SAFETY: the exact live client from this request; its owner is
            // this quiescent thread.
            let kind = unsafe { native_runtime_live_client_memory_kind_test_audit(block) }
                .expect("a live native client has a page");
            println!("profile.{name}.null=0");
            println!("profile.{name}.memkind={kind}");
            // SAFETY: as above.
            let committed = unsafe { native_runtime_live_client_slice_pcommitted_test_audit(block) }
                .expect("a live native client has a page");
            println!("profile.{name}.slice_pcommitted={committed}");
            // SAFETY: the exact live client, freed once.
            assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        }
        NativePageAllocationResult::AllocationFailed => {
            println!("profile.{name}.null=1");
            println!("profile.{name}.memkind=-1");
            println!("profile.{name}.slice_pcommitted=-1");
        }
        NativePageAllocationResult::Unavailable => panic!("{name}: the native runtime is unavailable"),
        NativePageAllocationResult::Retained => panic!("{name}: the native owner was retained"),
    }
}

/// Process decisions after the first allocation: the PageMap geometry (`max_vabits`,
/// `pagemap_commit`), the arenas startup reserved (`reserve_os_memory`,
/// `reserve_huge_os_pages`), and the kernel's per-process THP state after
/// `_mi_prim_mem_init` (`allow_thp`).
fn report_process() {
    let audit = native_runtime_process_options_test_audit().expect("the active process has an options audit");
    println!("profile.page_map={},{}", audit.page_map_reserved_size, u8::from(audit.page_map_fully_committed));
    println!("profile.arena_count={}", audit.arena_count);
    let status = std::fs::read_to_string("/proc/self/status").expect("the process status is readable");
    let thp = status
        .lines()
        .find_map(|line| line.strip_prefix("THP_enabled:"))
        .map_or("absent", str::trim);
    println!("profile.thp_enabled={thp}");
}

/// The arena backing a first small allocation: the process's canonical
/// first arena, its size and eager commitment.
fn report_first_arena() {
    let NativePageAllocationResult::Allocated(block) = native_allocate(64, false) else {
        println!("profile.first_arena=none");
        return;
    };
    // SAFETY: the exact live client; its owner is this quiescent thread.
    let arena_backed = unsafe { native_runtime_live_client_memory_kind_test_audit(block) } == Some(6);
    if arena_backed {
        let audit = native_runtime_lifecycle_test_audit().expect("the active process has a lifecycle audit");
        println!(
            "profile.first_arena={},{},{}",
            audit.process_arena_size, audit.process_arena_initially_committed, audit.process_arena_numa_node,
        );
    } else {
        println!("profile.first_arena=none");
    }
    // SAFETY: the exact live client, freed once.
    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
}

#[test]
fn option_profiles_match_the_pinned_source() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ");
    assert!(native_runtime_test_support::initialize(page_size));
    println!("CRABC_MI_M7_OPTION_PROFILES_TRACE_BEGIN");
    report_first_arena();
    report_process();
    report("small", 64);
    report("medium", 200 * 1024);
    report("large", 3 * 1024 * 1024);
    report("huge", 48 * 1024 * 1024);
    println!("CRABC_MI_M7_OPTION_PROFILES_TRACE_END");
}
