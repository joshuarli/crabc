#![cfg(target_arch = "x86_64")]

use crabc_rs::process::{self, ResourceUsage, ResourceUsageTarget};

fn time_key(time: crabc_rs::process::ResourceUsageTime) -> (i64, i64) {
    (time.seconds(), time.microseconds())
}

fn assert_usage_is_kernel_canonical(usage: ResourceUsage) {
    assert!((0..1_000_000).contains(&usage.user_time.microseconds()));
    assert!((0..1_000_000).contains(&usage.system_time.microseconds()));
    assert!(usage.user_time.seconds() >= 0);
    assert!(usage.system_time.seconds() >= 0);
    assert!(usage.maximum_resident_set_size >= 0);
    assert!(usage.integral_shared_memory_size >= 0);
    assert!(usage.integral_unshared_data_size >= 0);
    assert!(usage.integral_unshared_stack_size >= 0);
    assert!(usage.minor_page_faults >= 0);
    assert!(usage.major_page_faults >= 0);
    assert!(usage.swaps >= 0);
    assert!(usage.block_input_operations >= 0);
    assert!(usage.block_output_operations >= 0);
    assert!(usage.ipc_messages_sent >= 0);
    assert!(usage.ipc_messages_received >= 0);
    assert!(usage.signals_received >= 0);
    assert!(usage.voluntary_context_switches >= 0);
    assert!(usage.involuntary_context_switches >= 0);
}

#[test]
fn x86_64_resource_usage_target_vocabulary_matches_linux() {
    assert_eq!(ResourceUsageTarget::SelfProcess.as_raw(), 0);
    assert_eq!(ResourceUsageTarget::Children.as_raw(), -1);
    assert_eq!(ResourceUsageTarget::Thread.as_raw(), 1);
}

#[test]
fn x86_64_getrusage_reads_each_closed_target() {
    for target in [
        ResourceUsageTarget::SelfProcess,
        ResourceUsageTarget::Children,
        ResourceUsageTarget::Thread,
    ] {
        let usage = process::getrusage(target).expect("read Linux resource usage");
        assert_usage_is_kernel_canonical(usage);
    }
}

#[test]
fn x86_64_getrusage_is_read_only_and_counters_do_not_decrease() {
    let first = process::getrusage(ResourceUsageTarget::SelfProcess)
        .expect("read initial Linux resource usage");

    let mut checksum = 0_u64;
    for value in 0..100_000_u64 {
        checksum = checksum.wrapping_add(value);
    }
    assert_ne!(checksum, 0);

    let second = process::getrusage(ResourceUsageTarget::SelfProcess)
        .expect("read subsequent Linux resource usage");
    assert_usage_is_kernel_canonical(first);
    assert_usage_is_kernel_canonical(second);
    assert!(time_key(second.user_time) >= time_key(first.user_time));
    assert!(time_key(second.system_time) >= time_key(first.system_time));
    assert!(second.maximum_resident_set_size >= first.maximum_resident_set_size);
    assert!(second.integral_shared_memory_size >= first.integral_shared_memory_size);
    assert!(second.integral_unshared_data_size >= first.integral_unshared_data_size);
    assert!(second.integral_unshared_stack_size >= first.integral_unshared_stack_size);
    assert!(second.minor_page_faults >= first.minor_page_faults);
    assert!(second.major_page_faults >= first.major_page_faults);
    assert!(second.swaps >= first.swaps);
    assert!(second.block_input_operations >= first.block_input_operations);
    assert!(second.block_output_operations >= first.block_output_operations);
    assert!(second.ipc_messages_sent >= first.ipc_messages_sent);
    assert!(second.ipc_messages_received >= first.ipc_messages_received);
    assert!(second.signals_received >= first.signals_received);
    assert!(second.voluntary_context_switches >= first.voluntary_context_switches);
    assert!(second.involuntary_context_switches >= first.involuntary_context_switches);
}
