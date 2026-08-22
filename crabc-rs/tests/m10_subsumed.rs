//! Dependency-free behavior evidence for the bounded M10 subsumption ledger.

use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt::Write as _;
use std::process::Command;

#[test]
fn abort_is_immediate_process_termination() {
    if std::env::var_os("CRABC_RS_ABORT_CHILD").is_some() {
        std::process::abort();
    }

    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("abort_is_immediate_process_termination")
        .arg("--nocapture")
        .env("CRABC_RS_ABORT_CHILD", "1")
        .status()
        .expect("spawn abort child");
    assert!(!status.success(), "abort must not return successfully");
    assert!(status.code().is_none(), "abort must terminate by signal");
}

#[test]
fn ordinary_bytes_are_typed_slice_operations() {
    let mut bytes = [0u8; 5];
    bytes.copy_from_slice(b"abcde");
    assert_eq!(bytes, *b"abcde");
    bytes.fill(b'x');
    assert_eq!(bytes, *b"xxxxx");

    let haystack = b"abracadabra";
    assert_eq!(haystack.iter().position(|byte| *byte == b'c'), Some(4));
    assert_eq!(haystack.windows(3).position(|window| window == b"dab"), Some(6));
    assert_eq!(haystack.cmp(b"abracadabra"), std::cmp::Ordering::Equal);
}

#[test]
fn byte_string_observations_keep_the_nul_boundary_explicit() {
    let value = CStr::from_bytes_with_nul(b"crabc-rs\0").expect("one trailing NUL");
    assert_eq!(value.to_bytes(), b"crabc-rs");
    assert_eq!(value.to_bytes().iter().position(|byte| *byte == b'-'), Some(5));
    assert_eq!(value.to_bytes().split(|byte| *byte == b'-').count(), 2);
}

#[test]
fn numeric_operations_and_qsort_use_typed_results() {
    assert_eq!((-42_i32).abs(), 42);
    assert_eq!((-17_i32) / 5, -3);
    assert_eq!((-17_i32) % 5, -2);
    assert_eq!(0b0010_0000_u32.trailing_zeros(), 5);

    let mut values = [9, 1, 7, 3, 5];
    values.sort();
    assert_eq!(values, [1, 3, 5, 7, 9]);
}

#[test]
fn hash_map_owns_entries_and_supports_observation() {
    let mut values = HashMap::new();
    values.insert("open", 2_u32);
    values.insert("read", 0_u32);
    assert_eq!(values.get("open"), Some(&2));
    assert_eq!(values.get("missing"), None);
    assert_eq!(values.len(), 2);
}

#[test]
fn growing_formatted_output_is_owned_and_not_bounded_printf() {
    let mut output = String::new();
    write!(&mut output, "{}:{}", "crabc", 10).expect("String is writable");
    assert_eq!(output, "crabc:10");

    let owned = format!("{} {}", "owned", "output");
    assert_eq!(owned, "owned output");
}

#[test]
fn rust_allocation_policy_uses_owned_box_and_vec_not_malloc_usable_size() {
    let boxed = Box::new(7_u32);
    let mut values = Vec::with_capacity(2);
    values.push(*boxed);
    values.push(8);
    assert_eq!(values, [7, 8]);
}
