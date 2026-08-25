//! C public headers must remain consumable by a C++ compiler.
//!
//! This compiles only through the sealed installed `crabc-cc` driver.  It
//! catches C-only declaration tokens that would otherwise block libc++,
//! libunwind, and ordinary C++ consumers before any runtime link occurs.

#[path = "common/mod.rs"]
mod test_support;

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[test]
fn public_c_headers_compile_as_cxx17_through_the_owned_sysroot() {
    use std::path::Path;
    use std::process::Command;

    let repository = Path::new(test_support::REPOSITORY_ROOT);
    let fixture = repository.join("tests/fixtures/cxx_header_compat_test.cc");
    let object = test_support::TempArtifact::new("cxx_header_compat.o");

    let output = Command::new(test_support::crabc_cc())
        .args([
            "-std=c++17",
            "-c",
            fixture.to_str().unwrap(),
            "-o",
            object.to_str().unwrap(),
        ])
        .output()
        .expect("failed to invoke the owned driver for the C++ header probe");
    assert!(
        output.status.success(),
        "crabc public C headers are not C++17-consumable through the owned sysroot: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(object.is_file(), "C++ header probe did not produce an object");
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[test]
fn public_c_headers_compile_as_cxx17_through_the_owned_sysroot_is_native_only() {}
