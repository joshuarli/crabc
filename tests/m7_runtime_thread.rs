#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn native_runtime_thread_uses_libc_owned_state() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target");
    let debug = target.join("debug");
    let archive = target
        .join("release/examples/libm7_runtime_thread_probe.a");
    let fixture = root.join("tests/fixtures/m7_runtime_thread_test.c");
    let binary = test_support::TempArtifact::new("crabc-m7-runtime-thread");

    let probe_build = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "-p",
            "crabc-rs",
            "--example",
            "m7_runtime_thread_probe",
            "--release",
            "--no-default-features",
            "--features",
            "runtime-thread",
        ])
        .status()
        .expect("failed to build the M7 native thread probe archive");
    assert!(probe_build.success(), "M7 native thread probe archive did not build");
    assert!(debug.join("libldso.so").is_file(), "libldso.so not found");
    assert!(debug.join("libc.so").is_file(), "libc.so not found");
    assert!(archive.is_file(), "M7 native thread probe archive not found");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            debug.join("libldso.so").to_str().unwrap(),
            "-L",
            debug.to_str().unwrap(),
            fixture.to_str().unwrap(),
            archive.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile M7 native thread runtime fixture");
    assert!(status.success(), "M7 native thread runtime fixture did not compile");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &debug)
        .output()
        .expect("failed to run M7 native thread runtime fixture");
    assert!(
        output.status.success(),
        "M7 native thread runtime fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "m7 runtime thread ok\n"
    );
}
