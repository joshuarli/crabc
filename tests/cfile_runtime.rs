#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn native_cfile_uses_libc_owned_memory_stream_state() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target");
    let debug = target.join("debug");
    let archive = target.join("release/examples/libcfile_direct_probe.a");
    let fixture = root.join("tests/fixtures/cfile_runtime_test.c");
    let binary = test_support::TempArtifact::new("crabc-compat-cfile-runtime");

    let probe_build = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "-p",
            "crabc-rs",
            "--example",
            "cfile_direct_probe",
            "--release",
            "--no-default-features",
            "--features",
            "runtime-stdio",
        ])
        .status()
        .expect("failed to build the native CFile probe archive");
    assert!(
        probe_build.success(),
        "native CFile probe archive did not build"
    );
    assert!(debug.join("libldso.so").is_file(), "libldso.so not found");
    assert!(debug.join("libc.so").is_file(), "libc.so not found");
    assert!(archive.is_file(), "native CFile probe archive not found");

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
        .expect("failed to compile native CFile runtime fixture");
    assert!(
        status.success(),
        "native CFile runtime fixture did not compile"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &debug)
        .output()
        .expect("failed to run native CFile runtime fixture");
    assert!(
        output.status.success(),
        "native CFile runtime fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "compat cfile runtime ok\n"
    );
}
