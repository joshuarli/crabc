#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

fn build_dso(
    source: &std::path::Path,
    output: &std::path::Path,
    soname: &str,
    state_symbol: &str,
    value_symbol: &str,
) {
    let state_define = format!("-DM11_STATE_SYMBOL={state_symbol}");
    let value_define = format!("-DM11_VALUE_SYMBOL={value_symbol}");
    let status = Command::new("musl-gcc")
        .args([
            "-shared",
            "-fPIC",
            state_define.as_str(),
            value_define.as_str(),
            source.to_str().unwrap(),
            "-Wl,--soname",
            soname,
            "-o",
            output.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for M11 loader DSO");
    assert!(status.success(), "M11 loader DSO compilation failed");
}

#[test]
fn native_loader_basic_owns_handles_and_uses_private_runtime() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = root.join("tests/fixtures");
    let target = root.join("target");
    let debug = target.join("debug");
    let archive = target
        .join("release/examples/libm11_loader_dlfcn_basic_probe.a");
    let dso_source = fixtures.join("m11_loader_dlfcn_basic_dso.c");
    let fixture = fixtures.join("m11_loader_dlfcn_basic_test.c");
    let close_dso = test_support::TempArtifact::new("libm11_loader_close.so");
    let drop_dso = test_support::TempArtifact::new("libm11_loader_drop.so");
    let binary = test_support::TempArtifact::new("crabc-m11-loader-dlfcn-basic");

    build_dso(
        &dso_source,
        &close_dso,
        "libm11_loader_close.so",
        "m11_loader_close_state",
        "m11_loader_value",
    );
    build_dso(
        &dso_source,
        &drop_dso,
        "libm11_loader_drop.so",
        "m11_loader_drop_state",
        "m11_loader_value",
    );

    let probe_build = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "-p",
            "crabc-rs",
            "--example",
            "m11_loader_dlfcn_basic_probe",
            "--release",
            "--no-default-features",
            "--features",
            "runtime-loader",
        ])
        .status()
        .expect("failed to build the M11 native loader probe archive");
    assert!(probe_build.success(), "M11 native loader probe archive did not build");
    assert!(debug.join("libldso.so").is_file(), "libldso.so not found");
    assert!(debug.join("libc.so").is_file(), "libc.so not found");
    assert!(archive.is_file(), "M11 native loader probe archive not found");

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
        .expect("failed to compile M11 native loader fixture");
    assert!(status.success(), "M11 native loader fixture compilation failed");

    let library_path = format!(
        "{}:{}:{}",
        debug.display(),
        close_dso.parent().display(),
        drop_dso.parent().display()
    );
    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &library_path)
        .output()
        .expect("failed to run M11 native loader fixture");
    assert!(
        output.status.success(),
        "M11 native loader fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"m11 loader dlfcn basic ok\n");
}
