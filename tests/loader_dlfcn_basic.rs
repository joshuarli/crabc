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
    let state_define = format!("-DLOADER_STATE_SYMBOL={state_symbol}");
    let value_define = format!("-DLOADER_VALUE_SYMBOL={value_symbol}");
    let soname_option = format!("-Wl,--soname,{soname}");
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-shared",
            "-fPIC",
            state_define.as_str(),
            value_define.as_str(),
            source.to_str().unwrap(),
            soname_option.as_str(),
            "-o",
            output.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run crabc-cc for loader DSO");
    assert!(status.success(), "loader DSO compilation failed");
    let dynamic = Command::new("readelf")
        .args(["-d"])
        .arg(output)
        .output()
        .expect("failed to inspect loader DSO dynamic section");
    assert!(dynamic.status.success(), "readelf failed for loader DSO");
    assert!(
        String::from_utf8_lossy(&dynamic.stdout).contains(&format!("Library soname: [{soname}]")),
        "loader DSO is missing its requested SONAME",
    );
}

#[test]
fn native_loader_basic_owns_handles_and_uses_private_runtime() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = root.join("tests/fixtures");
    let target = root.join("target");
    let debug = target.join("debug");
    let archive = target.join("release/examples/libloader_dlfcn_basic_probe.a");
    let dso_source = fixtures.join("loader_dlfcn_basic_dso.c");
    let fixture = fixtures.join("loader_dlfcn_basic_test.c");
    let close_dso = test_support::TempArtifact::new("libloader_dlfcn_close.so");
    let drop_dso = test_support::TempArtifact::new("libloader_dlfcn_drop.so");
    let binary = test_support::TempArtifact::new("crabc-loader-loader-dlfcn-basic");

    build_dso(
        &dso_source,
        &close_dso,
        "libloader_dlfcn_close.so",
        "loader_dlfcn_close_state",
        "loader_dlfcn_value",
    );
    build_dso(
        &dso_source,
        &drop_dso,
        "libloader_dlfcn_drop.so",
        "loader_dlfcn_drop_state",
        "loader_dlfcn_value",
    );

    let probe_build = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "-p",
            "crabc-rs",
            "--example",
            "loader_dlfcn_basic_probe",
            "--release",
            "--no-default-features",
            "--features",
            "runtime-loader",
        ])
        .status()
        .expect("failed to build the native loader probe archive");
    assert!(
        probe_build.success(),
        "native loader probe archive did not build"
    );
    assert!(debug.join("libldso.so").is_file(), "libldso.so not found");
    assert!(debug.join("libc.so").is_file(), "libc.so not found");
    assert!(archive.is_file(), "native loader probe archive not found");

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-I",
            root.join("include").to_str().unwrap(),
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
        .expect("failed to compile native loader fixture");
    assert!(status.success(), "native loader fixture compilation failed");

    let library_path = format!(
        "{}:{}:{}",
        debug.display(),
        close_dso.parent().display(),
        drop_dso.parent().display()
    );
    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &library_path)
        .output()
        .expect("failed to run native loader fixture");
    assert!(
        output.status.success(),
        "native loader fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"loader loader dlfcn basic ok\n");
}
