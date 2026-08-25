#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

const DSO_SONAME: &str = "libloader_dlfcn_introspection.so";

fn build_dso(source: &std::path::Path, output: &std::path::Path) {
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-shared",
            "-fPIC",
            "-DLOADER_STATE_SYMBOL=loader_dlfcn_introspection_state",
            "-DLOADER_VALUE_SYMBOL=loader_dlfcn_introspection_value",
            source.to_str().unwrap(),
            "-Wl,--soname,libloader_dlfcn_introspection.so",
            "-o",
            output.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run crabc-cc for loader introspection DSO");
    assert!(
        status.success(),
        "loader introspection DSO compilation failed"
    );
    let dynamic = Command::new("readelf")
        .args(["-d"])
        .arg(output)
        .output()
        .expect("failed to inspect loader introspection DSO dynamic section");
    assert!(
        dynamic.status.success(),
        "readelf failed for loader introspection DSO"
    );
    assert!(
        String::from_utf8_lossy(&dynamic.stdout)
            .contains(&format!("Library soname: [{DSO_SONAME}]")),
        "loader introspection DSO is missing its requested SONAME",
    );
}

#[test]
fn native_loader_introspection_copies_bounded_records() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = root.join("tests/fixtures");
    let target = root.join("target");
    let debug = target.join("debug");
    let archive = target.join("release/examples/libloader_dlfcn_introspection_probe.a");
    let dso_source = fixtures.join("loader_dlfcn_basic_dso.c");
    let fixture = fixtures.join("loader_dlfcn_introspection_test.c");
    let dso = test_support::TempArtifact::new("libloader_dlfcn_introspection.so");
    let binary = test_support::TempArtifact::new("crabc-loader-loader-dlfcn-introspection");

    build_dso(&dso_source, &dso);

    let probe_build = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "-p",
            "crabc-rs",
            "--example",
            "loader_dlfcn_introspection_probe",
            "--release",
            "--no-default-features",
            "--features",
            "runtime-loader",
        ])
        .status()
        .expect("failed to build the loader introspection probe archive");
    assert!(
        probe_build.success(),
        "loader introspection probe archive did not build"
    );
    assert!(debug.join("libldso.so").is_file(), "libldso.so not found");
    assert!(debug.join("libc.so").is_file(), "libc.so not found");
    assert!(
        archive.is_file(),
        "loader introspection probe archive not found"
    );

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
        .expect("failed to compile loader introspection fixture");
    assert!(
        status.success(),
        "loader introspection fixture compilation failed"
    );

    let library_path = format!("{}:{}", debug.display(), dso.parent().display());
    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &library_path)
        .output()
        .expect("failed to run loader introspection fixture");
    assert!(
        output.status.success(),
        "loader introspection fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"loader loader dlfcn introspection ok\n");
}
