use std::process::Command;

#[test]
fn ldso_initializes_dlopen_tls_for_existing_threads() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso = target.join("libldso.so");
    let dso = target.join("libdynamic_tls.so");
    let binary = fixtures.join("ldso_dynamic_tls_test");

    let status = Command::new("musl-gcc")
        .args([
            "-shared",
            "-fPIC",
            fixtures.join("dynamic_tls_dso.c").to_str().unwrap(),
            "-o",
            dso.to_str().unwrap(),
        ])
        .status()
        .expect("failed to build dynamic TLS test DSO");
    assert!(status.success(), "dynamic TLS test DSO compilation failed");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-I",
            include.to_str().unwrap(),
            fixtures.join("ldso_dynamic_tls_test.c").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            ldso.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-ldl",
            "-lpthread",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to build dynamic TLS test executable");
    assert!(status.success(), "dynamic TLS test executable compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", target)
        .output()
        .expect("failed to run dynamic TLS test executable");
    assert!(
        output.status.success(),
        "dynamic TLS test exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "dynamic TLS ok\n");
}
