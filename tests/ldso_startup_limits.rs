#[path = "common/mod.rs"]
mod test_support;

#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::Command;

#[test]
fn ldso_preserves_large_startup_vectors_and_auxv() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixture = manifest_dir.join("tests/fixtures/ldso_startup_limits_test.c");
    let target = manifest_dir.join("target/debug");
    let binary = test_support::TempArtifact::new("ldso_startup_limits_test");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-D_GNU_SOURCE",
            "-I",
            manifest_dir.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            fixture.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for startup limits fixture");
    assert!(
        status.success(),
        "startup limits fixture compilation failed"
    );

    let mut command = Command::new(&binary);
    #[cfg(unix)]
    command.arg0("spoofed-argv0");
    for i in 0..199 {
        command.arg(format!("arg-{i}"));
    }
    for i in 0..700 {
        command.env(format!("CRABC_STARTUP_{i}"), "value");
    }
    let output = command
        .env("LD_LIBRARY_PATH", target)
        .output()
        .expect("failed to run startup limits fixture");
    assert!(
        output.status.success(),
        "startup limits fixture exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envc = stdout
        .strip_prefix("argc=200 envc=")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("unexpected startup vector output: {stdout}"));
    assert!(envc >= 700, "environment entries were truncated: {stdout}");
    assert!(
        stdout.contains(" execfn_nonnull=1 execfn_diff=1 platform=1\n"),
        "auxv entries were not preserved accurately: {stdout}"
    );
}
