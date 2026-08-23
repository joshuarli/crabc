#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn c_clock_gettime_uses_vdso_in_the_steady_state_hot_loop() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/vdso_clock_gettime_test.c");
    let binary = test_support::TempArtifact::new("vdso-clock-gettime");
    let trace = binary.parent().join("clock_gettime.trace");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            source.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile the vDSO clock_gettime fixture");
    assert!(
        status.success(),
        "vDSO clock_gettime fixture compilation failed"
    );

    let output = Command::new(&*binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run the vDSO clock_gettime fixture");
    assert!(
        output.status.success(),
        "vDSO clock_gettime fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "vdso clock route ok\n",
    );

    let trace_output = Command::new("strace")
        .args([
            "-f",
            "-qq",
            "-e",
            "trace=clock_gettime",
            "-o",
            trace.to_str().unwrap(),
            binary.to_str().unwrap(),
            "--hot",
        ])
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to trace the vDSO clock_gettime hot loop");
    assert!(
        trace_output.status.success(),
        "traced vDSO clock_gettime fixture exited with {:?}, stdout: {}, stderr: {}",
        trace_output.status.code(),
        String::from_utf8_lossy(&trace_output.stdout),
        String::from_utf8_lossy(&trace_output.stderr),
    );
    let trace_text = std::fs::read_to_string(&trace)
        .expect("strace did not produce the vDSO clock_gettime trace");
    let _ = std::fs::remove_file(&trace);
    assert!(
        !trace_text.contains("clock_gettime("),
        "the marked steady-state clock loop entered the kernel:\n{trace_text}",
    );
}
