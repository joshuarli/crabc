#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_runs_pie_with_dependency() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let target = manifest_dir
        .join("target/debug")
        .canonicalize()
        .expect("target/debug is not built");

    // These intentionally naked loader probes own `_start` and pass
    // `-nostdlib`; raw Clang is explicit so musl cannot contribute any target
    // startup or helper runtime input.

    // Build libfoo.so without a C runtime.
    let libfoo_src = fixtures.join("libfoo.c");
    let libfoo_so = test_support::TempArtifact::new("libfoo.so");
    let temp_dir = libfoo_so.parent();
    let mut command = test_support::naked_aarch64_command();
    let status = command
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            libfoo_src.to_str().unwrap(),
            "-o",
            libfoo_so.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile naked libfoo.so");
    assert!(status.success(), "naked libfoo.so compilation failed");

    // Build needfoo with a raw syscall `_start` and the canonical owned
    // interpreter. The test dispatcher temporarily stages the debug loader
    // at that path for the normal kernel exec below.
    let needfoo_src = fixtures.join("needfoo.c");
    let needfoo_bin = test_support::TempArtifact::new("needfoo");
    let mut command = test_support::naked_aarch64_command();
    let status = command
        .args([
            "-fPIE",
            "-pie",
            "-nostdlib",
            "-nostartfiles",
            "-Wl,--dynamic-linker,/lib/ld-crabc-aarch64.so.1",
            "-L",
            temp_dir.to_str().unwrap(),
            needfoo_src.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lfoo",
            "-o",
            needfoo_bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile naked needfoo");
    assert!(status.success(), "naked needfoo compilation failed");

    // Run needfoo with LD_LIBRARY_PATH pointing at the temporary dependency.
    let output = Command::new(&needfoo_bin)
        .env("LD_LIBRARY_PATH", temp_dir.to_str().unwrap())
        .output()
        .expect("failed to run needfoo");

    assert!(
        output.status.success(),
        "needfoo exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok\n");

    // A bare DT_NEEDED name must not fall back to the process current working
    // directory when the configured library path does not contain the DSO.
    let cwd_output = Command::new(&needfoo_bin)
        .current_dir(temp_dir)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run cwd dependency search case");
    assert!(
        !cwd_output.status.success(),
        "bare DT_NEEDED unexpectedly loaded from cwd: {}",
        String::from_utf8_lossy(&cwd_output.stderr)
    );
}
