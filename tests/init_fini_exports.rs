#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

fn assert_weak_function_export(library: &std::path::Path, name: &str) {
    let output = Command::new("readelf")
        .args(["--wide", "--dyn-syms", library.to_str().unwrap()])
        .output()
        .expect("failed to inspect libc dynamic symbols");
    assert!(output.status.success(), "readelf failed for {}", library.display());
    let found = String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.len() >= 8
            && fields[3] == "FUNC"
            && fields[4] == "WEAK"
            && fields[5] == "DEFAULT"
            && fields[7].split('@').next() == Some(name)
    });
    assert!(found, "{} is not a weak default-visible function in {}", name, library.display());
}

#[test]
fn weak_init_fini_exports_preserve_startup_and_finalization_order() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/init_fini_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-init-fini");
    let marker = test_support::TempArtifact::new("init-fini-marker");

    assert!(target.join("libldso.so").exists(), "libldso.so not found");
    assert!(target.join("libc.so").exists(), "libc.so not found");
    assert_weak_function_export(&target.join("libc.so"), "_init");
    assert_weak_function_export(&target.join("libc.so"), "_fini");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-D_GNU_SOURCE",
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for init_fini_exports_test");
    assert!(
        status.success(),
        "musl-gcc init_fini_exports_test compilation failed"
    );

    let output = Command::new(&binary)
        .arg(marker.as_os_str())
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run init_fini_exports_test");
    assert_eq!(
        output.status.code(),
        Some(37),
        "init_fini_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&*marker).expect("failed to read init/fini marker"),
        "exports\ninit\nmain\nfini\n"
    );
}
