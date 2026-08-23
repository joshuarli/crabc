#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn stdio_printf_edge_cases_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let binary = test_support::TempArtifact::new("stdio_printf_edges_test");
    let mut args = vec![
        "-fPIE".to_string(),
        "-pie".to_string(),
        "-I".to_string(),
        root.join("include").to_str().unwrap().to_string(),
        "-Wl,--dynamic-linker".to_string(),
        root.join("target/debug/libldso.so")
            .to_str()
            .unwrap()
            .to_string(),
        "-L".to_string(),
        root.join("target/debug").to_str().unwrap().to_string(),
        root.join("tests/fixtures/stdio_printf_edges_test.c")
            .to_str()
            .unwrap()
            .to_string(),
        "-Wl,--allow-shlib-undefined".to_string(),
        "-lc".to_string(),
        "-o".to_string(),
        binary.to_str().unwrap().to_string(),
    ];
    // crabc's x86_64 ABI uses binary64 long double, while musl-gcc defaults
    // to the x87 80-bit ABI on that host.
    if cfg!(target_arch = "x86_64") {
        args.insert(2, "-mlong-double-64".to_string());
    }
    let status = Command::new("musl-gcc")
        .args(args)
        .status()
        .expect("failed to compile stdio printf edge fixture");
    assert!(
        status.success(),
        "stdio printf edge fixture compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", root.join("target/debug"))
        .output()
        .expect("failed to run stdio printf edge fixture");
    assert!(
        output.status.success(),
        "stdio printf edge fixture exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "inf='      inf' INF='      INF'\n\
pos='hello'\n\
long='01234.568'\n\
short='-7616' char='-31'\n\
g='15.1 '\n\
hex='0x1.6bbap+0'\n\
size='-7' unsigned='9'\n\
buffer='hello'\n"
    );
}
