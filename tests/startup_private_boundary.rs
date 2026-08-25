//! The owned CRT lifecycle must not enlarge libc's default ELF ABI.

#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn owned_startup_handoff_has_no_default_visible_runtime_helpers() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let libc = root.join("target/debug/libc.so");
    let ldso = root.join("target/debug/libldso.so");
    assert_no_default_dynamic_symbols(
        &libc,
        [
            "__crabc_run_initial_dependencies",
            "__crabc_startup_early",
            "__ldso_register_initial_constructors",
        ],
    );
    assert_no_default_dynamic_symbols(&ldso, ["__ldso_process_fini"]);
}

fn assert_no_default_dynamic_symbols<'a>(
    library: &std::path::Path,
    private_helpers: impl IntoIterator<Item = &'a str>,
) {
    let output = Command::new("readelf")
        .args(["--wide", "--dyn-syms"])
        .arg(library)
        .output()
        .expect("failed to inspect libc dynamic symbols");
    assert!(
        output.status.success(),
        "readelf failed for {}",
        library.display()
    );
    let symbols = String::from_utf8_lossy(&output.stdout);
    for private_helper in private_helpers {
        assert!(
            !symbols.lines().any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.len() >= 8
                    && fields[4] == "GLOBAL"
                    && fields[5] == "DEFAULT"
                    && fields[7].split('@').next() == Some(private_helper)
            }),
            "{private_helper} unexpectedly escaped {}'s default dynamic ABI",
            library.display(),
        );
    }
}
