// Cargo features select dependency edges; these fixed target-local cfgs select
// shared runtime capabilities. Keeping those contracts separate lets owned
// backends share source without making allocator clients depend on C mimalloc.
fn x86_runtime_capabilities() {
    const CAPABILITIES: &[(&str, &str)] = &[
        ("crabc_x86_owned_runtime", "CARGO_FEATURE_X86_OWNED_STATIC_RUNTIME"),
        ("crabc_x86_dynamic_runtime", "CARGO_FEATURE_X86_OWNED_DYNAMIC_RUNTIME"),
        ("crabc_x86_allocator_runtime", "CARGO_FEATURE_X86_ALLOCATOR_RUNTIME"),
        ("crabc_x86_allocator_string_duplication", "CARGO_FEATURE_X86_ALLOCATOR_STRING_DUPLICATION"),
        ("crabc_x86_allocator_observability", "CARGO_FEATURE_X86_ALLOCATOR_OBSERVABILITY"),
        ("crabc_x86_environment_runtime", "CARGO_FEATURE_X86_ENVIRONMENT_RUNTIME"),
        ("crabc_x86_temporary_names", "CARGO_FEATURE_X86_TEMPORARY_NAMES"),
        ("crabc_x86_scandir", "CARGO_FEATURE_X86_SCANDIR"),
        ("crabc_x86_crypt_allocator_composition", "CARGO_FEATURE_X86_CRYPT_ALLOCATOR_COMPOSITION"),
    ];
    let selected_x86 = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
        && std::env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() == Ok("little");
    let enabled = |feature| std::env::var_os(feature).is_some();
    let owned = enabled("CARGO_FEATURE_X86_OWNED_STATIC_RUNTIME")
        || enabled("CARGO_FEATURE_X86_OWNED_STATIC_RUNTIME_CORE")
        || enabled("CARGO_FEATURE_X86_OWNED_STATIC_NATIVE_SHADOW");
    let native = enabled("CARGO_FEATURE_NATIVE_MIMALLOC_SHADOW");
    let c_backend = enabled("CARGO_FEATURE_X86_ALLOCATOR_RUNTIME");
    if selected_x86 {
        assert!(!(native && c_backend), "native x86 allocator and accepted C allocator selections are mutually exclusive");
    }
    for (cfg, feature) in CAPABILITIES {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
        let capability = if *cfg == "crabc_x86_dynamic_runtime" {
            enabled(feature) || enabled("CARGO_FEATURE_X86_OWNED_DYNAMIC_NATIVE_SHADOW")
        } else {
            enabled(feature) || owned
        };
        if selected_x86 && capability {
            println!("cargo::rustc-cfg={cfg}");
        }
    }
}

fn main() {
    x86_runtime_capabilities();
    // The installed static product selects musl's loaderless dlfcn stubs
    // (`static_dlfcn.rs`) rather than carrying a dynamic-loader weak import
    // into a closed ET_EXEC image.
    println!("cargo::rustc-check-cfg=cfg(crabc_owned_static_sysroot)");
    // Only installed-product builders select the paired C/Rust lifecycle.
    println!("cargo::rustc-check-cfg=cfg(crabc_owned_mimalloc_lifecycle)");
    // Focused real-owner evidence admits this fixture bridge only in a
    // disposable private static archive, never an installed product.
    println!("cargo::rustc-check-cfg=cfg(crabc_owned_pattern_private_test)");
    println!("cargo::rustc-check-cfg=cfg(crabc_owned_wordexp_paths_private_test)");
    println!("cargo::rustc-check-cfg=cfg(crabc_owned_wordexp_process_private_test)");
    println!("cargo::rustc-check-cfg=cfg(crabc_owned_wordexp_result_private_test)");
    // Rust's cdylib linker otherwise adds the platform crt startup objects.
    // Their linker-generated global `_init`/`_fini` symbols override the
    // musl ABI's weak exports.  libc has no crt entry point of its own, so
    // omit only those startup files; Rust's init/fini arrays remain in the
    // shared object and are handled by the dynamic linker.
    println!("cargo:rustc-cdylib-link-arg=-nostartfiles");
    // Keep the workspace-wide `link-dead-code` instrumentation, but let this
    // final panic-abort cdylib discard unreachable target-std unwind cleanup
    // retained by RustCrypto's alloc-enabled MCF serializer. This affects
    // neither the static archive nor any other workspace artifact.
    println!("cargo:rustc-cdylib-link-arg=-Wl,--gc-sections");
}
