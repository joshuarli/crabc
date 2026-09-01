fn main() {
    println!("cargo::rustc-check-cfg=cfg(crabc_general_initial_graph)");
    println!("cargo::rustc-check-cfg=cfg(crabc_general_initial_tls_materialization_v1)");
    println!("cargo::rustc-check-cfg=cfg(crabc_general_loader_libc_tls_runtime_v1)");
    for malformed in [
        "bad_magic",
        "bad_version",
        "bad_abi_size",
        "bad_mode",
        "bad_owner",
        "bad_generation",
        "poisoned_dtv",
    ] {
        println!(
            "cargo::rustc-check-cfg=cfg(crabc_general_loader_libc_tls_runtime_v1_{malformed})"
        );
    }
    if std::env::var_os("CARGO_FEATURE_X86_64_GENERAL_INITIAL_INTERPRETER").is_some() {
        println!("cargo::rustc-cfg=crabc_general_initial_graph");
    }
    if std::env::var_os("CARGO_FEATURE_X86_64_GENERAL_INITIAL_TLS_INTERPRETER").is_some() {
        println!("cargo::rustc-cfg=crabc_general_initial_graph");
        println!("cargo::rustc-cfg=crabc_general_initial_tls_materialization_v1");
    }
    if std::env::var_os(
        "CARGO_FEATURE_X86_64_GENERAL_INITIAL_TLS_RUNTIME_V1_INTERPRETER",
    )
    .is_some()
    {
        println!("cargo::rustc-cfg=crabc_general_initial_graph");
        println!("cargo::rustc-cfg=crabc_general_initial_tls_materialization_v1");
        println!("cargo::rustc-cfg=crabc_general_loader_libc_tls_runtime_v1");
    }
    println!("cargo:rustc-cdylib-link-arg=-nostartfiles");
    println!("cargo:rustc-cdylib-link-arg=-nostdlib");
    println!("cargo:rustc-cdylib-link-arg=-e");
    println!("cargo:rustc-cdylib-link-arg=_start");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-Bsymbolic");
}
