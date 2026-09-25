/// Give the enclosed C entries their own member of the installed static
/// archive, as musl's one-object-per-source-file `libc.a` does.
///
/// `scripts/build_x86_64_owned_sysroot.py` emits one archive member per Rust
/// module, and a static program that defines a libc function links only if
/// no extracted member also defines it. In that build the items become the
/// child module `$module`, whose public items are re-exported into the
/// enclosing module; every other build (the single-object libc.so and the
/// per-leaf fixture archives, whose object layout their runners pin) keeps
/// them inline. The items reach their siblings through the child's glob
/// import, never through `super::` or `self::`, so both expansions resolve
/// every path alike.
macro_rules! static_archive_member {
    ($module:ident { $($item:item)* }) => {
        #[cfg(all(crabc_owned_static_sysroot, not(crabc_x86_dynamic_runtime)))]
        mod $module {
            #[allow(unused_imports)]
            use super::*;

            $($item)*
        }
        #[cfg(all(crabc_owned_static_sysroot, not(crabc_x86_dynamic_runtime)))]
        #[allow(unused_imports)]
        pub use $module::*;
        $(
            #[cfg(not(all(crabc_owned_static_sysroot, not(crabc_x86_dynamic_runtime))))]
            $item
        )*
    };
}

/// Assemble one generated musl translation (`$stem.S` beside this file).
///
/// The installed static archive takes one module, hence one member, per musl
/// source object from the partition `build.rs` writes; every other build
/// assembles the checked combined translation unchanged.
macro_rules! musl_object_assembly {
    ($stem:literal) => {
        #[cfg(all(crabc_owned_static_sysroot, not(crabc_x86_dynamic_runtime)))]
        include!(concat!(env!("OUT_DIR"), "/musl_objects/", $stem, ".rs"));
        #[cfg(not(all(crabc_owned_static_sysroot, not(crabc_x86_dynamic_runtime))))]
        core::arch::global_asm!(include_str!(concat!($stem, ".S")), options(att_syntax));
    };
}
