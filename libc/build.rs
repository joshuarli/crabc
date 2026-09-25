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

/// Partition each generated musl assembly translation into its source objects.
///
/// The checked `src/c_abi/x86_64/*_x86_64.S` translations concatenate one
/// compiled musl source file per `/* musl-1.2.6/<path> */` marker. Musl's
/// libc.a keeps each source file in its own member, so a static program may
/// define one of its functions and link against the rest. The installed
/// static archive emits one member per Rust module; `musl_object_assembly!`
/// (`src/c_abi/x86_64/static_archive_member.rs`) therefore includes, in that
/// build only, one module per source object from
/// `$OUT_DIR/musl_objects/<stem>.rs`. A symbol a generator made local to the
/// combined translation but that another object references becomes a hidden
/// global of its defining object, so the partition links to the same
/// definitions and exports nothing new. Every other build assembles the
/// checked translation unchanged.
fn split_musl_objects() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;
    use std::path::PathBuf;

    const MARKER: &str = "/* musl-1.2.6/";
    let is_symbol_byte = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$');
    let tokens = |text: &str| -> BTreeSet<String> {
        text.split(|character: char| !(character.is_ascii() && is_symbol_byte(character as u8)))
            .filter(|token| !token.is_empty() && !token.starts_with(".L"))
            .map(str::to_owned)
            .collect()
    };
    let directive_symbol = |line: &str, directives: &[&str]| -> Option<String> {
        let trimmed = line.trim_start();
        directives.iter().find_map(|directive| {
            let rest = trimmed.strip_prefix(directive)?;
            if !rest.starts_with([' ', '\t']) {
                return None;
            }
            let name = rest.trim_start().split(|c: char| c == ',' || c.is_whitespace()).next()?;
            (!name.is_empty()).then(|| name.to_owned())
        })
    };

    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let source_dir = manifest.join("src/c_abi/x86_64");
    let output_root = PathBuf::from(std::env::var_os("OUT_DIR").expect("output directory")).join("musl_objects");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed={}", source_dir.display());
    let mut sources: Vec<PathBuf> = std::fs::read_dir(&source_dir)
        .expect("x86 source directory")
        .map(|entry| entry.expect("x86 source entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "S"))
        .collect();
    sources.sort();
    for path in sources {
        println!("cargo::rerun-if-changed={}", path.display());
        let text = std::fs::read_to_string(&path).expect("musl assembly translation");
        let stem = path.file_stem().expect("assembly stem").to_str().expect("UTF-8 stem").to_owned();
        let starts: Vec<usize> = text.match_indices(MARKER).map(|(index, _)| index)
            .filter(|&index| index == 0 || text.as_bytes()[index - 1] == b'\n')
            .collect();
        if starts.is_empty() {
            continue;
        }
        let header = &text[..starts[0]];
        let trailer = "\n.section .note.GNU-stack,\"\",@progbits\n";
        let mut chunks: Vec<(String, String)> = Vec::new();
        for (position, &start) in starts.iter().enumerate() {
            let end = starts.get(position + 1).copied().unwrap_or(text.len());
            let body = text[start..end].replace(trailer.trim_start(), "");
            let source = body[MARKER.len()..].split(" */").next().expect("marker path").to_owned();
            let tag: String = source.trim_end_matches(".c").trim_end_matches(".s").trim_end_matches(".S")
                .chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
            chunks.push((tag, body));
        }
        // Symbols each object defines, and those it declares global or weak.
        let mut defined: BTreeMap<String, usize> = BTreeMap::new();
        let mut exported: BTreeSet<String> = BTreeSet::new();
        for (index, (_, body)) in chunks.iter().enumerate() {
            for line in body.lines() {
                if let Some(name) = directive_symbol(line, &[".globl", ".global", ".weak"]) {
                    exported.insert(name);
                }
                let label = line.strip_suffix(':').filter(|name| {
                    !name.is_empty() && !name.starts_with(".L") && name.bytes().all(is_symbol_byte)
                });
                let set = directive_symbol(line, &[".set", ".equ", ".comm", ".lcomm"]);
                for name in label.map(str::to_owned).into_iter().chain(set) {
                    if let Some(previous) = defined.insert(name.clone(), index) {
                        assert_eq!(previous, index, "{stem}: {name} is defined by two musl objects");
                    }
                }
            }
        }
        // Musl's sources call these public functions by name, so an
        // application's replacement reaches them. The generators give each
        // translation private copies (`<prefix>elementary_NAME`,
        // `<prefix>provider_NAME`) so the combined object stands alone; the
        // partition calls the public symbol instead, as musl's objects do.
        const PUBLIC_MATH_CALLS: &[&str] = &[
            "atan", "atan2", "atan2f", "atanf", "copysign", "copysignf", "copysignl", "cos", "cosf",
            "cosh", "coshf", "exp", "exp2", "exp2f", "expf", "expm1", "expm1f", "fabs", "fabsf",
            "floor", "floorf", "hypot", "hypotf", "hypotl", "log", "log1p", "log1pf", "logf", "modf",
            "modff", "pow", "powl", "rint", "rintf", "round", "roundf", "roundl", "scalbn", "sin",
            "sinf", "sinh", "sinhf", "sinl", "sqrt", "sqrtf", "tan", "tanf",
        ];
        let route_public = |line: &str| -> String {
            let trimmed = line.trim_start();
            if trimmed.starts_with(".type") || trimmed.starts_with(".size") || trimmed.starts_with(".globl")
                || trimmed.starts_with(".global") || trimmed.starts_with(".hidden") || trimmed.starts_with(".local")
                || trimmed.ends_with(':')
            {
                return line.to_owned();
            }
            let mut routed = String::with_capacity(line.len());
            let mut token = String::new();
            let flush = |token: &mut String, routed: &mut String| {
                let public = token.strip_prefix("crabc_x86_").and_then(|rest| {
                    PUBLIC_MATH_CALLS.iter().copied().find(|name| {
                        ["_elementary_", "_provider_"].iter().any(|kind| {
                            rest.strip_suffix(name).is_some_and(|head| head.ends_with(kind))
                        })
                    })
                });
                routed.push_str(public.unwrap_or(token));
                token.clear();
            };
            for character in line.chars() {
                if character.is_ascii() && is_symbol_byte(character as u8) {
                    token.push(character);
                } else {
                    flush(&mut token, &mut routed);
                    routed.push(character);
                }
            }
            flush(&mut token, &mut routed);
            routed
        };
        let mut rust = String::new();
        let directory = output_root.join(&stem);
        std::fs::create_dir_all(&directory).expect("musl object directory");
        for (index, (tag, body)) in chunks.iter().enumerate() {
            let mut shared: BTreeSet<&String> = BTreeSet::new();
            for (other, (_, other_body)) in chunks.iter().enumerate() {
                if other != index {
                    let used = tokens(other_body);
                    shared.extend(defined.iter().filter(|(name, owner)| {
                        **owner == index && !exported.contains(*name) && used.contains(*name)
                    }).map(|(name, _)| name));
                }
            }
            let mut object = String::from(header);
            for line in body.lines() {
                match directive_symbol(line, &[".local"]) {
                    Some(name) if shared.contains(&name) => {}
                    _ => {
                        object.push_str(&route_public(line));
                        object.push('\n');
                    }
                }
            }
            for name in &shared {
                writeln!(object, "\t.globl\t{name}\n\t.hidden\t{name}").expect("string write");
            }
            object.push_str(trailer);
            let file = directory.join(format!("{tag}.S"));
            std::fs::write(&file, object).expect("musl object assembly");
            writeln!(
                rust,
                "mod {tag}_source {{ core::arch::global_asm!(include_str!({:?}), options(att_syntax)); }}",
                file.display().to_string(),
            ).expect("string write");
        }
        std::fs::write(output_root.join(format!("{stem}.rs")), rust).expect("musl object modules");
    }
}

fn main() {
    x86_runtime_capabilities();
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        split_musl_objects();
    }
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
