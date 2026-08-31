//! Fixed musl x86-64 source-faithful C-locale floating-conversion assembly translation.
 //!
 //! This target-local leaf owns the source-faithful narrow scanner behind
 //! `strtof`, `strtod`, `strtold`, and `atof` in the selected static archive;
 //! `float_parse_locale` composes its fixed-locale/wide completion. It accepts
 //! valid, readable NUL-terminated C
 //! strings and, for every `strto*` entry, an optional writable end-pointer.
 //! The public ABI is Linux/x86-64 System V: `strtof`/`strtod`/`atof` return
 //! binary32/binary64 in `xmm0`, while `strtold` returns x87 binary80 in
 //! `st0`. It does not expose public `__floatscan`, allocation, stdio streams,
 //! locale databases, or a general text runtime. The companion wide adapter
 //! is the only owner allowed to invoke its private one-byte refill callback.
 //!
 //! ## Fixed source and license provenance
 //!
 //! This is an assembly translation of pinned musl 1.2.6 release commit
 //! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the release archive
 //! whose SHA-256 is
 //! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
 //! The relevant musl sources carry musl's MIT license; the repository's
 //! pinned musl provenance in `compat/upstreams.toml` is authoritative.
 //! The translated assembly retains the applicable musl source behavior, not
 //! an ambient libc or a foreign linked object.
 //!
 //! | Pinned source | Owned target-local translation |
 //! | --- | --- |
 //! | `src/stdlib/strtod.c` (`strtox`, `strtof`, `strtod`, `strtold`) | `float_parse_musl_entry_x86_64.S` public wrappers and pseudo-`FILE` endpoint handling |
 //! | `src/stdlib/atof.c` | `float_parse_musl_entry_x86_64.S` `atof` tail-call wrapper |
 //! | `src/internal/floatscan.c` (`scanexp`, `decfloat`, `hexfloat`, `__floatscan`) | `float_parse_musl_x86_64.S` under private `crabc_x86_float_parse_*` names |
 //! | `src/internal/shgetc.c` (`__shlim`, `__shgetc`) | `float_parse_musl_support_x86_64.S` pseudo-string reader |
 //! | `src/math/{scalbn,scalbnl,copysignl}.c` and `src/math/x86_64/{fabsl,fmodl}.c` | the same private support translation |
 //!
 //! The `__shgetc` refill route is unreachable for this narrow source's
 //! pseudo-`FILE` construction: `strtox` stores `rend = (void *)-1` and
 //! valid public inputs are NUL terminated. Its private fallback recognizes
 //! only the checked `wcsto*` adapter's one-byte callback; it does not import
 //! musl `__uflow`/`__toread` or any stdio owner. It is invalid to use this
 //! internal scanner with any other stream.
 //!
 //! ## Code-generation provenance
 //!
 //! The checked assembly is generated from exactly those sources with musl's
 //! x86-64 `-std=c99 -ffreestanding -frounding-math` configuration and private
 //! helper renaming. Generation occurs in the native image pinned by
 //! `docker/Dockerfile.x86_64` (Alpine 3.24.1 digest recorded there,
 //! GCC 15.2.0 at translation time) using the image's
 //! `/usr/local/bin/crabc-x86_64-musl-gcc`. It is checked in so the Rust
 //! static archive never invokes a foreign compiler or links a foreign object.
 //! Do not regenerate it as a formatting exercise: update its provenance,
 //! structural disassembly gate, and pinned-musl differential corpus together.
 //!
 //! The former rational packer was deliberately removed. It could compute many
 //! binary32/binary64 values but could not reproduce musl/x86's actual
 //! binary80 operation order, current-rounding behavior, fenv flags, signed
 //! zero, and `errno` outcomes near underflow. This translation keeps those
//! The native artifact verifies that fidelity for its named grammar, range,
//! binary80 ABI, and directed-rounding corpus. It is evidence for that
//! selected fixed-locale string/wide boundary, not a claim that every C text,
//! locale, stdio, or floating-math behavior is complete.
 //!
 //! `float_parse_musl_x86_64.S` and its support/entry siblings contain no
 //! public helper symbol. The existing target-local `__errno_location` is the
 //! one intentionally shared dependency, retaining the static initial-TLS
 //! `errno` boundary.

 #[cfg(not(all(
     target_os = "linux",
     target_arch = "x86_64",
     target_endian = "little"
 )))]
 compile_error!("the x86 floating parser requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("float_parse_musl_x86_64.S"),
    options(att_syntax)
);
core::arch::global_asm!(
    include_str!("float_parse_musl_support_x86_64.S"),
    options(att_syntax)
);
core::arch::global_asm!(
    include_str!("float_parse_musl_entry_x86_64.S"),
    options(att_syntax)
);
core::arch::global_asm!(
    include_str!("float_parse_locale_musl_x86_64.S"),
    options(att_syntax)
);
core::arch::global_asm!(
    include_str!("float_parse_locale_aliases_x86_64.S"),
    options(att_syntax)
);
