# Retired x86 private loader fixtures

The x86 product fold in `8672fe86e` made `x86_64-owned-dynamic-runtime` the
only x86-64 `crabc-ldso` feature and deleted the private `*_source_root.rs`
roots and their fixed-graph runners. `dff45cb88` removed the remaining
dispatcher arms. This note maps each retired command to the current evidence,
so a removed behavioral case is not mistaken for a removed check.

The 71 behavioral rows recorded in
`.work/campaign/lanes/s3a-ldso/migration.md` (A1–A34, B1–B19, C1–C11, D1–D7)
are covered by the four installed-product runners:

| Installed case | Runner |
| --- | --- |
| `ldso-initial-graph` | `compat/x86_64/run_owned_ldso_initial_graph_cases.sh` |
| `ldso-general-initial-tls` | `compat/x86_64/run_owned_ldso_initial_tls_cases.sh` |
| `ldso-general-loader-lifecycle` | `compat/x86_64/run_owned_ldso_lifecycle_cases.sh` |
| `ldso-loader-libc-tls-runtime-v1` | `compat/x86_64/run_owned_ldso_runtime_v1_cases.sh` |

`./scripts/dev-x86_64.sh materialized-dynamic-sysroot` runs those cases on the
installed, second and extracted products. The 163 loader tests compiled by the
same command retain the source-only relocation, image, state and TLS checks.

| Retired dispatcher command | Current location |
| --- | --- |
| `ldso-relocation` | 163 loader tests (`ldso/src/x86_64_general_relocation_tests.rs`) |
| `ldso-image` | 163 loader tests (ELF64 image metadata checks) |
| `ldso-initial-graph` | `ldso-initial-graph` installed case |
| `ldso-general-initial-graph` | `ldso-initial-graph` installed case |
| `ldso-general-initial-target-root` | `ldso-initial-graph` installed case |
| `ldso-general-initial-tls` | `ldso-general-initial-tls` installed case |
| `ldso-general-initial-tls-target-root` | `ldso-general-initial-tls` installed case |
| `ldso-initial-tls` | `ldso-general-initial-tls` installed case |
| `ldso-initial-exec-tls` | `cross-dso` (startup initial-exec DSO) and `dlopen-pie`/`dlopen-non-pie` (new runtime initial-exec rejection) |
| `ldso-owned-crt-handoff` | `crt-dynamic-startup` and `ldso-loader-libc-tls-runtime-v1` installed cases |
| `ldso-fixed-graph-introspection` | `dlopen-pie`/`dlopen-non-pie` (`dl_iterate_phdr`, `dlinfo`, `dladdr`) |
| `ldso-dynamic-admission` | `dlopen-pie`/`dlopen-non-pie` and `lazy-pie`/`lazy-non-pie` |
| `ldso-fixed-graph-dlfcn` | `dlopen-pie`/`dlopen-non-pie` |
| `ldso-public-dlfcn` | `dlopen-pie`/`dlopen-non-pie` (public dlfcn surface) |
| `ldso-dladdr-symbol-bounds` | `dlopen-pie`/`dlopen-non-pie` (`dladdr` exact/interior/unmapped results) |
| `ldso-bounded-dlopen` | `dlopen-pie`/`dlopen-non-pie` (runtime mapping, constructors, `RTLD_NOLOAD`) |
| `loader-libc-tls-runtime-v1` | `ldso-loader-libc-tls-runtime-v1` installed case |
| `loader-libc-tls-runtime-v1-registry` | `ldso-loader-libc-tls-runtime-v1` installed case |
| `loader-libc-general-tls-runtime-v1` | `ldso-general-initial-tls` and `ldso-loader-libc-tls-runtime-v1` installed cases |
| `loader-libc-general-tls-runtime-v1-target-root` | `ldso-loader-libc-tls-runtime-v1` installed case |
| `dynamic-main-thread-runtime-v1` | `ldso-loader-libc-tls-runtime-v1` installed case |
| `dynamic-main-thread-runtime-v1-target-root` | `ldso-loader-libc-tls-runtime-v1` installed case |
| `ldso-target-root` | The installed product is the only x86 loader root; the four cases above run it directly |

The ten private fixed-graph entries were removed from
`compat/x86_64/parity.toml`: `ldso-fixed-graph-introspection`,
`ldso-fixed-graph-dlfcn`, `ldso-public-fixed-graph-dlfcn`,
`ldso-fixed-graph-dladdr-symbol-bounds`, `ldso-bounded-runtime-dlopen`,
`ldso-initial-graph`, `ldso-target-root-admission`, `ldso-initial-tls`,
`ldso-initial-exec-tls` and `ldso-dynamic-fixed-graph-admission`. The
remaining loader artifacts point at `materialized-dynamic-sysroot`; the
`ldso-owned-crt-handoff-wire` artifact keeps `crt-dynamic-startup`.
