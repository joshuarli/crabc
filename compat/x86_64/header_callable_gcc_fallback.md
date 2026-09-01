# No-dependency GCC callable-backend investigation

The canonical x86 callable inventory in `header_callable_inventory.py` uses
Clang JSON AST records and compiler preprocessor records. The pinned x86
evidence image in `docker/Dockerfile.x86_64` intentionally has no Clang. This
package checks whether its existing GCC/G++ toolchain can provide an equivalent
function-declaration inventory without changing Docker.

Run the fail-closed investigation on native Linux/x86-64 with:

```sh
python3 compat/x86_64/header_callable_gcc_fallback_probe.py \
  --require-no-docker-blocker
```

The expected report is `blocked-missing-gmp-dev`. That is a successful
investigation result, not a callable-inventory pass.

## Evidence

`docker/Dockerfile.x86_64` installs `build-base`; the current native image
reports GCC/G++ 15.2.0, the GCC plugin include directory, and the compiled
`libcc1plugin`. It does not install `/usr/include/gmp.h`. The compile-only source
`header_callable_gcc_plugin_compile_probe.cc` references exactly the GCC
front-end properties a future backend needs:

- `PLUGIN_FINISH_DECL` for parser-originated function declarations;
- source file and line;
- `DECL_EXTERNAL`, `TREE_STATIC`, `DECL_DECLARED_INLINE_P`, and parsed-body
  state, which distinguish archive-owned declarations from static inline
  definitions.

Compiling that probe against the advertised plugin headers fails before a
plugin can load:

```text
fatal error: gmp.h: No such file or directory
```

The existing GCC built-ins do not supply an alternative full declaration
inventory:

- `-fdump-lang-raw` and `-fdump-translation-unit` are rejected by GCC 15.2.
- `-fdump-tree-original-raw` contains the synthetic static-inline definition
  but drops the external declaration without a body.
- `-fdump-go-spec` contains that external declaration but drops the static
  inline definition and has no header-provenance record suitable for the
  canonical inventory.
- `-fdiagnostics-format=json` returns diagnostics, not declarations.
- `gcc -E -dD` does preserve compiler-originated callable macro records, but
  preprocessor output cannot enumerate semantic function declarations.
- The installed `libcc1plugin` requires its private `fd` protocol argument; it
  is not a standalone declaration-record emitter.

The probe reads only compiler output from a synthetic source. It never parses
project or musl header text, and it cannot turn one partial dump into a list of
callables.

## Exact approval boundary

There is no sound no-Docker-dependency fallback today. A disposable Alpine
experiment with the same GCC 15.2.0 showed that adding **only `gmp-dev`** lets
a custom GCC plugin compile and load; `isl-dev` was not required. That is a
possible route, not an approved repository change.

Before changing `docker/Dockerfile.x86_64`, the user must explicitly approve
both of these coupled changes:

1. Add `gmp-dev` as an x86 evidence-image build dependency, with its package
   provenance and GCC 15.2 plugin ABI recorded.
2. Add a reviewed GCC-plugin declaration backend to the canonical inventory
   contract. It must emit deterministic JSON, normalize source provenance,
   cover all 183/191 headers and seven profiles in C and C++, deduplicate
   redeclarations, serialize types stably, preserve the two
   oracle-not-applicable pairs, and feed the existing finite archive-extraction
   audit without weakening it.

Until that approval and the full evidence exist, this package neither changes
`header_callable_inventory.py`/`.toml`/checked JSON nor affects
`libc.headers-layouts`, any campaign result, or public x86 support.
