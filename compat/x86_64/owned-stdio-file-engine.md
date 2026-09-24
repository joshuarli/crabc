# Installed FILE-engine receipt

`run_owned_stdio_file_engine.sh [STATIC_SYSROOT DYNAMIC_SYSROOT]` records a
finite installed-header FILE-engine replay. It compiles one unchanged object
for each of nine frozen probes with the selected dynamic product's
headers, links that same object once with pinned musl and once in every
product linkage, and retains raw compiler, linker, run, copied-root,
and seal evidence. Without a supplied pair it first builds current static and
dynamic products from the checkout into its evidence directory, so one command
replays every row against the checkout's own source.

The closed rows are `stdio.file-backends`, `stdio.process-streams`,
`stdio.wide-stream`, `stdio.wide-format`, `stdio.file-extensions`,
`stdio.printf-float`, `stdio.scanf`, `stdio.frozen-surface`, and
`stdio.engine-model`. They retain
the actual observations in `owned_stdio_backends_probe.c`,
`owned_stdio_process_probe.c`, `owned_wide_stdio_probe.c`,
`owned_wide_format_probe.c`, `owned_stdio_extensions_probe.c`,
`owned_static_printf_float_probe.c`, `owned_static_scanf_probe.c`,
`owned_stdio_surface_probe.c`, and `owned_stdio_engine_model_probe.c`:
descriptor/memory/cookie streams including
ordinary-exit flushing; `popen`/`pclose`/`system` process and failure cleanup;
wide orientation and memory streams; wide grammar; `stdio_ext` state and
locking; float formatting and fenv across destinations; scanf grammar,
lookahead, fenv, and `%m` allocation failure; and the remaining frozen entry
points, exact `feof`/`ferror` values, buffered bytes kept across a mid-stream
`setvbuf`, and musl's newest-first open-file exit flush before the standard
streams; stdin's zero `lbf`, `rewind` keeping end-of-file when it cannot seek,
and `ungetc` on a fresh stream after `setvbuf` supplies a buffer. The model row
drives byte and wide streams over every backend through seeded sequences of
valid operations and folds each step's result, errno, position, indicators,
`stdio_ext` buffer state, and backing-object state (descriptor offset and size,
pipe contents, memory or cookie bytes) into one digest per scenario, so it
compares musl's buffering and read-ahead policy as well as results. Building it
with `-DMODEL_TRACE` prints the steps themselves to localize a differing
digest. The rows do not add a runtime API.

## Frozen symbol surface

The reader parses the undefined global and weak symbols of the nine retained
installed-header ELF objects. Together they must reference every symbol that
the frozen ledger `compat/crabc-rs/coverage.toml` lists for
`stdio.path-stream`, `stdio.stream-io`, `stdio.position-buffering`, and
`stdio.format-scan`; a missing name rejects the receipt. Its result reports the
per-capability counts as `frozen_surface`, and the family coordinator requires
all four before this component credits them. `stdio.fopen64-alias` is a
`<stdio.h>` macro with no x86 ELF name, so the separate v3 `owned-stdio`
component keeps that observation.

## Intentional differences from pinned musl

Each difference is confined to input C leaves undefined or lets the library
diagnose; valid programs observe musl's behavior.

- Input directly followed by output without a positioning call (C11 7.21.5.3)
  is undefined. Musl's `__towrite` drops unread lookahead without seeking, so
  it writes at the descriptor's read-ahead offset. `prepare_write` first
  returns the lookahead and writes at the logical position.
- `__fdopen` validates the descriptor with `F_GETFL` (`EBADF`) and rejects a
  mode its access mode cannot satisfy (`EINVAL`) before taking ownership.
  Musl accepts both and fails at the first I/O. POSIX permits the `EBADF`
  diagnosis and requires applications to supply a compatible mode; `popen`
  modes other than `r`/`w` inherit the same check.
- An empty mode string is rejected with `EINVAL`. Musl's
  `strchr("rwa", *mode)` also matches the terminator and opens it write-only.
- `printf` that mixes numbered and unnumbered conversions returns -1 with
  `EINVAL`; musl reads uninitialized positional state.
- `fread`/`fwrite` with an overflowing `size * nmemb` set the error indicator
  (`fread` also `EOVERFLOW`) instead of wrapping the byte count.

Each row runs in exactly six supplied-product cells: static ET_EXEC, static
PIE, and dynamic PIE/non-PIE through both kernel and direct-loader entry. The
pinned-musl static link is the oracle. The raw stdout, stderr, and status of
each candidate cell must equal its named oracle. The probes retain their own
observable allocation-failure, ordinary-exit, and subprocess assertions; the
runner does not reduce them to a symbol checklist.

The process row has an explicit finite control fixture. The runner generates
three fixed installed-header launcher sources for `sh`, `cat`, and `sleep`; it
compiles each once against the installed headers, then links distinct oracle,
static, static-PIE, dynamic-PIE, and dynamic-non-PIE launchers. Every launcher
execs the sealed physical `/control/ld-musl-x86_64.so.1` and
`/control/busybox` with a literal applet name. It neither dispatches an
arbitrary command nor uses an ambient shell or a product loader alias. The
oracle launcher is pinned-musl linked, and static launchers are selected-static
linked, so those roots have no candidate dynamic-link dependency. The process roots,
and the two dynamic wide-format roots that reopen a saved descriptor through
`/proc/self/fd`, receive temporary copies plus a tracked private read-only procfs fixture.
The retained receipt includes its fixed mount
command, raw mountinfo, same-PID-namespace witness, and successful unmount; no root
walk is allowed until that teardown is recorded. The temporary controls are removed
before the dynamic copied product receives its after-audit. Durable stage copies and
the exact generated source/object/link receipts remain under the evidence work
directory.

`scripts/dev-x86_64.sh owned-stdio-file-engine` is the only new dispatcher route
with this fixture authority. It selects the existing dynamic-loader mount
container policy with `SYS_CHROOT`, `SYS_ADMIN`, and AppArmor unconfined; it does
not select a privileged container or change the earlier `owned-stdio` route.

A development replay may bind the frozen `26df` supplied static/dynamic products
read-only under `.work/frozen-26df`. Its report seals the current consumer source
and the exact frozen product trees before and after the run. That mixed-epoch
result is development evidence only: it is neither a same-source qualification
nor stdio-family promotion.

## Receipt reader

`owned_stdio_file_engine_receipt.py` reconstructs
`owned-stdio-file-engine.json` after the producer exits. It rejects symlink
hops before resolution, validates source and product seals before loading the
product helper, derives the selected compiler/linker from that sealed helper,
checks every header trace is inside installed `usr/include`, rebuilds all
product links, audits copied dynamic payloads, checks immutable source/object
seals, and compares raw records to pinned musl. It also checks the physical
BusyBox, bootstrap musl loader, proc-mount tools, fixed launcher sources,
launcher objects, linkage-specific binaries, and retained stage copies.
Recomputed report hashes alone therefore cannot replace a header, tool,
launcher, product-link identity, payload, raw output, ordinary-exit file, or
runtime cell.

The public reader entry point is:

```sh
python3 -B compat/x86_64/owned_stdio_file_engine_receipt.py \
  .work/x86_64/.../owned-stdio-file-engine.json \
  --checkout "$PWD" --require-static
```

It returns `crabc.x86_64-owned-stdio-file-engine/v1`, `matrix` equal to
`supplied-static`, six exact execution-cell labels, the closed rows, exact
source and product mappings, the source/product before seal, and the
`frozen_surface` counts. Its
`family_completion`, `promotion_ready`, and `public_support` flags are all
false. The separate v3 `stdio.fopen64-alias` component remains required
support evidence; neither receipt credits the other or completes the stdio
family.
