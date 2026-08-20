# Musl-vs-crabc differential runner

This is the first compatibility-laboratory runner. It compiles one workload
object from `tests/foundational.c` using the headers from the pinned musl 1.2.6
tree, then links that same object twice:

```text
reference  → musl 1.2.6's loader and libc
candidate  → crabc's target/debug/libldso.so and libc.so
```

`run.py` executes both artifacts with the same inherited environment (apart
from the candidate-only `LD_LIBRARY_PATH` needed to locate crabc), and compares
the exit status, complete stdout, complete workload stderr, and the workload's
explicit errno marker. Python preserves signal termination as a negative return
code, so signal termination is not silently normalized into a successful exit.

Successful crabc loader startup must be silent on stderr. The runner therefore
compares raw stderr byte-for-byte; loader diagnostics, application writes, and
signals are all visible differences. The JSON report retains
`normalized_lines`/`normalized_line_count` as an explicit invariant, and the
foundational case requires them to be empty/zero.

The runner never downloads anything. The native AArch64 development image
provides the pinned oracle at `/opt/musl-1.2.6`; the caller must build crabc
first so `target/debug/libldso.so` and `target/debug/libc.so` exist. The exact
musl source hash and environment pin live in [`../upstreams.toml`](../upstreams.toml).

Every comparison publishes a machine-readable JSON result atomically at
`compat/reports/differential/<case>.json` by default. It records the case,
pass/fail result, both exit statuses, normalization metadata, errno, and byte
length/SHA-256/text metadata for reference and candidate stdout/stderr. The
normalization fields are currently always an empty list and zero count.
Override the destination with `--report PATH` or
`CRABC_DIFFERENTIAL_REPORT=PATH`; the parent directory is created as needed.

## Run in the native AArch64 development image

From the repository root, after the normal workspace build:

```sh
cargo build --workspace
python3 compat/differential/run.py foundational
```

This also writes `compat/reports/differential/foundational.json`.

The intended Docker entry point is the same final command from `/workspace`:

```sh
python3 compat/differential/run.py foundational
```

`dev.sh` integration is intentionally left to its owner. A smoke-test wrapper
that also checks `--help` is available at `tests/runner_test.py`.

For a non-default installation, override only paths while retaining the pinned
basename and AArch64 loader:

```sh
MUSL_ROOT=/opt/musl-1.2.6 \
CRABC_TARGET_DIR=/workspace/target/debug \
python3 compat/differential/run.py
```

To keep a report outside the repository, pass for example
`--report /tmp/crabc-foundational.json`.

The foundational case has no filesystem side effects and produces stable
streams. Future cases should document every normalization explicitly; semantic
differences must remain visible rather than being hidden by broad filtering.
