# libc-test Integration Harness

Builds and runs the [libc-test](https://git.musl-libc.org/cgit/libc-test) suite against crabc's libc.so to produce a categorized failure report. `run.sh` remains a compatibility launcher; the build, link, timeout, and test loop live in the dependency-free `runner.py`, while `report.py` owns structured-report generation.

## How It Works

1. Builds `crabc/libc` into `target/debug/libc.so` (via `cargo build`).
2. Creates a `fake-libs/` directory with symlinks so the linker resolves `-lc`, `-lpthread`, `-lm`, etc. against our libc.so instead of musl's.
3. Builds libc-test's `runtest.exe` and `libtest.a` as host tools (linked against musl).
4. Compiles and links executable tests with `musl-gcc -L fake-libs/`, then runs them via `LD_LIBRARY_PATH=fake-libs/`. API checks instead use `gcc -nostdinc` with crabc's headers plus GCC's builtin headers, so a missing crabc header cannot silently fall back to musl.
5. Categorizes results: **PASS**, **FAIL**, **BUILDERROR** (compile/link failure), **TIMEOUT** (30s), or an explicit **SKIP** only when the pinned musl oracle fails due to a documented Docker environment constraint.

## Usage

```bash
./run.sh              # functional tests only (default)
./run.sh math         # math tests only
./run.sh regression   # regression tests only
./run.sh api          # API/header tests only
./run.sh all          # all categories
```

Reports are saved to `reports/`. Symlinks `reports/latest-summary.txt` and
`reports/latest-raw.txt` always point to the most recent human reports. Each run
also emits machine-readable artifacts:

- `latest-results.jsonl` contains one object for every test. Each object records
  `suite`, `test`, `status`, `phase`, `reason`, the linker-derived
  `missing_symbols` list, and its diagnostic file.
- `latest-report.json` contains the run metadata, status counts, and a
  `missing_symbols` array. Every entry has a symbol, `blocked_test_count`, and
  `blocked_tests` containing suite/test IDs.
- `latest-missing-symbols.tsv` is the same graph as sorted `symbol<TAB>test`
  edges, with a header, for shell or spreadsheet analysis.

The JSON report has `schema_version: 1`; timestamped files beside these
symlinks are retained for each invocation. `report.py` uses only Python's
standard library and parses common GNU ld/lld forms including `undefined
reference to` and `undefined symbol`. A link failure without an unresolved
symbol remains a `BUILDERROR` with reason `link_error` rather than being
incorrectly attributed to libc.

## Requirements

- musl-gcc (`apt install musl-tools`)
- Python 3 (standard library only, for structured reporting)
- Rust nightly toolchain (for building crabc)
- libc-test source at `/home/root/libc-test` (override with `LIBC_TEST_DIR` env var)

The report parser tests can be run without a libc-test checkout:

```bash
python3 -m unittest discover -s libc-test-harness -p 'test_*.py'
```

## Known Limitations

- **Surface parity is incomplete** — missing exports can still cause link failures. Use `latest-report.json` to see which unresolved symbols block each test; do not infer behavior from an export count.
- **Static linking is not tested** — only dynamic-linked binaries are built.
- **Only functional subset is tested by default** — use `./run.sh all` for everything.
- **`regression/statvfs` is skipped on Docker's root overlay** — it reports zero
  inode capacity under both crabc and the pinned musl oracle. The structured
  event has `reason: "oracle_environment"`; do not treat it as a candidate pass.

## Current measurements

Reports are deliberately local and timestamped. Generate the repository-level
summary with `./scripts/dev.sh dashboard`; it separates current exported ABI
counts from implementation and verification claims.
