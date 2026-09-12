#!/usr/bin/env bash
# Actual native process proof for the private x86 wordexp-process adapter.
#
# The normal sealed static sysroot remains untouched. This runner builds it as
# the source of project headers, CRT, and bounded helpers, then builds a
# separate test-cfg libc archive containing the private bridge and links one C
# consumer directly with the same owned static inputs.
set -euo pipefail
ulimit -c 0

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly BUILDER="$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py"
readonly PROBE="$ROOT_DIR/compat/x86_64/owned_wordexp_process_private_probe.c"
readonly TARGET=x86_64-unknown-linux-musl
readonly TOOLCHAIN=nightly-2026-07-24
readonly PRIVATE_CFG=crabc_owned_wordexp_process_private_test
readonly BRIDGE=crabc_owned_wordexp_process_private_test
readonly LLD="/opt/rustup/toolchains/$TOOLCHAIN-x86_64-unknown-linux-musl/lib/rustlib/$TARGET/bin/gcc-ld/ld.lld"

fail() {
    printf 'private x86 wordexp process bridge: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in awk chroot cmp cp mkdir mktemp nm python3 readelf realpath sha256sum timeout; do
    require_tool "$tool"
done
[ -x "$LLD" ] || fail "requires pinned x86 ld.lld"
[ -x /usr/bin/gcc ] || fail "requires pinned C compiler"
[ -f "$BUILDER" ] || fail "missing owned static-sysroot builder"
[ -f "$PROBE" ] || fail "missing private bridge consumer"
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail "requires repository-local TMPDIR"

checkout_physical="$(realpath -e "$ROOT_DIR")" || fail "cannot resolve checkout root"
tmpdir_physical="$(realpath -e "$TMPDIR")" || fail "cannot resolve TMPDIR"
case "$tmpdir_physical" in
    "$checkout_physical"/.work/*) ;;
    *) fail "TMPDIR physically escapes checkout .work" ;;
esac

readonly WORK_DIR="$(mktemp -d "$TMPDIR/owned-wordexp-process-private.XXXXXX")"
readonly SYSROOT="$WORK_DIR/static-sysroot"
readonly PRIVATE_ARCHIVE="$WORK_DIR/private-cargo/$TARGET/release/libc.a"
readonly OBJECT="$WORK_DIR/private-probe.o"
readonly CANDIDATE="$WORK_DIR/private-probe"
readonly NO_SHELL_ROOT="$WORK_DIR/no-shell-root"
readonly MARKER="$WORK_DIR/selected-marker"
readonly PID_FILE="$WORK_DIR/nul-shell-leader.pid"

on_exit() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        printf 'private x86 wordexp process bridge: retained failure evidence at %s\n' "$WORK_DIR" >&2
    fi
}
trap on_exit EXIT

printf 'private x86 wordexp process evidence: %s\n' "$WORK_DIR"

# Build the normal immutable product first. The private bridge is absent from
# this archive and must never be copied into or overwrite it.
if ! python3 -B "$BUILDER" --output "$SYSROOT" \
        >"$WORK_DIR/static-sysroot.stdout" 2>"$WORK_DIR/static-sysroot.stderr"; then
    fail "owned static-sysroot build failed"
fi
[ -x "$SYSROOT/bin/crabc-cc" ] || fail "normal static driver is absent"
[ -f "$SYSROOT/usr/lib/libc.a" ] || fail "normal static libc archive is absent"
if nm -g --defined-only "$SYSROOT/usr/lib/libc.a" |
        awk -v symbol="$BRIDGE" '$NF == symbol { found = 1 } END { exit(found ? 0 : 1) }'; then
    fail "normal sealed libc archive unexpectedly exports $BRIDGE"
fi

# Reproduce the owned-static libc compilation profile with one additional
# private cfg. `--check-cfg` makes that test-only spelling deliberate rather
# than a silently accepted conditional. This raw Cargo archive is never
# installed: only the direct fixture link below sees it.
if ! python3 -B - "$ROOT_DIR" "$WORK_DIR" "$PRIVATE_ARCHIVE" \
        >"$WORK_DIR/private-build.stdout" 2>"$WORK_DIR/private-build.stderr" <<'PY'
from __future__ import annotations

import json
from pathlib import Path
import shlex
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
work = Path(sys.argv[2]).resolve()
archive = Path(sys.argv[3]).resolve()
sys.path.insert(0, str(root / "scripts"))
import build_x86_64_owned_sysroot as builder

tools = builder.resolve_pinned_producer_tools()
rustup = builder.pinned_rustup()
target_dir = work / "private-cargo"
dependency_file = work / "private-allocator.d"
c_flags = [
    "-nostdinc", "-isystem", str(root / "include"),
    "-fPIC", "-ftls-model=initial-exec", "-fstack-protector-strong",
    builder.MIMALLOC_LIFECYCLE_C_FLAG,
    f"-ffile-prefix-map={root}=/crabc", "-MD", "-MF", str(dependency_file),
]
environment = builder.deterministic_environment()
environment.update({
    "CC_x86_64_unknown_linux_musl": "/usr/bin/gcc",
    "CFLAGS_x86_64_unknown_linux_musl": shlex.join(c_flags),
    "CC_SHELL_ESCAPED_FLAGS": "1",
})
command = [
    str(rustup), "run", builder.PINNED_TOOLCHAIN, "cargo", "rustc", "--locked",
    "-p", "crabc-libc", "--lib", "--release", "--features",
    "x86-owned-static-runtime", "--target", builder.TARGET, "--target-dir",
    str(target_dir), "--",
    "--cfg", "crabc_owned_static_sysroot",
    "--cfg", builder.MIMALLOC_LIFECYCLE_RUST_CFG,
    "--cfg", "crabc_owned_wordexp_process_private_test",
    "--check-cfg", "cfg(crabc_owned_wordexp_process_private_test)",
    "-C", "relocation-model=pic", "-C", "code-model=small", "-C", "panic=abort",
    "-Ztls-model=initial-exec", "--remap-path-prefix", f"{root}=/crabc",
]
completed = subprocess.run(
    command, cwd=root, env=environment, stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
)
(work / "private-cargo.stdout").write_bytes(completed.stdout)
(work / "private-cargo.stderr").write_bytes(completed.stderr)
if completed.returncode:
    raise SystemExit(f"private cfg cargo build failed ({completed.returncode})")
if not archive.is_file():
    raise SystemExit("private cfg Cargo archive is absent")
record = {
    "schema": "crabc.x86_64-wordexp-process-private-archive/v2",
    "target": builder.TARGET,
    "private_cfg": "crabc_owned_wordexp_process_private_test",
    "cargo_command": command,
    "allocator_c_flags": c_flags,
    "producer_tools": tools,
    "raw_archive": str(archive),
}
(work / "private-build.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
PY
then
    fail "private cfg archive build failed"
fi
[ -f "$PRIVATE_ARCHIVE" ] || fail "private cfg Cargo archive is absent"
grep -Fq -- '"--check-cfg"' "$WORK_DIR/private-build.json" ||
    fail "private archive build did not record --check-cfg"
grep -Fq -- "cfg($PRIVATE_CFG)" "$WORK_DIR/private-build.json" ||
    fail "private archive build did not record the bridge cfg"
[ "$(nm -g --defined-only --format=posix "$PRIVATE_ARCHIVE" |
        awk -v symbol="$BRIDGE" '$1 == symbol && $2 ~ /^[TW]$/ { count++ } END { print count + 0 }')" = 1 ] ||
    fail "private archive must provide exactly one strong $BRIDGE"

# The sealed normal driver correctly refuses a modified installed archive.
# Compile against its installed headers, then link the object directly with
# the separate private archive and the same normal CRT/helpers. This leaves
# the normal product payload immutable.
if ! /usr/bin/gcc -nostdinc -isystem "$SYSROOT/usr/include" -ffreestanding \
        -fno-builtin -fno-stack-protector -fno-pie -std=c11 -c "$PROBE" -o "$OBJECT" \
        >"$WORK_DIR/compile.stdout" 2>"$WORK_DIR/compile.stderr"; then
    sed -n '1,160p' "$WORK_DIR/compile.stderr" >&2
    fail "private C consumer compilation failed"
fi
[ -f "$OBJECT" ] || fail "private C consumer object is absent"

library="$SYSROOT/usr/lib"
if ! "$LLD" -static --no-dynamic-linker --no-undefined --gc-sections \
        -z relro -z now -e _start "$library/crt1.o" "$library/crti.o" "$OBJECT" \
        "$PRIVATE_ARCHIVE" "$library/libcrabc-builtins.a" "$library/crtn.o" \
        --trace -o "$CANDIDATE" >"$WORK_DIR/link.stdout" 2>"$WORK_DIR/link.stderr"; then
    fail "private C consumer link failed"
fi
[ -x "$CANDIDATE" ] || fail "private C consumer executable is absent"
readelf --program-headers --wide "$CANDIDATE" >"$WORK_DIR/candidate.programs"
if grep -Fq 'Requesting program interpreter' "$WORK_DIR/candidate.programs"; then
    fail "private consumer unexpectedly has a dynamic interpreter"
fi

# This static execution root deliberately has no bin directory, let alone
# /bin/sh. The no-command expression must complete because it never selects
# the command adapter. The subsequent main run is the complementary proof
# that selected command bodies use the pinned shell in the normal root.
mkdir -m 700 "$NO_SHELL_ROOT"
cp "$CANDIDATE" "$NO_SHELL_ROOT/private-probe"
[ ! -e "$NO_SHELL_ROOT/bin/sh" ] || fail "no-command root unexpectedly contains /bin/sh"
printf 'private x86 wordexp process no-command bridge: PASS\n' >"$WORK_DIR/no-command.expected.stdout"
no_command_status=0
chroot "$NO_SHELL_ROOT" /private-probe --no-command \
    >"$WORK_DIR/no-command.stdout" 2>"$WORK_DIR/no-command.stderr" || no_command_status=$?
printf '%s\n' "$no_command_status" >"$WORK_DIR/no-command.status"
[ "$no_command_status" -eq 0 ] || fail "ordinary no-command expansion failed without /bin/sh"
cmp "$WORK_DIR/no-command.expected.stdout" "$WORK_DIR/no-command.stdout" ||
    fail "ordinary no-command expansion output drifted without /bin/sh"
[ ! -s "$WORK_DIR/no-command.stderr" ] ||
    fail "ordinary no-command expansion wrote stderr without /bin/sh"

printf 'private x86 wordexp process bridge: PASS\n' >"$WORK_DIR/expected.stdout"
printf visible >"$WORK_DIR/expected.stderr"
status=0
timeout 15 "$CANDIDATE" "$MARKER" "$PID_FILE" \
    >"$WORK_DIR/candidate.stdout" 2>"$WORK_DIR/candidate.stderr" || status=$?
printf '%s\n' "$status" >"$WORK_DIR/candidate.status"
[ "$status" -eq 0 ] || fail "native bridge consumer failed with status $status"
cmp "$WORK_DIR/expected.stdout" "$WORK_DIR/candidate.stdout" || fail "native bridge stdout drifted"
cmp "$WORK_DIR/expected.stderr" "$WORK_DIR/candidate.stderr" || fail "SHOWERR/quiet stderr boundary drifted"
[ "$(cat "$MARKER")" = x ] || fail "selected command marker is not exactly once"
[ -s "$PID_FILE" ] || fail "NUL-output shell leader evidence is absent"

python3 -B - "$WORK_DIR/evidence.json" "$WORK_DIR" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

destination = Path(sys.argv[1])
work = Path(sys.argv[2]).resolve()

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

artifacts = [
    "private-build.json", "private-cargo/x86_64-unknown-linux-musl/release/libc.a",
    "private-probe.o", "private-probe",
    "no-command.stdout", "no-command.stderr", "no-command.status",
    "candidate.stdout", "candidate.stderr", "candidate.status", "selected-marker",
    "nul-shell-leader.pid", "candidate.programs", "link.stdout", "link.stderr",
]
record = {
    "schema": "crabc.x86_64-wordexp-process-private-native/v1",
    "status": "private-test-cfg-actual-spawn-proof-not-selected-not-qualification",
    "source": {
        "adapter": "libc/src/c_abi/x86_64/owned_wordexp_process.rs",
        "consumer": "compat/x86_64/owned_wordexp_process_private_probe.c",
    },
    "work": str(work),
    "artifacts": {
        name: digest(work / name) for name in artifacts if (work / name).is_file()
    },
    "normal_product_archive_sha256": digest(work / "static-sysroot/usr/lib/libc.a"),
}
destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
PY

printf 'private x86 wordexp process bridge: PASS (actual spawned shell; evidence %s)\n' "$WORK_DIR"
