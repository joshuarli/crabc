#!/usr/bin/env bash
# Native x86-64 source-only witness for the pinned musl 1.2.6 aio submit
# signal-order boundary. This intentionally compiles the test-only direct
# inclusion of immutable src/aio/aio.c; it neither builds nor runs crabc.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_VERSION=1.2.6
readonly MUSL_ARCHIVE="$ROOT/.work/x86_64/source-oracles/musl-${MUSL_VERSION}.tar.gz"
readonly MUSL_ARCHIVE_SHA256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a
readonly MUSL_REVISION=9fa28ece75d8a2191de7c5bb53bed224c5947417
readonly ORACLE_ROOT="/opt/musl-${MUSL_VERSION}"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly ORACLE_ARCHIVE="$ORACLE_ROOT/lib/libc.a"
readonly WITNESS_SOURCE="$ROOT/compat/x86_64/aio_source_signal_order_witness.c"
readonly SOURCE_AIO_SHA256=a094ee091f0afc34789be384d450e8c5960d14d651ee924f6e08542554202ca4
readonly SOURCE_AIO_IMPL_SHA256=d89b582d5f2e49890b4830f942555b6a513b1c5125613f9e9f121db267185b16
readonly SOURCE_CLOSE_SHA256=0a287fdef55394bdedfafc924efcec2d27e584a252cd2c71553fae0bb8ec9672
readonly SOURCE_BLOCK_SHA256=c0288b630002171684c42830f219ac2bc94a108f52e18dcddbd7405b3d5477e7
readonly SOURCE_COPYRIGHT_SHA256=b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b

fail() {
    printf 'ERROR: pinned musl aio source signal order: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_sha256() {
    local expected="$1" path="$2" label="$3" actual
    actual="$(sha256sum "$path" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || fail "$label SHA-256 drifted: $actual"
}

assert_symbol() {
    local symbols="$1" binding="$2" visibility="$3" name="$4" label="$5"
    awk -v binding="$binding" -v visibility="$visibility" -v name="$name" '
        $4 == "FUNC" && $5 == binding && $6 == visibility && $8 == name { found = 1 }
        END { exit !found }
    ' "$symbols" || fail "$label lacks $binding/$visibility $name"
}

assert_no_dynamic_runtime() {
    local binary="$1" headers="$2" dynamic="$3"
    readelf --program-headers --wide "$binary" >"$headers"
    readelf --dynamic --wide "$binary" >"$dynamic" || true
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
        fail "instrumented source witness unexpectedly has a dynamic runtime"
    fi
}

case "${TMPDIR:-}" in
    "$ROOT"/.work/*) ;;
    *) fail "TMPDIR must be a physical checkout .work directory" ;;
esac
[ -d "$TMPDIR" ] && [ "$(realpath "$TMPDIR")" = "$TMPDIR" ] || {
    fail "TMPDIR must be a physical checkout .work directory"
}
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cmp env grep objdump python3 readelf sed sha256sum tar timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$ORACLE_ARCHIVE" ] || fail "missing pinned musl static archive"
[ -f "$MUSL_ARCHIVE" ] || fail "missing fixed musl source archive: $MUSL_ARCHIVE"
[ -f "$WITNESS_SOURCE" ] || fail "missing source-order witness C file"
assert_sha256 "$MUSL_ARCHIVE_SHA256" "$MUSL_ARCHIVE" "musl source archive"

work="$(mktemp -d "$TMPDIR/aio-source-signal-order.XXXXXX")"
chmod a+rx "$work"
# Keep source, link, and raw run receipts below the checkout .work boundary.
printf 'pinned musl aio source-signal-order evidence: %s\n' "$work"

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" \
    >"$work/musl-oracle.stdout" 2>"$work/musl-oracle.stderr"
[ ! -s "$work/musl-oracle.stderr" ] || fail "pinned musl oracle verifier wrote stderr"
printf '0\n' >"$work/musl-oracle.status"

mkdir -p "$work/source"
tar -xzf "$MUSL_ARCHIVE" -C "$work/source"
source_tree="$work/source/musl-${MUSL_VERSION}"
[ -d "$source_tree" ] || fail "source archive did not produce musl-${MUSL_VERSION}"
assert_sha256 "$SOURCE_AIO_SHA256" "$source_tree/src/aio/aio.c" "src/aio/aio.c"
assert_sha256 "$SOURCE_AIO_IMPL_SHA256" "$source_tree/src/internal/aio_impl.h" "src/internal/aio_impl.h"
assert_sha256 "$SOURCE_CLOSE_SHA256" "$source_tree/src/unistd/close.c" "src/unistd/close.c"
assert_sha256 "$SOURCE_BLOCK_SHA256" "$source_tree/src/signal/block.c" "src/signal/block.c"
assert_sha256 "$SOURCE_COPYRIGHT_SHA256" "$source_tree/COPYRIGHT" "musl COPYRIGHT"

# Reproduce precisely the two generated headers aio.c's internal include path
# needs, using the pinned source Makefile's recipes. The raw aio.c bytes are
# never rewritten; its SHA is repeated after compilation below.
mkdir -p "$source_tree/obj/include/bits" "$source_tree/obj/src/internal"
sed -f "$source_tree/tools/mkalltypes.sed" \
    "$source_tree/arch/x86_64/bits/alltypes.h.in" \
    "$source_tree/include/alltypes.h.in" >"$source_tree/obj/include/bits/alltypes.h"
cp "$source_tree/arch/x86_64/bits/syscall.h.in" "$source_tree/obj/include/bits/syscall.h"
sed -n -e 's/__NR_/SYS_/p' "$source_tree/arch/x86_64/bits/syscall.h.in" \
    >>"$source_tree/obj/include/bits/syscall.h"

python3 -B - "$source_tree/src/aio/aio.c" "$work/source-order.json" <<'PY'
import json
from pathlib import Path
import sys

source_path, record_path = map(Path, sys.argv[1:])
source = source_path.read_text(encoding="utf-8")
queue_ref = source.index("\tq->ref++;")
queue_unlock = source.index("\tpthread_mutex_unlock(&q->lock);", queue_ref)
submit_block = source.index("\tpthread_sigmask(SIG_BLOCK, &allmask, &origmask);", queue_unlock)
submit_create = source.index("\tif (pthread_create(&td, &a, io_thread_func, &args)) {", submit_block)
submit_restore = source.index("\tpthread_sigmask(SIG_SETMASK, &origmask, 0);", submit_create)
if "__block_app_sigs" in source:
    raise SystemExit("aio.c unexpectedly calls __block_app_sigs")
record_path.write_text(json.dumps({
    "schema": "crabc.x86_64-pinned-musl-aio-source-order/v1",
    "source": "src/aio/aio.c",
    "submit_offsets": {
        "queue_reference_increment": queue_ref,
        "queue_mutex_unlock": queue_unlock,
        "all_signal_block": submit_block,
        "pthread_create": submit_create,
        "original_mask_restore": submit_restore,
    },
    "calls_block_app_sigs": False,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

object="$work/aio-source-signal-order-witness.o"
binary="$work/aio-source-signal-order-witness"
link_map="$work/aio-source-signal-order-witness.link.map"
source_symbols="$work/source-object.symbols"
close_member="$work/oracle-close.lo"
close_symbols="$work/oracle-close.symbols"
archive_members="$work/oracle-archive-members"
binary_symbols="$work/binary.symbols"
close_disassembly="$work/close.disassembly"
headers="$work/binary.program-headers"
dynamic="$work/binary.dynamic"

# Source internal headers precede only the pinned oracle's public headers;
# sanitize ambient include/library compiler variables exactly as the oracle
# verifier does. There is no compiler wrapper, LD_PRELOAD, or source rewrite.
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c99 -D_XOPEN_SOURCE=700 -fno-stack-protector -fno-builtin \
    -I "$work/source" \
    -I "$source_tree/arch/x86_64" -I "$source_tree/arch/generic" \
    -I "$source_tree/obj/src/internal" -I "$source_tree/src/include" \
    -I "$source_tree/src/internal" -I "$source_tree/obj/include" \
    -I "$source_tree/include" -pthread -c "$WITNESS_SOURCE" -o "$object"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -static -fno-pie -no-pie -pthread "$object" \
    -Wl,-Map,"$link_map" -lc -o "$binary"

readelf --symbols --wide "$object" >"$source_symbols"
assert_symbol "$source_symbols" GLOBAL HIDDEN __aio_close "included aio.c object"
assert_symbol "$source_symbols" GLOBAL DEFAULT aio_cancel "included aio.c object"
assert_symbol "$source_symbols" GLOBAL DEFAULT aio_read "included aio.c object"
ar t "$ORACLE_ARCHIVE" >"$archive_members"
grep -Fxq aio.lo "$archive_members" || fail "oracle archive lacks aio.lo"
grep -Fxq close.lo "$archive_members" || fail "oracle archive lacks close.lo"
ar p "$ORACLE_ARCHIVE" close.lo >"$close_member"
readelf --symbols --wide "$close_member" >"$close_symbols"
assert_symbol "$close_symbols" WEAK HIDDEN __aio_close "oracle close.lo"
assert_symbol "$close_symbols" GLOBAL DEFAULT close "oracle close.lo"
grep -Fq "$ORACLE_ARCHIVE(close.lo)" "$link_map" || fail "link did not select oracle close.lo"
if grep -Fq "$ORACLE_ARCHIVE(aio.lo)" "$link_map"; then
    fail "link selected archive aio.lo beside the direct included aio.c object"
fi

readelf --file-header --wide "$binary" >"$work/binary.file-header"
grep -Fq 'Type:                              EXEC (Executable file)' "$work/binary.file-header" \
    || fail "source witness is not static ET_EXEC"
assert_no_dynamic_runtime "$binary" "$headers" "$dynamic"
readelf --symbols --wide "$binary" >"$binary_symbols"
assert_symbol "$binary_symbols" GLOBAL HIDDEN __aio_close "linked source witness"
assert_symbol "$binary_symbols" GLOBAL DEFAULT aio_cancel "linked source witness"
assert_symbol "$binary_symbols" GLOBAL DEFAULT close "linked source witness"
objdump -d --disassemble=close "$binary" >"$close_disassembly"
grep -Eq 'call[[:space:]].*<__aio_close>' "$close_disassembly" \
    || fail "oracle close does not call the included aio.c __aio_close"

run_case() {
    local mode="$1" expected="$2" status
    set +e
    env -u LD_LIBRARY_PATH -u LD_PRELOAD timeout 8 "$binary" "$mode" \
        >"$work/${mode}.stdout" 2>"$work/${mode}.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/${mode}.status"
    [ "$status" -eq 0 ] || fail "$mode source-order witness exited $status"
    printf '%s\n' "$expected" >"$work/${mode}.expected"
    cmp "$work/${mode}.expected" "$work/${mode}.stdout" \
        || fail "$mode source-order checkpoint stream drifted"
    [ ! -s "$work/${mode}.stderr" ] || fail "$mode source-order witness wrote stderr"
}

run_case early 'mode=early events=SQWHRAX child_status=0 timeout=0 classification=early-close-returned'
run_case deferred 'mode=deferred events=SQWBPUHRVX child_status=0 timeout=0 classification=deferred-close-returned'
assert_sha256 "$SOURCE_AIO_SHA256" "$source_tree/src/aio/aio.c" "src/aio/aio.c after witness compile"

python3 -B - "$work/evidence.json" "$work" "$MUSL_ARCHIVE" "$ORACLE_ARCHIVE" \
    "$WITNESS_SOURCE" "$object" "$binary" "$ROOT/compat/x86_64/run_aio_source_signal_order.sh" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

record_path, work, source_archive, oracle_archive, witness_source, obj, binary, runner = map(Path, sys.argv[1:])
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
record = {
    "schema": "crabc.x86_64-pinned-musl-aio-source-signal-order/v1",
    "status": "passed",
    "instrumented_fixed_source_only": True,
    "unmodified_musl_execution": False,
    "crabc_product_execution": False,
    "source_archive": {
        "path": str(source_archive),
        "sha256": digest(source_archive),
        "release": "musl-1.2.6",
        "revision": "9fa28ece75d8a2191de7c5bb53bed224c5947417",
    },
    "harness": {
        "witness_source": str(witness_source),
        "witness_source_sha256": digest(witness_source),
        "runner": str(runner),
        "runner_sha256": digest(runner),
        "source_object_sha256": digest(obj),
        "binary_sha256": digest(binary),
    },
    "oracle_static_archive": {
        "path": str(oracle_archive),
        "sha256": digest(oracle_archive),
    },
    "cases": {
        mode: {
            "stdout": f"{mode}.stdout",
            "stdout_sha256": digest(work / f"{mode}.stdout"),
            "stderr": f"{mode}.stderr",
            "stderr_sha256": digest(work / f"{mode}.stderr"),
            "raw_status": int((work / f"{mode}.status").read_text(encoding="utf-8")),
        }
        for mode in ("early", "deferred")
    },
    "checkpoints": {
        "early": "SQWHRAX",
        "deferred": "SQWBPUHRVX",
        "Q": "seed pipe-read observed in /proc/self/task/*/wchan",
        "H": "SIGUSR1 handler entered",
        "R": "handler close(exact seeded fd) returned",
        "U": "source SIG_SETMASK handoff begins",
        "V": "source SIG_SETMASK handoff returned",
    },
    "result": "close reentry returned in the controlled pre-block and deferred handoff schedules",
}
record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf 'pinned musl aio source-signal-order: PASS; evidence: %s\n' "$work"
