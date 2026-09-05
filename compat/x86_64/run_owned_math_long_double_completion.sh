#!/usr/bin/env bash
# Supplied-product x87 binary80 fdiml/exp10l/pow10l consumer differential.
#
# `libc_math_long_double_completion_probe.c` is the existing fixed musl 1.2.6
# behavioral source. It is compiled exactly once through the supplied dynamic
# driver, then that one ET_REL object is linked to musl, the optional supplied
# static product, and the supplied dynamic product. The raw binary80 record
# format checks typed SysV calls, signed zero, NaN/infinity, finite boundaries,
# all four x87/MXCSR rounding modes, exceptions, and control restoration.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly SOURCE="$ROOT/compat/x86_64/libc_math_long_double_completion_probe.c"
readonly VALIDATOR="$ROOT/compat/x86_64/validate_libc_math_long_double_completion.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly RECORDS=247

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'ERROR: owned binary80 long-double completion: %s\n' "$*" >&2
    exit 1
}

static_sysroot=''
dynamic_sysroot=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] || usage
            [ -n "$2" ] && [[ "$2" != -* ]] && [ -z "$static_sysroot" ] || usage
            static_sysroot="$2"
            shift 2
            ;;
        -*)
            usage
            ;;
        *)
            [ -n "$1" ] && [ -z "$dynamic_sysroot" ] || usage
            dynamic_sysroot="$1"
            shift
            ;;
    esac
done
[ -n "$dynamic_sysroot" ] || usage

[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'
for tool in cmp cp mkdir mktemp python3 readelf realpath timeout wc; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl oracle compiler'
[ -f "$SOURCE" ] || fail 'missing fixed binary80 source'
[ -f "$VALIDATOR" ] || fail 'missing binary80 record validator'
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail 'requires repository-local TMPDIR'

checkout_physical="$(realpath -e "$ROOT")" || fail 'cannot resolve checkout root'
temporary_physical="$(realpath -e "$TMPDIR")" || fail 'cannot resolve TMPDIR'
case "$temporary_physical" in
    "$checkout_physical"/.work/*) ;;
    *) fail 'TMPDIR physically escapes checkout .work' ;;
esac

dynamic_sysroot="$(realpath -e -- "$dynamic_sysroot")" || fail 'cannot resolve dynamic sysroot'
if [ -n "$static_sysroot" ]; then
    static_sysroot="$(realpath -e -- "$static_sysroot")" || fail 'cannot resolve static sysroot'
fi

# The common validator authenticates each product manifest/payload and every
# sealed link receipt. It also rejects ambient link inputs and wrong ELF mode.
python3 -B - "$ROOT" "$dynamic_sysroot" "$static_sysroot" <<'PY'
from pathlib import Path
import sys

root_text, dynamic_text, static_text = sys.argv[1:]
root, dynamic = Path(root_text), Path(dynamic_text)
static = Path(static_text) if static_text else None
if not dynamic.is_relative_to(root / ".work"):
    raise SystemExit("owned binary80 long-double dynamic product escapes checkout .work")
if static is not None and not static.is_relative_to(root / ".work"):
    raise SystemExit("owned binary80 long-double static product escapes checkout .work")
sys.path.insert(0, str(root / "compat/x86_64"))
from owned_posix_product_evidence import _validate_dynamic_product, _validate_static_product
_validate_dynamic_product(dynamic)
if static is not None:
    _validate_static_product(static)
PY

work="$(mktemp -d "$TMPDIR/owned-math-long-double-completion.XXXXXX")"
readonly work
printf 'owned binary80 long-double completion evidence: %s\n' "$work"

capture() {
    local prefix="$1" status=0
    shift
    "$@" >"$prefix.stdout" 2>"$prefix.stderr" || status=$?
    printf '%s\n' "$status" >"$prefix.status"
    [ "$status" -eq 0 ] || fail "${prefix##*/} exited with ${status}"
}

validate_records() {
    local prefix="$1"
    python3 -B "$VALIDATOR" "$prefix.stdout" || fail "${prefix##*/} emitted invalid binary80 records"
    [ "$(wc -c <"$prefix.stdout")" -eq "$((RECORDS * 42))" ] ||
        fail "${prefix##*/} record count drifted"
    [ ! -s "$prefix.stderr" ] || fail "${prefix##*/} wrote stderr"
}

compare_to_oracle() {
    local prefix="$1"
    validate_records "$prefix"
    cmp "$work/oracle.stdout" "$prefix.stdout" || fail "${prefix##*/} differs from pinned musl"
    cmp "$work/oracle.stderr" "$prefix.stderr" || fail "${prefix##*/} stderr differs from pinned musl"
}

validate_link() {
    local product="$1" object="$2" executable="$3" receipt="$4" linkage="$5" output="$6"
    python3 -B - "$ROOT" "$product" "$object" "$executable" "$receipt" "$linkage" "$output" <<'PY'
from pathlib import Path
import json
import sys

root, product, workload, executable, receipt, linkage, output = sys.argv[1:]
root, product, workload, executable, receipt, output = map(Path, (root, product, workload, executable, receipt, output))
sys.path.insert(0, str(root / "compat/x86_64"))
from owned_posix_product_evidence import validate_link
identity = validate_link(product, workload, executable, receipt, linkage)
output.write_text(json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

# The full runtime and consumer payload must be copied before dynamic execution.
# Verify every manifest-bound product file and the one copied application at
# each boundary, so a successful chroot cannot be attributed to a stale tree.
audit_execution_root() {
    local root="$1" consumer="$2" phase="$3"
    python3 -B - "$dynamic_sysroot" "$root" "$consumer" "$work/execution-${phase}.json" <<'PY'
from pathlib import Path
import hashlib
import json
import os
import stat
import sys

product, execution_root, consumer, record = map(Path, sys.argv[1:])
def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

def regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
        raise SystemExit(f"owned binary80 long-double execution {label} is not a regular file: {path}")

manifest = json.loads((product / "share/crabc/manifest.json").read_text(encoding="utf-8"))
files = manifest.get("files")
if not isinstance(files, dict) or not files:
    raise SystemExit("owned binary80 long-double execution product lacks payload hashes")
payload = {}
for relative, expected in sorted(files.items()):
    source, copied = product / relative, execution_root / relative
    regular(source, "source payload")
    regular(copied, "copied payload")
    source_digest, copied_digest = digest(source), digest(copied)
    if source_digest != expected:
        raise SystemExit(
            f"owned binary80 long-double execution source payload drifted: {relative} "
            f"expected={expected} actual={source_digest}"
        )
    if copied_digest != expected:
        raise SystemExit(
            f"owned binary80 long-double execution copied payload drifted: {relative} "
            f"expected={expected} actual={copied_digest}"
        )
    payload[relative] = expected
regular(consumer, "consumer")
copied_consumer = execution_root / "consumer"
regular(copied_consumer, "copied consumer")
if digest(consumer) != digest(copied_consumer):
    raise SystemExit("owned binary80 long-double execution consumer drifted")
record.write_text(json.dumps({"payload": payload, "consumer_sha256": digest(consumer)}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

# This is the one source translation for every oracle, static, and dynamic
# link. No candidate-specific macro or replacement source changes the frozen
# binary80 workload.
"$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_GNU_SOURCE \
    -fno-builtin -fno-stack-protector \
    -c "$SOURCE" -o "$work/workload.o"

"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -lm -o "$work/oracle"
capture "$work/oracle" "$work/oracle"
validate_records "$work/oracle"

if [ -n "$static_sysroot" ]; then
    for mode in static static-pie; do
        candidate="$work/$mode"
        receipt="$work/$mode.receipt.json"
        (
            cd "$work"
            "$static_sysroot/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
                "$work/workload.o" -o "$candidate"
        )
        validate_link "$static_sysroot" "$work/workload.o" "$candidate" "$receipt" "$mode" \
            "$work/$mode.link.json"
        capture "$work/$mode" "$candidate"
        compare_to_oracle "$work/$mode"
    done
fi

for mode in pie non-pie; do
    candidate="$work/dynamic-$mode"
    "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    validate_link "$dynamic_sysroot" "$work/workload.o" "$candidate" \
        "$candidate.crabc-link.json" "$mode" "$work/dynamic-$mode.link.json"
done

# Use a separate complete product copy for every kernel/direct launch. That
# keeps both entries observable and makes each pre/post copy audit independent.
for mode in pie non-pie; do
    for entry in kernel direct; do
        root="$work/dynamic-$mode-$entry-root"
        cp -a -- "$dynamic_sysroot" "$root"
        cp -- "$work/dynamic-$mode" "$root/consumer"
        audit_execution_root "$root" "$work/dynamic-$mode" "$mode-$entry-pre"
        if [ "$entry" = kernel ]; then
            capture "$work/dynamic-$mode-$entry" /usr/sbin/chroot "$root" /consumer
        else
            capture "$work/dynamic-$mode-$entry" /usr/sbin/chroot "$root" "$INTERPRETER" /consumer
        fi
        compare_to_oracle "$work/dynamic-$mode-$entry"
        audit_execution_root "$root" "$work/dynamic-$mode" "$mode-$entry-post"
        cmp "$work/execution-$mode-$entry-pre.json" "$work/execution-$mode-$entry-post.json" ||
            fail "dynamic-$mode-$entry execution payload changed"
    done
done

printf 'owned binary80 long-double completion: PASS (one installed-header object; pinned musl; optional static/static-PIE; dynamic PIE/non-PIE kernel/direct; %s exact binary80 records per execution) evidence: %s\n' \
    "$RECORDS" "$work"
