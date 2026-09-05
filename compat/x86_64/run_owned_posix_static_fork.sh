#!/usr/bin/env bash
# Immutable supplied-static adapters for the existing fork workloads.
#
# This runner deliberately owns no dynamic-fork claim. It compiles each
# unchanged workload once with the supplied static product's static-PIE source
# policy, then links those exact object bytes to pinned musl and both sealed
# static entries. The raw execution roots are disposable so the POSIX probe's
# child-root transition remains an observable part of the workload.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly EVIDENCE="$ROOT/compat/x86_64/owned_static_fork_evidence.py"
readonly CHROOT="$(command -v chroot)"

usage() {
    printf 'usage: %s --static-sysroot STATIC_SYSROOT\n' "$0" >&2
    exit 2
}

[ "$#" -eq 2 ] && [ "$1" = --static-sysroot ] && [ -n "$2" ] || usage
case "$2" in
    -*) usage ;;
esac
readonly PROVIDED_STATIC="$(realpath -e -- "$2")"

# Reject path escapes and a missing checkout-managed scratch directory before
# a supplied driver or any mutable evidence path is used. The driver plans
# below then validate its complete physical payload before compilation.
python3 -B - "$ROOT" "${TMPDIR:-}" "$PROVIDED_STATIC" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
product = Path(sys.argv[3])
if (
    not temporary.is_dir()
    or temporary.is_symlink()
    or temporary.resolve() != temporary
    or not temporary.is_relative_to(root / ".work")
):
    raise SystemExit("owned POSIX static fork TMPDIR must be a physical checkout .work directory")
if (
    not product.is_dir()
    or product.is_symlink()
    or product.resolve() != product
    or not product.is_relative_to(root / ".work")
):
    raise SystemExit("owned POSIX static fork product must be a physical checkout .work directory")
PY

readonly STATIC_DRIVER="$PROVIDED_STATIC/bin/crabc-cc"
[ -x "$ORACLE_CC" ] || {
    printf 'owned POSIX static fork: missing pinned musl oracle compiler\n' >&2
    exit 1
}
[ -f "$EVIDENCE" ] || {
    printf 'owned POSIX static fork: missing specialized evidence helper\n' >&2
    exit 1
}
[ "$(uname -sm)" = 'Linux x86_64' ] || {
    printf 'owned POSIX static fork: requires native Linux/x86-64\n' >&2
    exit 1
}

# These are read-only preflight calls. The sealed driver verifies every
# installed payload hash before it emits either plan, so no malformed supplied
# product can reach source translation or create a runner work directory.
"$STATIC_DRIVER" --print-link-plan -static >/dev/null
"$STATIC_DRIVER" --print-link-plan -static-pie >/dev/null

readonly work="$(mktemp -d "$TMPDIR/owned-posix-static-fork.XXXXXX")"
chmod a+rx "$work"
printf 'owned POSIX static fork evidence: %s\n' "$work"

finish() {
    local status=$?
    trap - EXIT
    chmod -R a+rX "$work" || status=1
    if [ "$status" -ne 0 ]; then
        printf 'owned POSIX static fork retained failure evidence: %s\n' "$work" >&2
    fi
    exit "$status"
}
trap finish EXIT

fail() {
    printf 'owned POSIX static fork: %s\n' "$*" >&2
    exit 1
}

source_for_role() {
    case "$1" in
        atfork-registry)
            printf '%s\n' "$ROOT/compat/x86_64/owned_atfork_registry_probe.c"
            ;;
        static-posix-forkexec)
            printf '%s\n' "$ROOT/compat/x86_64/owned_static_posix_probe.c"
            ;;
        *) fail "unknown workload role: $1" ;;
    esac
}

assert_unchanged() {
    local baseline="$1" path="$2" observed="$3" description="$4"
    sha256sum "$path" >"$observed"
    cmp "$baseline" "$observed" || fail "$description changed after its immutable boundary"
}

validate_sealed_link() {
    local role_dir="$1" linkage="$2" candidate="$3" receipt="$4"
    local identity="$role_dir/$linkage/link-identity.json"

    python3 -B - "$ROOT" "$PROVIDED_STATIC" "$role_dir/workload.o" "$candidate" \
        "$receipt" "$linkage" "$identity" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "compat/x86_64"))
from owned_posix_product_evidence import validate_link

product, workload, executable, receipt = map(Path, sys.argv[2:6])
identity_path = Path(sys.argv[7])
identity = validate_link(product, workload, executable, receipt, sys.argv[6])
if identity_path.exists() or identity_path.is_symlink():
    raise SystemExit("owned POSIX static fork link identity path is unsafe")
with identity_path.open("x", encoding="utf-8", newline="\n") as output:
    json.dump(identity, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
}

audit_musl_static_image() {
    local candidate="$1"
    readelf -hW "$candidate" >"$candidate.header"
    readelf -lW "$candidate" >"$candidate.segments"
    readelf -dW "$candidate" >"$candidate.dynamic"
    python3 -B - "$candidate.header" "$candidate.segments" "$candidate.dynamic" <<'PY'
from pathlib import Path
import re
import sys

header, segments, dynamic = (Path(path).read_text(encoding="utf-8") for path in sys.argv[1:])
if re.search(r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$", header, re.MULTILINE) is None:
    raise SystemExit("owned POSIX static fork musl oracle is not an x86-64 ELF")
if re.search(r"^\s*Type:\s+EXEC(?:\s| \()", header, re.MULTILINE) is None:
    raise SystemExit("owned POSIX static fork musl oracle is not ET_EXEC")
if re.search(r"^\s*INTERP\b", segments, re.MULTILINE) is not None:
    raise SystemExit("owned POSIX static fork musl oracle acquired PT_INTERP")
if re.search(r"\(NEEDED\)", dynamic) is not None:
    raise SystemExit("owned POSIX static fork musl oracle acquired DT_NEEDED")
PY
}

run_in_disposable_root() {
    local role_dir="$1" linkage="$2" candidate="$3"
    local execution_root="$role_dir/$linkage/root"
    local raw_prefix="$role_dir/$linkage/ordinary"
    local status

    mkdir -p "$execution_root/workload"
    chmod a+rx "$execution_root" "$execution_root/workload"
    cp "$candidate" "$execution_root/workload/consumer"
    chmod a+rx "$execution_root/workload/consumer"
    set +e
    timeout 60 env -i PATH=/ LC_ALL=C "$CHROOT" "$execution_root" /workload/consumer \
        >"$raw_prefix.stdout" 2>"$raw_prefix.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$raw_prefix.status"
    [ "$status" -eq 0 ] || fail "$linkage/$role_dir ordinary workload exited with $status"
}

compare_raw() {
    local role_dir="$1" linkage="$2" suffix
    for suffix in stdout stderr status; do
        cmp "$role_dir/musl/ordinary.$suffix" "$role_dir/$linkage/ordinary.$suffix" ||
            fail "$role_dir $linkage ordinary $suffix differs from pinned musl"
    done
}

for role in atfork-registry static-posix-forkexec; do
    readonly_source="$(source_for_role "$role")"
    [ -f "$readonly_source" ] || fail "missing workload source: $readonly_source"
    role_dir="$work/$role"
    mkdir -p "$role_dir/musl" "$role_dir/static" "$role_dir/static-pie"
    chmod a+rx "$role_dir" "$role_dir/musl" "$role_dir/static" "$role_dir/static-pie"

    sha256sum "$readonly_source" >"$role_dir/source-before.sha256"
    "$STATIC_DRIVER" -static-pie -std=c11 -c "$readonly_source" -o "$role_dir/workload.o"
    sha256sum "$role_dir/workload.o" >"$role_dir/workload.sha256"
    python3 -B "$EVIDENCE" compile "$ROOT" "$PROVIDED_STATIC" "$role" \
        "$readonly_source" "$role_dir/workload.o" "$role_dir/compile.json" \
        "$role_dir/headers.d" "$role_dir/headers.trace"

    "$ORACLE_CC" -static -fno-pie -no-pie -pthread "$role_dir/workload.o" \
        -o "$role_dir/musl/consumer"
    assert_unchanged "$role_dir/workload.sha256" "$role_dir/workload.o" \
        "$role_dir/workload.after-musl.sha256" "$role workload object"
    audit_musl_static_image "$role_dir/musl/consumer"
    run_in_disposable_root "$role_dir" musl "$role_dir/musl/consumer"

    for linkage in static static-pie; do
        (
            cd "$role_dir/$linkage"
            "$STATIC_DRIVER" "-$linkage" --link-receipt receipt.json \
                "$role_dir/workload.o" -o consumer
        )
        assert_unchanged "$role_dir/workload.sha256" "$role_dir/workload.o" \
            "$role_dir/workload.after-$linkage.sha256" "$role workload object"
        validate_sealed_link "$role_dir" "$linkage" "$role_dir/$linkage/consumer" \
            "$role_dir/$linkage/receipt.json"
        run_in_disposable_root "$role_dir" "$linkage" "$role_dir/$linkage/consumer"
        compare_raw "$role_dir" "$linkage"
    done

    sha256sum "$readonly_source" >"$role_dir/source-after.sha256"
    python3 -B "$EVIDENCE" role "$role" "$readonly_source" "$role_dir" "$PROVIDED_STATIC"
    printf 'owned POSIX static fork %s: PASS\n' "$role"
done

printf 'owned POSIX static fork: PASS (two unchanged static-PIE objects, pinned musl + supplied static ET_EXEC/static-PIE, retained source/header/link/raw disposable-root evidence); evidence: %s\n' "$work"
