#!/usr/bin/env bash
# Source-bound installed POSIX filesystem composition through every owned mode.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_posix_filesystem_probe.c"
readonly cases=(aliases directory traversal temporary handles)
# The traversal transcript proves deferred cancellation ends as PTHREAD_CANCELED
# after the callback gate releases; a filesystem without native handles reports
# the explicit, comparable "handles unavailable" outcome.

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath "$provided_dynamic")"
fi

# Validate the optional installed/extracted product before making evidence.
# This runner owns only disposable checkout state; its chroots never operate on
# a host pathname outside their copied execution root.
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
product_argument = sys.argv[3]
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned POSIX filesystem TMPDIR must be a physical checkout .work directory")
if product_argument:
    product = Path(product_argument)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit("owned POSIX filesystem product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-posix-filesystem.XXXXXX")"
chmod a+rx "$work"
printf 'owned POSIX filesystem evidence: %s\n' "$work"
trap 'printf "owned POSIX filesystem failed near %s; evidence: %s\\n" "${step:-setup}" "$work" >&2' ERR

# All names are ordinary strong public providers in the installed aggregate.
# The __*stat declarations are source-verified compatibility aliases; they are
# deliberately not added to public project headers merely for this probe.
assert_posix_filesystem_symbols() {
    local binary="$1" table="$2" output="$3"

    readelf --wide "$table" "$binary" >"$output"
    python3 -B - "$output" <<'PYTHON'
from pathlib import Path
import sys

names = {
    "__fxstat", "__fxstatat", "__lxstat", "__xstat",
    "alphasort", "ftw", "lchmod", "mktemp", "name_to_handle_at",
    "nftw", "open_by_handle_at", "readdir_r", "scandir", "telldir",
    "tempnam", "tmpnam", "versionsort",
}
records = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in names:
        records.setdefault(fields[7], []).append(fields)
if set(records) != names:
    raise SystemExit(f"owned POSIX filesystem symbol roster differs: {records}")
for name, entries in records.items():
    if len(entries) != 1:
        raise SystemExit(f"owned POSIX filesystem duplicate provider: {name}: {entries}")
    fields = entries[0]
    if fields[3:6] != ["FUNC", "GLOBAL", "DEFAULT"] or fields[6] == "UND":
        raise SystemExit(f"owned POSIX filesystem provider binding: {name}: {fields}")
PYTHON
}

audit_consumer() {
    local family="$1" mode="$2" candidate="$3" receipt="$4"

    readelf -hW "$candidate" >"$candidate.header"
    readelf -lW "$candidate" >"$candidate.segments"
    readelf -dW "$candidate" >"$candidate.dynamic"
    python3 -B - "$family" "$mode" "$candidate" "$receipt" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

family, mode, candidate_text, receipt_text = sys.argv[1:]
candidate = Path(candidate_text)
receipt = json.loads(Path(receipt_text).read_text(encoding="utf-8"))

def require(value, message):
    if not value:
        raise SystemExit("owned POSIX filesystem artifact: " + message)

expected_format = (
    "crabc-x86-64-owned-dynamic-sysroot-v1"
    if family == "dynamic" else "crabc-x86-64-sealed-static-driver-v1"
)
require(receipt.get("schema") == 1 and receipt.get("format") == expected_format,
        "sealed driver receipt")
output_hash = (
    receipt.get("output_sha256")
    if family == "dynamic" else receipt.get("output", {}).get("sha256")
)
require(output_hash == hashlib.sha256(candidate.read_bytes()).hexdigest(),
        "output receipt hash")
header = Path(str(candidate) + ".header").read_text(encoding="utf-8")
require("Advanced Micro Devices X86-64" in header, "machine")
expected_type = "DYN" if mode in ("pie", "static-pie") else "EXEC"
require(re.search(r"Type:\s+" + expected_type + r"\s", header), "ELF entry mode")
segments = Path(str(candidate) + ".segments").read_text(encoding="utf-8")
dynamic = Path(str(candidate) + ".dynamic").read_text(encoding="utf-8")
interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)\]", segments)
needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)
require(interpreters == (["/lib/ld-crabc-x86_64.so.1"] if family == "dynamic" else []),
        "interpreter boundary")
require(needed == (["libc.so"] if family == "dynamic" else []),
        "owned runtime dependencies")
require("(TEXTREL)" not in dynamic, "text relocations")
PY
}

# Each child has only a private copied product. The workload creates /work and
# only observes legacy absent names below /work or /tmp inside that chroot.
run_in_root() {
    local root="$1" output="$2"
    shift 2
    mkdir -p "$root/tmp"
    step="run-${output##*/}"
    timeout 35 env -i PATH="$PATH" chroot "$root" "$@" \
        >"$output" 2>"${output%.stdout}.stderr"
}

# Build the dynamic product first so exactly one installed dynamic driver emits
# the source object consumed unchanged by musl, static/static-PIE, and dynamic
# PIE/non-PIE links. A supplied product replaces only product creation.
if [ -z "$provided_dynamic" ]; then
    step=build-dynamic
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
readonly installed="$provided_dynamic"
step=compile-installed-object
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"

step=link-oracle
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
assert_posix_filesystem_symbols "$work/oracle" --syms "$work/oracle-symbols.txt"
mkdir -p "$work/oracle-root/tmp"
cp "$work/oracle" "$work/oracle-root/consumer"
for scenario in "${cases[@]}"; do
    run_in_root "$work/oracle-root" "$work/oracle-$scenario.stdout" /consumer "$scenario"
done
printf 'owned POSIX filesystem pinned-musl oracle: PASS\n'

# Without a supplied dynamic product the focused command qualifies both owned
# static entries too. Product qualification calls this runner with one supplied
# dynamic product, intentionally skipping static construction rather than
# treating this leaf as promotion evidence.
if [ -z "${1:-}" ]; then
    step=build-static
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    assert_posix_filesystem_symbols "$work/static-sysroot/usr/lib/libc.a" --syms \
        "$work/static-archive-symbols.txt"
    for mode in static static-pie; do
        candidate="$work/static-$mode"
        receipt="$candidate.receipt.json"
        step="link-static-$mode"
        (
            cd "$work"
            "$work/static-sysroot/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
                "$work/workload.o" -o "$candidate"
        )
        audit_consumer static "$mode" "$candidate" "$receipt"
        assert_posix_filesystem_symbols "$candidate" --syms "$candidate-symbols.txt"
        root="$work/static-$mode-root"
        mkdir -p "$root/tmp"
        cp "$candidate" "$root/consumer"
        for scenario in "${cases[@]}"; do
            run_in_root "$root" "$work/static-$mode-$scenario.stdout" /consumer "$scenario"
            cmp "$work/oracle-$scenario.stdout" "$work/static-$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/static-$mode-$scenario.stderr"
        done
        printf 'owned POSIX filesystem static %s: PASS\n' "$mode"
    done
fi

assert_posix_filesystem_symbols "$installed/usr/lib/libc.so" --dyn-syms \
    "$work/dynamic-provider-symbols.txt"
for mode in pie non-pie; do
    candidate="$work/dynamic-$mode"
    step="link-dynamic-$mode"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    audit_consumer dynamic "$mode" "$candidate" "$candidate.crabc-link.json"
    root="$work/dynamic-$mode-root"
    cp -a "$installed/." "$root/"
    cp "$candidate" "$root/consumer"
    for scenario in "${cases[@]}"; do
        for entry in kernel direct; do
            if [ "$entry" = direct ]; then
                command=(/lib/ld-crabc-x86_64.so.1 /consumer "$scenario")
            else
                command=(/consumer "$scenario")
            fi
            run_in_root "$root" "$work/dynamic-$mode-$entry-$scenario.stdout" "${command[@]}"
            cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$entry-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/dynamic-$mode-$entry-$scenario.stderr"
        done
    done
    printf 'owned POSIX filesystem dynamic %s: PASS\n' "$mode"
done

printf 'owned POSIX filesystem: PASS (same installed object, pinned musl, stat compatibility aliases, directory streams/comparators/allocation, ftw/nftw cancellation, racy legacy temporary names, contained file-handle outcomes, strong provider/receipt ELF audit, static/static-PIE and dynamic PIE/non-PIE kernel/direct chroots); evidence: %s\n' "$work"
