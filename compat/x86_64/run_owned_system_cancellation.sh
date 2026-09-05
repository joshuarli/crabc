#!/usr/bin/env bash
# Source-defined system/pclose wait ownership with an isolated test exec target.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly witness="$ROOT/compat/x86_64/run_pthread_wait_witness.py"
readonly probe="$ROOT/compat/x86_64/owned_system_cancellation_probe.c"
readonly child="$ROOT/compat/x86_64/owned_system_cancellation_child.c"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
[ "$(uname -sm)" = 'Linux x86_64' ]
python3 -B - "$ROOT" "${TMPDIR:-}" "${1:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('system cancellation TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('system cancellation product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-system-cancellation.XXXXXX")"
printf 'owned system cancellation evidence: %s\n' "$work"
mkdir -p "$work/oracle-root/bin"
"$oracle_cc" -std=c11 -I"$ROOT/include" -E -H "$probe" >/dev/null 2>"$work/oracle.headers"
for header in errno.h pthread.h stdio.h stdlib.h signal.h sys/wait.h poll.h bits/alltypes.h; do
    grep -Fq "$ROOT/include/$header" "$work/oracle.headers"
done
"$oracle_cc" -std=c11 -static -fno-pie -no-pie -pthread -fno-builtin -I"$ROOT/include" "$probe" -o "$work/oracle-root/consumer"
"$oracle_cc" -std=c11 -static -fno-pie -no-pie -fno-builtin -I"$ROOT/include" "$child" -o "$work/oracle-root/bin/sh"


run_consumer() {
    local execution_root="$1" consumer="$2" label="$3"
    for scenario in normal failure timeout; do
        local -a arguments=()
        if [ "$scenario" != normal ]; then arguments=("$scenario"); fi
        printf 'system cancellation running %s/%s\n' "$label" "$scenario"
        timeout 30 env -i PATH="$PATH" python3 -B "$witness" "$execution_root" \
            "$consumer" "${arguments[@]}" >"$work/$label-$scenario.stdout"
        if [ "$scenario" = normal ]; then grep -qx owned-system-cancellation-ok "$work/$label-$scenario.stdout"; fi
        if [ "$label" != oracle ]; then cmp "$work/oracle-$scenario.stdout" "$work/$label-$scenario.stdout"; fi
    done
}
run_consumer "$work/oracle-root" /consumer oracle
printf 'system cancellation pinned-musl oracle: PASS\n'

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
receipt = json.loads(Path(receipt_text).read_text())
def require(value, message):
    if not value:
        raise SystemExit('system cancellation artifact: ' + message)
expected_format = 'crabc-x86-64-owned-dynamic-sysroot-v1' if family == 'dynamic' else 'crabc-x86-64-sealed-static-driver-v1'
require(receipt.get('schema') == 1 and receipt.get('format') == expected_format, 'sealed driver receipt')
output_hash = receipt.get('output_sha256') if family == 'dynamic' else receipt.get('output', {}).get('sha256')
require(output_hash == hashlib.sha256(candidate.read_bytes()).hexdigest(), 'output receipt hash')
header = Path(str(candidate) + '.header').read_text()
require('Advanced Micro Devices X86-64' in header, 'machine')
elf_type = 'DYN' if mode in ('pie', 'static-pie') else 'EXEC'
require(re.search(r'Type:\s+' + elf_type + r'\s', header), 'ELF entry mode')
segments = Path(str(candidate) + '.segments').read_text()
dynamic = Path(str(candidate) + '.dynamic').read_text()
interpreters = re.findall(r'Requesting program interpreter: ([^\]]+)\]', segments)
needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic)
require(interpreters == (['/lib/ld-crabc-x86_64.so.1'] if family == 'dynamic' else []), 'interpreter boundary')
require(needed == (['libc.so'] if family == 'dynamic' else []), 'owned runtime dependencies')
require('(TEXTREL)' not in dynamic, 'text relocation')
PY
}

run_product() {
    local family="$1" product="$2" mode
    local -a modes=(static static-pie)
    local driver="$product/bin/crabc-cc"
    if [ "$family" = dynamic ]; then modes=(pie non-pie); driver="$product/bin/crabc-cc-dynamic"; fi
    for mode in "${modes[@]}"; do
        local label="$family-$mode" execution_root="$work/$family-$mode-root"
        local entry="-$mode"
        if [ "$family" = dynamic ]; then entry="--dynamic-$mode"; fi
        cp -a "$product" "$execution_root"
        for name in consumer child; do
            local source_file="$probe" candidate="$work/$label-$name"
            if [ "$name" = child ]; then source_file="$child"; fi
            "$driver" "$entry" -std=c11 -fno-builtin -fno-stack-protector -c "$source_file" -o "$candidate.o"
            local receipt="$candidate.crabc-link.json"
            local -a receipt_arguments=()
            if [ "$family" = static ]; then receipt="$candidate.receipt.json"; receipt_arguments=(--link-receipt "$(basename "$receipt")"); fi
            (cd "$work"; "$driver" "$entry" "${receipt_arguments[@]}" "$candidate.o" -o "$candidate")
            audit_consumer "$family" "$mode" "$candidate" "$receipt"
            if [ "$name" = child ]; then cp "$candidate" "$execution_root/bin/sh";
            else cp "$candidate" "$execution_root/consumer"; fi
        done
        run_consumer "$execution_root" /consumer "$label"
        if [ "$family" = dynamic ]; then
            # The fixed-path exec child still enters via its owned PT_INTERP;
            # this second route varies only the parent consumer's initial entry.
            for scenario in normal failure timeout; do
                local -a arguments=()
                if [ "$scenario" != normal ]; then arguments=("$scenario"); fi
                timeout 30 env -i PATH="$PATH" python3 -B "$witness" "$execution_root" \
                    /lib/ld-crabc-x86_64.so.1 /consumer "${arguments[@]}" >"$work/$label-direct-$scenario.stdout"
                cmp "$work/oracle-$scenario.stdout" "$work/$label-direct-$scenario.stdout"
            done
        fi
        printf 'system cancellation %s: PASS\n' "$label"
    done
}
provided_dynamic="${1:-}"
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
    run_product static "$work/static-product"
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
run_product dynamic "$(realpath -e "$provided_dynamic")"
printf 'owned system cancellation: PASS (musl system/pclose source waits, contained protocol exec, child ownership and supervisor cleanup); evidence: %s\n' "$work"
