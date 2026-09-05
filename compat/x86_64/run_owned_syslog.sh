#!/usr/bin/env bash
# Pinned-musl syslog differential through sealed installed x86 products.
#
# The consumer binds /dev/log only after each invocation has entered its own
# disposable chroot.  Neither this runner nor the consumer writes host /dev.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_syslog_probe.c"
readonly interpreter=/lib/ld-crabc-x86_64.so.1

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
[ "$(uname -sm)" = 'Linux x86_64' ]

python3 -B - "$ROOT" "${TMPDIR:-}" "${1:-}" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned syslog TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned syslog product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-syslog.XXXXXX")"
chmod a+rx "$work"
printf 'owned syslog evidence: %s\n' "$work"

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
"$oracle_cc" -std=c11 -I"$ROOT/include" -E -H "$probe" \
    >/dev/null 2>"$work/oracle.headers"
for header in errno.h fcntl.h poll.h pthread.h sys/socket.h sys/un.h sys/wait.h syslog.h time.h unistd.h; do
    grep -Fq "$ROOT/include/$header" "$work/oracle.headers"
done

prepare_execution_root() {
    local root="$1"
    mkdir -p "$root/dev"
    : >"$root/dev/console"
}

run_scenarios() {
    local execution_root="$1" consumer="$2" label="$3"
    local entry="${4:-kernel}"
    local scenario
    local -a command=("$consumer")

    if [ "$entry" = direct ]; then command=("$interpreter" "$consumer"); fi
    for scenario in normal worker fork cancellation; do
        # Each consumer clears a stale private socket name itself.  Resetting
        # the private regular console here makes LOG_CONS output observable
        # without relying on an ordering artifact from another scenario.
        : >"$execution_root/dev/console"
        printf 'owned syslog running %s/%s/%s\n' "$label" "$entry" "$scenario"
        timeout 40 env -i PATH="$PATH" TZ=UTC+12 chroot "$execution_root" \
            "${command[@]}" "$scenario" \
            >"$work/$label-$entry-$scenario.stdout" \
            2>"$work/$label-$entry-$scenario.stderr"
        grep -qx "owned-syslog-$scenario-ok" "$work/$label-$entry-$scenario.stdout"
        if [ "$label" != oracle ]; then
            cmp "$work/oracle-kernel-$scenario.stdout" "$work/$label-$entry-$scenario.stdout"
            cmp "$work/oracle-kernel-$scenario.stderr" "$work/$label-$entry-$scenario.stderr"
        fi
    done
}

mkdir "$work/oracle-root"
prepare_execution_root "$work/oracle-root"
"$oracle_cc" -std=c11 -static -fno-pie -no-pie -pthread -fno-builtin \
    -fno-stack-protector -I"$ROOT/include" "$probe" \
    -o "$work/oracle-root/consumer"
run_scenarios "$work/oracle-root" /consumer oracle
printf 'owned syslog pinned-musl oracle: PASS\n'

audit_consumer() {
    local family="$1" mode="$2" candidate="$3" receipt="$4" provider="$5"
    readelf -hW "$candidate" >"$candidate.header"
    readelf -lW "$candidate" >"$candidate.segments"
    readelf -dW "$candidate" >"$candidate.dynamic"
    readelf -sW "$candidate" >"$candidate.symbols"
    readelf -sW "$provider" >"$candidate.provider-symbols"
    python3 -B - "$family" "$mode" "$candidate" "$receipt" "$candidate.provider-symbols" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

family, mode, candidate_text, receipt_text, provider_symbols_text = sys.argv[1:]
candidate = Path(candidate_text)
receipt = json.loads(Path(receipt_text).read_text())

def require(value, message):
    if not value:
        raise SystemExit('owned syslog artifact: ' + message)

expected_format = (
    'crabc-x86-64-owned-dynamic-sysroot-v1'
    if family == 'dynamic' else 'crabc-x86-64-sealed-static-driver-v1'
)
require(receipt.get('schema') == 1 and receipt.get('format') == expected_format,
        'sealed driver receipt')
output_hash = receipt.get('output_sha256') if family == 'dynamic' else receipt.get('output', {}).get('sha256')
require(output_hash == hashlib.sha256(candidate.read_bytes()).hexdigest(),
        'output receipt hash')
header = Path(str(candidate) + '.header').read_text()
require('Advanced Micro Devices X86-64' in header, 'machine')
expected_type = 'DYN' if mode in ('pie', 'static-pie') else 'EXEC'
require(re.search(r'Type:\s+' + expected_type + r'\s', header), 'ELF mode')
segments = Path(str(candidate) + '.segments').read_text()
dynamic = Path(str(candidate) + '.dynamic').read_text()
interpreters = re.findall(r'Requesting program interpreter: ([^\]]+)\]', segments)
needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic)
require(interpreters == (['/lib/ld-crabc-x86_64.so.1'] if family == 'dynamic' else []),
        'interpreter boundary')
require(needed == (['libc.so'] if family == 'dynamic' else []),
        'owned runtime dependencies')
require('(TEXTREL)' not in dynamic, 'text relocations')
symbols = Path(str(candidate) + '.symbols').read_text()
for name in ('closelog', 'openlog', 'setlogmask', 'syslog', 'vsyslog'):
    require(re.search(r'\b' + name + r'$', symbols, re.M), 'linked provider ' + name)
# A static consumer incorporates the weak definition. A dynamic consumer
# correctly retains an undefined import, so inspect its installed libc
# provider rather than incorrectly requiring the executable to define it.
provider_symbols = Path(provider_symbols_text).read_text()
require(re.search(r'\bWEAK\s+\w+\s+\w+\s+vsyslog$', provider_symbols, re.M),
        'weak vsyslog alias')
PY
}

link_product() {
    local family="$1" product="$2" mode="$3"
    local driver entry label candidate receipt execution_root

    if [ "$family" = static ]; then
        driver="$product/bin/crabc-cc"
        entry="-$mode"
        label="static-$mode"
    else
        driver="$product/bin/crabc-cc-dynamic"
        entry="--dynamic-$mode"
        label="dynamic-$mode"
    fi
    candidate="$work/$label-consumer"
    "$driver" "$entry" -std=c11 -fno-builtin -fno-stack-protector \
        -c "$probe" -o "$candidate.o"
    if [ "$family" = static ]; then
        receipt="$candidate.receipt.json"
        (cd "$work" && "$driver" "$entry" --link-receipt "$(basename "$receipt")" \
            "$candidate.o" -o "$candidate")
    else
        receipt="$candidate.crabc-link.json"
        (cd "$work" && "$driver" "$entry" "$candidate.o" -o "$candidate")
    fi
    if [ "$family" = static ]; then
        audit_consumer "$family" "$mode" "$candidate" "$receipt" "$candidate"
    else
        audit_consumer "$family" "$mode" "$candidate" "$receipt" "$product/usr/lib/libc.so"
    fi
    execution_root="$work/$label-root"
    cp -a "$product" "$execution_root"
    prepare_execution_root "$execution_root"
    cp "$candidate" "$execution_root/consumer"
    run_scenarios "$execution_root" /consumer "$label"
    if [ "$family" = dynamic ]; then
        run_scenarios "$execution_root" /consumer "$label" direct
    fi
    printf 'owned syslog %s: PASS\n' "$label"
}

provided_dynamic="${1:-}"
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    link_product static "$work/static-product" static
    link_product static "$work/static-product" static-pie
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
provided_dynamic="$(realpath -e "$provided_dynamic")"
link_product dynamic "$provided_dynamic" pie
link_product dynamic "$provided_dynamic" non-pie

printf 'owned syslog: PASS (pinned musl, private AF_UNIX /dev/log and console, static/static-PIE/dynamic-PIE/non-PIE, main/worker/fork/deferred-cancellation); evidence: %s\n' "$work"
