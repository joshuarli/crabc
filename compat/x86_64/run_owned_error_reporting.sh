#!/usr/bin/env bash
# Pinned-musl differential for owned perror and the legacy err(3) family.
#
# The three probe roles are compiled once with the project headers and then
# linked unchanged by musl and the installed crabc drivers.  Static musl also
# proves the original independent err.o/perror.o archive replacement behavior.
# The installed one-CGU static archive retains strong providers, so its normal
# static/static-PIE delivery is qualified separately. Dynamic providers prove
# ordinary consumer lookup and the source oracle's libc-local internal edges.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_error_reporting_probe.c"
readonly crabc_interpreter=/lib/ld-crabc-x86_64.so.1
readonly musl_interpreter=/lib/ld-musl-x86_64.so.1

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
    raise SystemExit('owned error-reporting TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned error-reporting product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-error-reporting.XXXXXX")"
chmod a+rx "$work"
printf 'owned error-reporting evidence: %s\n' "$work"
trap 'printf "owned error-reporting failed near %s; evidence: %s\\n" "${step:-setup}" "$work" >&2' ERR

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
"$oracle_cc" -std=c11 -D_GNU_SOURCE -DCRABC_ERROR_REPORTING_INTERPOSE_STRERROR \
    -I"$ROOT/include" -E -H "$probe" \
    >/dev/null 2>"$work/probe.headers"
for header in errno.h err.h pthread.h stdarg.h stdio.h stdlib.h string.h sys/wait.h unistd.h wchar.h; do
    grep -Fq "$ROOT/include/$header" "$work/probe.headers"
done

compile_probe() {
    local name="$1" definition="${2:-}"
    local -a definition_arguments=()
    [ -z "$definition" ] || definition_arguments=("$definition")
    step="compile-$name"
    "$oracle_cc" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector -fPIC \
        -I"$ROOT/include" "${definition_arguments[@]}" -c "$probe" -o "$work/$name.o"
    readelf -hW "$work/$name.o" >"$work/$name.object-header"
}

compile_probe base
compile_probe strerror-static -DCRABC_ERROR_REPORTING_INTERPOSE_STRERROR
compile_probe perror-static -DCRABC_ERROR_REPORTING_INTERPOSE_PERROR
compile_probe strerror-provider -DCRABC_ERROR_REPORTING_INTERPOSE_STRERROR_PROVIDER
compile_probe strerror-consumer -DCRABC_ERROR_REPORTING_INTERPOSE_STRERROR_CONSUMER
compile_probe perror-provider -DCRABC_ERROR_REPORTING_INTERPOSE_PERROR_PROVIDER
compile_probe perror-consumer -DCRABC_ERROR_REPORTING_INTERPOSE_PERROR_CONSUMER

prepare_static_root() {
    mkdir -p "$1"
}

prepare_musl_root() {
    local root="$1"
    mkdir -p "$root/lib" "$root/usr/lib"
    cp /opt/musl-1.2.6/lib/libc.so "$root$musl_interpreter"
    cp /opt/musl-1.2.6/lib/libc.so "$root/usr/lib/libc.so"
}

run_program() {
    local root="$1" consumer="$2" label="$3" entry="$4" interpreter="$5" scenario="$6"
    local -a command=("$consumer" "$scenario")

    [ "$entry" != direct ] || command=("$interpreter" "$consumer" "$scenario")
    step="run-$label-$entry-$scenario"
    timeout 40 env -i PATH="$PATH" TZ=UTC chroot "$root" "${command[@]}" \
        >"$work/$label-$entry-$scenario.stdout" \
        2>"$work/$label-$entry-$scenario.stderr"
}

run_base() {
    local root="$1" consumer="$2" label="$3" entry="$4" interpreter="$5"
    local scenario
    for scenario in main worker; do
        run_program "$root" "$consumer" "$label" "$entry" "$interpreter" "$scenario"
        grep -qx "owned-error-reporting-$scenario-ok" \
            "$work/$label-$entry-$scenario.stdout"
    done
}

compare_base() {
    local candidate="$1" oracle="$2" entry="$3"
    local scenario
    for scenario in main worker; do
        cmp "$work/$oracle-kernel-$scenario.stdout" "$work/$candidate-$entry-$scenario.stdout"
        cmp "$work/$oracle-kernel-$scenario.stderr" "$work/$candidate-$entry-$scenario.stderr"
    done
}

run_interpose() {
    local root="$1" consumer="$2" label="$3" entry="$4" interpreter="$5" kind="$6"
    run_program "$root" "$consumer" "$label" "$entry" "$interpreter" interpose
    grep -qx "owned-error-reporting-interpose-$kind-ok" \
        "$work/$label-$entry-interpose.stdout"
}

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
        raise SystemExit('owned error-reporting artifact: ' + message)

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
provider_symbols = Path(provider_symbols_text).read_text()
for name in ('perror', 'err', 'errx', 'verr', 'verrx', 'warn', 'warnx', 'vwarn', 'vwarnx'):
    require(re.search(r'\bFUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+' + name + r'$', provider_symbols, re.M),
            'strong selected provider ' + name)
PY
}

audit_interposition_graph() {
    local consumer="$1" provider="$2" kind="$3"
    readelf -dW "$consumer" >"$consumer.dynamic"
    python3 -B - "$consumer.dynamic" "$(basename "$provider")" "$kind" <<'PY'
import re
import sys
from pathlib import Path

text, provider, kind = sys.argv[1:]
needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', Path(text).read_text())
if provider not in needed or 'libc.so' not in needed:
    raise SystemExit('owned error-reporting interposition graph lacks provider or libc')
if needed.index(provider) > needed.index('libc.so'):
    raise SystemExit('owned error-reporting interposition provider is after libc')
if kind not in {'strerror', 'perror'}:
    raise SystemExit('owned error-reporting interposition kind drifted')
PY
}

link_oracle_static() {
    local label="$1" object="$2"
    local root="$work/$label-root"
    prepare_static_root "$root"
    step="link-$label"
    "$oracle_cc" -static -fno-pie -no-pie -pthread "$object" -o "$root/consumer"
}

# The normal same object establishes musl's byte/status/concurrency baseline.
link_oracle_static oracle-static "$work/base.o"
run_base "$work/oracle-static-root" /consumer oracle-static kernel ''
printf 'owned error-reporting pinned-musl static normal: PASS\n'

# Musl's independent err.o/perror.o objects retain strong application-provider
# replacement at final static link. This source oracle is intentionally kept
# distinct from the installed one-CGU static archive's strong-provider scope.
for kind in strerror perror; do
    link_oracle_static "oracle-static-interpose-$kind" "$work/$kind-static.o"
    run_interpose "$work/oracle-static-interpose-$kind-root" /consumer \
        "oracle-static-interpose-$kind" kernel '' "$kind"
done
printf 'owned error-reporting pinned-musl static interposition: PASS\n'

link_oracle_dynamic_base() {
    local mode="$1" root="$work/oracle-dynamic-$mode-root"
    local -a flags=(-fPIE -pie)
    [ "$mode" = pie ] || flags=(-fno-pie -no-pie)
    prepare_musl_root "$root"
    step="link-oracle-dynamic-$mode"
    "$oracle_cc" "${flags[@]}" -pthread "$work/base.o" \
        -Wl,--dynamic-linker,"$musl_interpreter",-rpath,/usr/lib \
        -o "$root/consumer"
    run_base "$root" /consumer "oracle-dynamic-$mode" kernel "$musl_interpreter"
    run_base "$root" /consumer "oracle-dynamic-$mode" direct "$musl_interpreter"
}

link_oracle_dynamic_interpose() {
    local mode="$1" kind="$2" root="$work/oracle-dynamic-$mode-interpose-$kind-root"
    local provider="$root/usr/lib/liberror-reporting-$kind.so"
    local -a flags=(-fPIE -pie)
    [ "$mode" = pie ] || flags=(-fno-pie -no-pie)
    prepare_musl_root "$root"
    step="link-oracle-provider-$mode-$kind"
    "$oracle_cc" -shared -fPIC "$work/$kind-provider.o" \
        -Wl,-soname,"$(basename "$provider")" -o "$provider"
    step="link-oracle-interpose-$mode-$kind"
    "$oracle_cc" "${flags[@]}" -pthread "$work/$kind-consumer.o" \
        -Wl,--dynamic-linker,"$musl_interpreter",-rpath,/usr/lib,--no-as-needed \
        "$provider" -o "$root/consumer"
    audit_interposition_graph "$root/consumer" "$provider" "$kind"
    run_interpose "$root" /consumer "oracle-dynamic-$mode-interpose-$kind" kernel "$musl_interpreter" "$kind"
    run_interpose "$root" /consumer "oracle-dynamic-$mode-interpose-$kind" direct "$musl_interpreter" "$kind"
}

for mode in pie non-pie; do
    link_oracle_dynamic_base "$mode"
    for kind in strerror perror; do
        link_oracle_dynamic_interpose "$mode" "$kind"
    done
done
printf 'owned error-reporting pinned-musl dynamic base/interposition: PASS\n'

link_static_candidate() {
    local product="$1" mode="$2"
    local label candidate receipt
    label="static-$mode"
    candidate="$work/$label-consumer"
    receipt="$candidate.receipt.json"
    step="link-$label"
    (
        cd "$work"
        "$product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
            "$work/base.o" -o "$candidate"
    )
    audit_consumer static "$mode" "$candidate" "$receipt" "$candidate"
    prepare_static_root "$work/$label-root"
    cp "$candidate" "$work/$label-root/consumer"
    run_base "$work/$label-root" /consumer "$label" kernel ''
    compare_base "$label" oracle-static kernel
    printf 'owned error-reporting %s: PASS\n' "$label"
}

link_dynamic_candidate_base() {
    local product="$1" mode="$2"
    local label candidate receipt
    label="dynamic-$mode"
    candidate="$work/$label-consumer"
    receipt="$candidate.crabc-link.json"
    step="link-$label"
    "$product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/base.o" -o "$candidate"
    audit_consumer dynamic "$mode" "$candidate" "$receipt" "$product/usr/lib/libc.so"
    cp -a "$product" "$work/$label-root"
    cp "$candidate" "$work/$label-root/consumer"
    run_base "$work/$label-root" /consumer "$label" kernel "$crabc_interpreter"
    run_base "$work/$label-root" /consumer "$label" direct "$crabc_interpreter"
    compare_base "$label" "oracle-dynamic-$mode" kernel
    compare_base "$label" "oracle-dynamic-$mode" direct
    printf 'owned error-reporting %s: PASS\n' "$label"
}

link_dynamic_candidate_interpose() {
    local product="$1" mode="$2" kind="$3"
    local label="dynamic-$mode-interpose-$kind"
    local root="$work/$label-root"
    local provider="$root/usr/lib/liberror-reporting-$kind.so"
    local consumer="$work/$label-consumer"
    cp -a "$product" "$root"
    step="link-provider-$label"
    "$product/bin/crabc-cc-dynamic" --dynamic-shared-object "$work/$kind-provider.o" -o "$provider"
    step="link-$label"
    "$product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/$kind-consumer.o" \
        --application-dso "$provider" -o "$consumer"
    audit_interposition_graph "$consumer" "$provider" "$kind"
    cp "$consumer" "$root/consumer"
    run_interpose "$root" /consumer "$label" kernel "$crabc_interpreter" "$kind"
    run_interpose "$root" /consumer "$label" direct "$crabc_interpreter" "$kind"
    cmp "$work/oracle-dynamic-$mode-interpose-$kind-kernel-interpose.stdout" \
        "$work/$label-kernel-interpose.stdout"
    cmp "$work/oracle-dynamic-$mode-interpose-$kind-kernel-interpose.stderr" \
        "$work/$label-kernel-interpose.stderr"
    cmp "$work/oracle-dynamic-$mode-interpose-$kind-direct-interpose.stdout" \
        "$work/$label-direct-interpose.stdout"
    cmp "$work/oracle-dynamic-$mode-interpose-$kind-direct-interpose.stderr" \
        "$work/$label-direct-interpose.stderr"
    printf 'owned error-reporting %s: PASS\n' "$label"
}

provided_dynamic="${1:-}"
if [ -z "$provided_dynamic" ]; then
    step=build-static-product
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    link_static_candidate "$work/static-product" static
    link_static_candidate "$work/static-product" static-pie
    provided_dynamic="$work/dynamic-product"
    step=build-dynamic-product
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
provided_dynamic="$(realpath -e "$provided_dynamic")"

# Record the library relocation table beside the live DSO-preemption evidence.
readelf -rW "$provided_dynamic/usr/lib/libc.so" >"$work/installed-libc.relocations"
for mode in pie non-pie; do
    link_dynamic_candidate_base "$provided_dynamic" "$mode"
    for kind in strerror perror; do
        link_dynamic_candidate_interpose "$provided_dynamic" "$mode" "$kind"
    done
done

printf 'owned error-reporting: PASS (pinned musl static replacement source oracle; same-object static/static-PIE and dynamic PIE/non-PIE delivery; kernel/direct dynamic entry; source-permitted concurrent fragments, stderr orientation, errno text, ordinary exit, worker, and shared DSO public/local-edge resolution); evidence: %s\n' "$work"
