#!/usr/bin/env bash
# Whole installed cancellation roster, with optional supplied-static replay.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly witness="$ROOT/compat/x86_64/run_pthread_wait_witness.py"
readonly interpreter=/lib/ld-crabc-x86_64.so.1
readonly evidence="$ROOT/compat/x86_64/owned_io_cancellation_evidence.py"
source "$ROOT/compat/x86_64/owned_io_cancellation_fixtures.sh"
usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
provided_static=''
provided_dynamic=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] || usage
            [ -z "$provided_static" ] || usage
            [ -n "$2" ] && [[ "$2" != -* ]] || usage
            provided_static="$2"
            shift 2
            ;;
        -*)
            usage
            ;;
        *)
            [ -z "$provided_dynamic" ] && [ -n "$1" ] || usage
            provided_dynamic="$1"
            shift
            ;;
    esac
done
[ "$(uname -sm)" = 'Linux x86_64' ]
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" "$provided_static" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('dynamic cancellation TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('dynamic cancellation product must be a checkout .work directory')
if sys.argv[4]:
    product = Path(sys.argv[4]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('static cancellation product must be a checkout .work directory')
    sys.path.insert(0, str(root / 'compat/x86_64'))
    from owned_static_sysroot_package import source_entries, validate_installed_tree
    validate_installed_tree(product, source_entries(product))
PY
if [ -n "$provided_static" ]; then
    provided_static="$(realpath "$provided_static")"
fi
readonly work="$(mktemp -d "$TMPDIR/owned-dynamic-io-cancellation.XXXXXX")"
chmod a+rx "$work"
printf 'owned dynamic I/O cancellation evidence: %s\n' "$work"
installed="$provided_dynamic"
if [ -z "$installed" ]; then
    installed="$work/installed"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$installed" >"$work/build.json"
fi
installed="$(realpath "$installed")"
readonly installed
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly execution_root="$work/execution-root"
cp -a "$installed" "$execution_root"
if [ -n "$provided_static" ]; then mkdir "$work/static-execution-root"; fi
# A descriptor opened read-only before chroot supplies /proc observations.
# This private root contains only the owned product, consumers, and scratch;
# no host loader, libc, shell, or executable search directory is mounted.
for runtime in lib/ld-crabc-x86_64.so.1 usr/lib/libc.so; do
    cmp "$installed/$runtime" "$execution_root/$runtime"
    readelf -dW "$installed/$runtime" >"$work/$(basename "$runtime").dynamic"
    if grep -Eq '\(NEEDED\)|\(TEXTREL\)' "$work/$(basename "$runtime").dynamic"; then
        printf 'dynamic cancellation runtime has an unowned dependency or text relocation\n' >&2
        exit 1
    fi
done

run_fixture() {
    local root="$1" output="$2" status=0
    shift 2
    local -a command=(timeout 30 env -i "PATH=$PATH" python3 -B "$witness" "$root" "$@")
    python3 -B - "${output%.stdout}.command.json" "${command[@]}" <<'PY_COMMAND'
import json
import os
from pathlib import Path
import sys
with Path(sys.argv[1]).open('x') as output:
    json.dump({'cwd': os.getcwd(), 'command': sys.argv[2:]}, output, sort_keys=True, separators=(',', ':'))
    output.write('\n')
PY_COMMAND
    "${command[@]}" >"$output" 2>"${output%.stdout}.stderr" || status=$?
    printf '%s\n' "$status" >"${output%.stdout}.status"
    return "$status"
}

compare_oracle() {
    local candidate="$1" suffix
    for suffix in stdout stderr status; do
        cmp "$work/$probe-oracle.$suffix" "$candidate.$suffix"
    done
}

audit_dynamic_consumer() {
    local mode="$1" candidate="$2"
    readelf -hW "$candidate" >"$candidate.header"
    readelf -lW "$candidate" >"$candidate.segments"
    readelf -dW "$candidate" >"$candidate.dynamic"
    readelf --dyn-syms -W "$candidate" >"$candidate.symbols"
    python3 -B - "$installed" "$mode" "$candidate" "$interpreter" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path
root, mode, candidate_text, interpreter = sys.argv[1:]
root, candidate = Path(root), Path(candidate_text)
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def require(condition, message):
    if not condition:
        raise SystemExit('dynamic cancellation audit: ' + message)
receipt = json.loads(Path(str(candidate) + '.crabc-link.json').read_text())
require(receipt.get('schema') == 1 and receipt.get('format') == 'crabc-x86-64-owned-dynamic-sysroot-v1', 'receipt format')
require(receipt.get('mode') == ('pie' if mode == 'pie' else 'exec') and receipt.get('binding') == 'now', 'entry or binding mode')
require(receipt.get('runtime_imports') == [] and receipt.get('application_dsos') == {}, 'unexpected application dependency')
require(receipt.get('output_path') == str(candidate.resolve()) and receipt.get('output_sha256') == digest(candidate), 'consumer identity')
require(receipt.get('manifest_sha256') == digest(root / 'share/crabc/manifest.json'), 'product identity')
entry = 'Scrt1.o' if mode == 'pie' else 'crt1.o'
expected = sorted('usr/lib/' + name for name in (entry, 'crabc-dynamic-attach.o', 'crti.o', 'libc.so', 'libcrabc-builtins.a', 'crtn.o'))
require(receipt.get('owned_runtime_inputs') == expected, 'runtime input roster')
for record in receipt['input_receipts']:
    require(record['sha256'] == digest(Path(record['path'])), 'link input identity')
header = Path(str(candidate) + '.header').read_text()
require('Advanced Micro Devices X86-64' in header, 'machine')
require(re.search(r'Type:\s+' + ('DYN' if mode == 'pie' else 'EXEC') + r'\s', header), 'ELF type')
segments = Path(str(candidate) + '.segments').read_text()
require(re.findall(r'Requesting program interpreter: ([^\]]+)\]', segments) == [interpreter], 'owned interpreter')
dynamic = Path(str(candidate) + '.dynamic').read_text()
require(re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic) == ['libc.so'], 'owned libc dependency')
require('(TEXTREL)' not in dynamic, 'text relocations')
PY
}

for probe in "${OWNED_IO_CANCELLATION_PROBES[@]}"; do
    source_file="$ROOT/compat/x86_64/${probe}_probe.c"
    object="$work/$probe.o"
    # One PIE object supports every ordinary static and dynamic linkage.
    # The installed driver owns headers/code generation; the separate audit
    # repeats dependency-only preprocessing and permits exactly one local
    # witness header, never the checkout's public include tree.
    "$driver" --dynamic-pie -std=c11 -fno-builtin -fno-stack-protector \
        -c "$source_file" -o "$object"
    mapfile -t headers < <(owned_io_cancellation_headers "$probe")
    python3 -B "$evidence" record-compile "$installed" "$source_file" "$object" \
        "$work/$probe.compile.json" "${headers[@]}"
    "$oracle_cc" -pthread "$object" -o "$work/$probe-oracle"
    mapfile -t oracle_arguments < <(owned_io_cancellation_arguments "$probe" "$work/$probe-oracle-files")
    run_fixture '' "$work/$probe-oracle.stdout" "$work/$probe-oracle" "${oracle_arguments[@]}"
    grep -qx "${probe//_/-}-ok" "$work/$probe-oracle.stdout"
    if [ -n "$provided_static" ]; then
        for mode in static static-pie; do
            candidate="$work/$probe-$mode"
            receipt="$candidate.receipt.json"
            (
                cd "$work"
                "$provided_static/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
                    "$object" -o "$candidate"
            )
            python3 -B "$evidence" record-link "$provided_static" "$object" "$candidate" "$receipt" \
                "$mode" "$candidate.link-identity.json"
            cp "$candidate" "$work/static-execution-root/consumer"
            mapfile -t candidate_arguments < <(owned_io_cancellation_arguments "$probe" "/$probe-$mode-files")
            run_fixture "$work/static-execution-root" "$candidate.stdout" /consumer "${candidate_arguments[@]}"
            compare_oracle "$candidate"
        done
    fi
    for mode in pie non-pie; do
        candidate="$work/$probe-$mode"
        "$driver" "--dynamic-$mode" "$object" -o "$candidate"
        python3 -B "$evidence" record-link "$installed" "$object" "$candidate" "$candidate.crabc-link.json" \
            "$mode" "$candidate.link-identity.json"
        audit_dynamic_consumer "$mode" "$candidate"
        cp "$candidate" "$execution_root/consumer"
        for entry in kernel interpreter; do
            entry_arguments=(/consumer)
            if [ "$entry" = interpreter ]; then entry_arguments=("$interpreter" /consumer); fi
            mapfile -t candidate_arguments < <(owned_io_cancellation_arguments "$probe" "/$probe-$mode-$entry-files")
            run_fixture "$execution_root" "$candidate-$entry.stdout" "${entry_arguments[@]}" "${candidate_arguments[@]}"
            grep -qx "${probe//_/-}-ok" "$candidate-$entry.stdout"
            compare_oracle "$candidate-$entry"
        done
    done
    python3 -B "$evidence" verify-compile "$installed" "$source_file" "$object" \
        "$work/$probe.compile.json" "${headers[@]}"
    printf 'dynamic cancellation %s: PASS (one installed-header object; optional supplied static/static-PIE; PIE/non-PIE, kernel/direct interpreter)\n' "$probe"
done
printf 'owned dynamic I/O cancellation: PASS (whole ten-fixture roster; same objects for pinned musl, optional supplied static/static-PIE, sealed PIE/non-PIE kernel/direct interpreter; raw status/stdout/stderr, blocked syscall witnesses, main/worker cancellation and fork); evidence: %s\n' "$work"
