#!/usr/bin/env bash
# Actual installed dynamic cancellation composition, separate from static proof.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly witness="$ROOT/compat/x86_64/run_pthread_wait_witness.py"
readonly interpreter=/lib/ld-crabc-x86_64.so.1
source "$ROOT/compat/x86_64/owned_io_cancellation_fixtures.sh"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
[ "$(uname -sm)" = 'Linux x86_64' ]
python3 -B - "$ROOT" "${TMPDIR:-}" "${1:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('dynamic cancellation TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('dynamic cancellation product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-dynamic-io-cancellation.XXXXXX")"
printf 'owned dynamic I/O cancellation evidence: %s\n' "$work"
installed="${1:-}"
if [ -z "$installed" ]; then
    installed="$work/installed"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$installed" >"$work/build.json"
fi
installed="$(realpath -e "$installed")"
readonly installed
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly execution_root="$work/execution-root"
cp -a "$installed" "$execution_root"
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
    "$oracle_cc" -std=c11 -I"$ROOT/include" -E -H "$source_file" \
        >/dev/null 2>"$work/$probe.headers"
    mapfile -t headers < <(owned_io_cancellation_headers "$probe")
    for header in "${headers[@]}"; do grep -Fq "$ROOT/include/$header" "$work/$probe.headers"; done
    "$oracle_cc" -std=c11 -pthread -fno-builtin -fno-stack-protector \
        -I"$ROOT/include" "$source_file" -o "$work/$probe-oracle"
    mapfile -t oracle_arguments < <(owned_io_cancellation_arguments "$probe" "$work/$probe-oracle-files")
    timeout 30 env -i PATH="$PATH" python3 -B "$witness" '' "$work/$probe-oracle" \
        "${oracle_arguments[@]}" >"$work/$probe-oracle.stdout"
    grep -qx "${probe//_/-}-ok" "$work/$probe-oracle.stdout"
    for mode in pie non-pie; do
        candidate="$work/$probe-$mode"
        "$driver" "--dynamic-$mode" -std=c11 -fno-builtin -fno-stack-protector \
            -c "$source_file" -o "$candidate.o"
        "$driver" "--dynamic-$mode" "$candidate.o" -o "$candidate"
        audit_dynamic_consumer "$mode" "$candidate"
        cp "$candidate" "$execution_root/consumer"
        for entry in kernel interpreter; do
            entry_arguments=(/consumer)
            if [ "$entry" = interpreter ]; then entry_arguments=("$interpreter" /consumer); fi
            mapfile -t candidate_arguments < <(owned_io_cancellation_arguments "$probe" "/$probe-$mode-$entry-files")
            timeout 30 env -i PATH="$PATH" python3 -B "$witness" "$execution_root" \
                "${entry_arguments[@]}" "${candidate_arguments[@]}" >"$candidate-$entry.stdout"
            grep -qx "${probe//_/-}-ok" "$candidate-$entry.stdout"
            cmp "$work/$probe-oracle.stdout" "$candidate-$entry.stdout"
        done
    done
    printf 'dynamic cancellation %s: PASS (PIE/non-PIE, kernel/direct interpreter)\n' "$probe"
done
printf 'owned dynamic I/O cancellation: PASS (pinned musl + sealed PIE/non-PIE, kernel/direct interpreter, blocked syscall witnesses, main/worker cancellation and fork); evidence: %s\n' "$work"
