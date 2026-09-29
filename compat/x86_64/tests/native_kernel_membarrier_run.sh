#!/usr/bin/env bash
# Link one C object through musl and both owned allocator backends, then keep
# the raw kernel registration timeline from every static and dynamic entry.
set -euo pipefail
ulimit -c 0

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly source="$root/compat/x86_64/tests/native_kernel_membarrier_probe.c"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc

if [ "$#" -ne 5 ]; then
    printf 'usage: %s WORK ACCEPTED_STATIC ACCEPTED_DYNAMIC NATIVE_STATIC NATIVE_DYNAMIC\n' "$0" >&2
    exit 2
fi
readonly work="$(realpath -m "$1")"
readonly accepted_static="$(realpath -e "$2")"
readonly accepted_dynamic="$(realpath -e "$3")"
readonly native_static="$(realpath -e "$4")"
readonly native_dynamic="$(realpath -e "$5")"

python3 -B - "$root" "$work" "$accepted_static" "$accepted_dynamic" "$native_static" "$native_dynamic" <<'PY'
from pathlib import Path
import subprocess
import sys

root, work, *products = map(Path, sys.argv[1:])
if not work.is_relative_to(root / '.work') or work.exists() or work.is_symlink():
    raise SystemExit('membarrier probe WORK must be a fresh checkout .work directory')
if any(not path.is_dir() or not path.is_relative_to(root / '.work') for path in products):
    raise SystemExit('membarrier probe products must be physical checkout .work directories')
if subprocess.run(['git', 'status', '--porcelain'], cwd=root, capture_output=True, check=True).stdout:
    raise SystemExit('membarrier probe requires clean tracked source')
PY
mkdir "$work"

source_identity() {
    python3 -B - "$root" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_static_products import source_identity
print(json.dumps(source_identity(root), sort_keys=True))
PY
}
source_identity >"$work/source-before.json"
for pair in accepted native; do
    static_variable="${pair}_static"
    dynamic_variable="${pair}_dynamic"
    static_product="${!static_variable}"
    dynamic_product="${!dynamic_variable}"
    sha256sum "$static_product/share/crabc/manifest.json" >"$work/$pair-static-manifest.before.sha256"
    sha256sum "$dynamic_product/share/crabc/manifest.json" >"$work/$pair-dynamic-manifest.before.sha256"
done

# The installed driver selects the project headers for this one object.
"$accepted_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -fno-stack-protector -c "$source" -o "$work/probe.o"
sha256sum "$source" "$work/probe.o" >"$work/object.sha256"
"$oracle_cc" -static -fno-pie -no-pie "$work/probe.o" -o "$work/oracle"

audit_link() {
    local product="$1" candidate="$2" receipt="$3" linkage="$4" output="$5"
    python3 -B - "$root" "$product" "$work/probe.o" "$candidate" "$receipt" "$linkage" "$output" <<'PY'
import json
from pathlib import Path
import sys
root, product, workload, candidate, receipt = map(Path, sys.argv[1:6])
linkage, output = sys.argv[6], Path(sys.argv[7])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import validate_link
record = validate_link(product, workload, candidate, receipt, linkage)
with output.open('x', encoding='utf-8') as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write('\n')
PY
}

run_case() {
    local name="$1" execution_root="$2" entry="$3" status
    shift 3
    if timeout 30 strace -f -e trace=membarrier -o "$work/$name.strace" \
        chroot "$execution_root" "$entry" "$@" >"$work/$name.stdout" 2>"$work/$name.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"$work/$name.status"
}

mkdir "$work/oracle-root"
cp "$work/oracle" "$work/oracle-root/consumer"
run_case oracle "$work/oracle-root" /consumer

for pair in accepted native; do
    static_variable="${pair}_static"
    dynamic_variable="${pair}_dynamic"
    static_product="${!static_variable}"
    dynamic_product="${!dynamic_variable}"
    for mode in static static-pie; do
        candidate="$work/$pair-$mode"
        receipt="$candidate.receipt.json"
        (cd "$work" && "$static_product/bin/crabc-cc" "-$mode" \
            --link-receipt "$(basename "$receipt")" "$work/probe.o" -o "$candidate")
        audit_link "$static_product" "$candidate" "$receipt" "$mode" \
            "$work/$pair-$mode-link.json"
        execution_root="$work/$pair-$mode-root"
        mkdir "$execution_root"
        cp "$candidate" "$execution_root/consumer"
        run_case "$pair-$mode" "$execution_root" /consumer
    done
    execution_root="$work/$pair-dynamic-root"
    cp -al "$dynamic_product" "$execution_root"
    for mode in pie non-pie; do
        candidate="$work/$pair-dynamic-$mode"
        "$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" \
            "$work/probe.o" -o "$candidate"
        audit_link "$dynamic_product" "$candidate" "$candidate.crabc-link.json" "$mode" \
            "$work/$pair-dynamic-$mode-link.json"
        cp "$candidate" "$execution_root/consumer-$mode"
        run_case "$pair-dynamic-$mode-kernel" "$execution_root" "/consumer-$mode"
        run_case "$pair-dynamic-$mode-direct" "$execution_root" \
            /lib/ld-crabc-x86_64.so.1 "/consumer-$mode"
    done
done

source_identity >"$work/source-after.json"
cmp "$work/source-before.json" "$work/source-after.json"
sha256sum -c "$work/object.sha256" >"$work/object-verify.log"
for pair in accepted native; do
    static_variable="${pair}_static"
    dynamic_variable="${pair}_dynamic"
    sha256sum -c "$work/$pair-static-manifest.before.sha256" \
        >"$work/$pair-static-manifest.verify.log"
    sha256sum -c "$work/$pair-dynamic-manifest.before.sha256" \
        >"$work/$pair-dynamic-manifest.verify.log"
done

# Preserve every execution before returning the expected red regression.
python3 -B - "$work" <<'PY'
from pathlib import Path
import re
import sys

work = Path(sys.argv[1])
names = ('oracle',) + tuple(
    f'{backend}-{mode}'
    for backend in ('accepted', 'native')
    for mode in ('static', 'static-pie', 'dynamic-pie-kernel', 'dynamic-pie-direct',
                 'dynamic-non-pie-kernel', 'dynamic-non-pie-direct')
)
pattern = re.compile(r'stage=(\S+) command=(\d+) raw=(-?\d+) errno_before=(\d+) errno_after=(\d+)')
failed = False
for name in names:
    status = int((work / f'{name}.status').read_text().strip())
    stream = (work / f'{name}.stdout').read_text()
    preinit_seen = re.search(r'^preinit_seen=(\d+)$', stream, re.MULTILINE)
    preinit_seen = int(preinit_seen.group(1)) if preinit_seen else -1
    rows = {(stage, int(command)): (int(raw), int(before), int(after))
            for stage, command, raw, before, after in pattern.findall(stream)}
    expected = ('main-before-malloc', 'main-after-malloc',
                'child-before-register', 'child-after-register')
    if preinit_seen:
        expected = ('preinit',) + expected
    if (status != 0 or preinit_seen != (0 if name == 'oracle' else 1)
            or len(rows) != 9 + 2 * preinit_seen or any((stage, command) not in rows
            for stage in expected for command in (0, 8)) or ('child-register', 16) not in rows):
        print(f'{name}: invalid probe execution status={status} '
              f'preinit_seen={preinit_seen} rows={len(rows)}')
        failed = True
        continue
    if any(before != 7 or after != 7 for _, before, after in rows.values()):
        print(f'{name}: raw syscall changed errno')
        failed = True
    before = rows[('main-before-malloc', 8)][0]
    after = rows[('main-after-malloc', 8)][0]
    child = rows[('child-before-register', 8)][0]
    registered = rows[('child-after-register', 8)][0]
    calls = [line for line in (work / f'{name}.strace').read_text().splitlines()
             if 'membarrier(' in line]
    first_query = next((i for i, line in enumerate(calls)
                        if 'MEMBARRIER_CMD_QUERY' in line), -1)
    first_registration = next((i for i, line in enumerate(calls)
                               if 'MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,' in line), -1)
    registration_before_probe = 0 <= first_registration < first_query
    if first_query < 0 or first_registration < 0 or registration_before_probe != name.startswith('native-'):
        print(f'{name}: unexpected kernel registration order query={first_query} '
              f'register={first_registration}')
        failed = True
    preinit = rows[('preinit', 8)][0] if preinit_seen else 'absent'
    print(f'{name}: preinit={preinit} main-before={before} '
          f'main-after={after} child-before={child} child-after-register={registered} '
          f'register-before-first-query={registration_before_probe}')
    if registered != 0:
        failed = True
    if child != -1:
        print(f'{name}: RED unregistered-child assumption; expected raw -EPERM (-1), got {child}')
        failed = True
raise SystemExit(1 if failed else 0)
PY
