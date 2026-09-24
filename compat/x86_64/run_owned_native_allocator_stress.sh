#!/usr/bin/env bash
# Installed native-shadow allocator stress and seeded soak (development runs).
#
# Stress: the unmodified pinned mimalloc v3.5.0 `test/test-stress.c` archive
# member, compiled only with the upstream `USE_STD_MALLOC` binding so its
# custom allocation names select calloc/realloc/free. Its worker scheduling,
# which thread frees, owner exit and transfer timing, and the initial thread's
# final transfer cleanup stay the source's. Each case passes the source CLI
# `THREADS SCALE ITER`; SCALE > 100 enables the source's large-object mode.
# Cases run smallest first and dispatch stops at the first failure, so a
# larger failure is only reported after every smaller case passed. Every
# product run must reproduce the musl oracle's stdout exactly with empty
# stderr before its watchdog expires.
#
# Soak: `owned_native_allocator_soak_probe.c` per seed, with the audit-enabled
# products reporting process-wide PageMap/arena/metadata/TLD/Theap/abandoned
# counts at each drained checkpoint. The runner retains every transcript and
# a JSON summary. At every drained checkpoint no worker TLD, Theap, owner,
# metadata capability, or abandoned page may remain; PageMap entries and
# submaps, arenas, metadata high-water, and current RSS may not grow
# across equivalent churn beyond a tenth of their first-half maximum.
#
# Modes: the musl oracle; the pinned C mimalloc backend through the same
# owned static-PIE libc (`accepted-c`, a resident-memory reference); and the
# audit-enabled native-shadow static-PIE and dynamic PIE (kernel loader)
# products. Without supplied native products the runner builds both;
# supplied ones must record the native-shadow backend and the lifecycle test
# audit. The C-backend product is always built here.
#
# Development knobs (defaults in parentheses):
#   CRABC_NATIVE_ALLOCATOR_STRESS_CASES   "T S I,..." (see default_cases)
#   CRABC_NATIVE_ALLOCATOR_STRESS_TIMEOUT per-case watchdog seconds (300)
#   CRABC_NATIVE_ALLOCATOR_SOAK_SEEDS     space-separated (0x5eed0001 0x5eed0002 0x5eed0003)
#   CRABC_NATIVE_ALLOCATOR_SOAK_ROUNDS    rounds per seed (1200)
#   CRABC_NATIVE_ALLOCATOR_SOAK_WORKERS   concurrent owners per round (8)
#   CRABC_NATIVE_ALLOCATOR_SOAK_INTERVAL  rounds per drained checkpoint (60)
#   CRABC_NATIVE_ALLOCATOR_SOAK_WATCHDOG  seconds per soak process (900)
#   CRABC_NATIVE_ALLOCATOR_SKIP           "stress" or "soak" to run only the other
#
# Every run publishes a revision-bound receipt through
# `native_shadow_receipt.py` under `.work/x86_64/reports/native-shadow/
# owned-native-allocator-stress/latest`: the source seal, digests of every
# executed program and product provenance file, each case's exit status and
# raw logs in order, and whether every knob above held its default. The
# previous receipt is withdrawn before the first case, so a failed or
# interrupted run leaves either a failing receipt or none.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly soak_probe="$ROOT/compat/x86_64/owned_native_allocator_soak_probe.c"
readonly archive="$ROOT/.work/allocator-cache/mimalloc-3.5.0.tar.gz"
readonly modes=(oracle c-static-pie static-pie dynamic-pie)

# Workers 1, 2, 4, 8 at each setting; SCALE 101 and 150 are large-object
# mode, and the last case is the source's default 32 workers, 50%, 50 rounds.
readonly default_cases='1 1 1,2 1 1,4 1 1,8 1 1,1 10 10,2 10 10,4 10 10,8 10 10,1 50 20,2 50 20,4 50 20,8 50 20,1 50 50,2 50 50,4 50 50,8 50 50,1 101 5,2 101 5,4 101 5,8 101 5,1 150 20,2 150 20,4 150 20,8 150 20,32 50 50'
stress_cases="${CRABC_NATIVE_ALLOCATOR_STRESS_CASES:-$default_cases}"
stress_timeout="${CRABC_NATIVE_ALLOCATOR_STRESS_TIMEOUT:-300}"
soak_seeds="${CRABC_NATIVE_ALLOCATOR_SOAK_SEEDS:-0x5eed0001 0x5eed0002 0x5eed0003}"
soak_rounds="${CRABC_NATIVE_ALLOCATOR_SOAK_ROUNDS:-1200}"
soak_workers="${CRABC_NATIVE_ALLOCATOR_SOAK_WORKERS:-8}"
soak_interval="${CRABC_NATIVE_ALLOCATOR_SOAK_INTERVAL:-60}"
soak_watchdog="${CRABC_NATIVE_ALLOCATOR_SOAK_WATCHDOG:-900}"
skip="${CRABC_NATIVE_ALLOCATOR_SKIP:-}"
readonly receipt_runner=owned-native-allocator-stress
canonical=yes
for knob in STRESS_CASES STRESS_TIMEOUT SOAK_SEEDS SOAK_ROUNDS SOAK_WORKERS SOAK_INTERVAL SOAK_WATCHDOG SKIP; do
    knob="CRABC_NATIVE_ALLOCATOR_$knob"
    [ -z "${!knob+x}" ] || canonical=no
done

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

static_sysroot=''
dynamic_sysroot=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$static_sysroot" ] && [ -n "$2" ] || usage
            static_sysroot="$(realpath -e "$2")"
            shift 2
            ;;
        -*|'') usage ;;
        *)
            [ -z "$dynamic_sysroot" ] || usage
            dynamic_sysroot="$(realpath -e "$1")"
            shift
            ;;
    esac
done
case "$skip" in ''|stress|soak) ;; *) usage ;; esac

python3 -B - "$ROOT" "${TMPDIR:-}" "$static_sysroot" "$dynamic_sysroot" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('native-allocator-stress TMPDIR must be a physical checkout .work directory')
for argument in sys.argv[3:]:
    if argument and not Path(argument).is_relative_to(root / '.work'):
        raise SystemExit('native-allocator-stress products must be checkout .work directories')
PY

work="$(mktemp -d "$TMPDIR/owned-native-allocator-stress.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'native-allocator-stress evidence: %s\n' "$work"

rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
receipt_cases=()
receipt_products=()
# Publishes this run's receipt on every exit. A failure outside a case (a
# build, an oracle mismatch, or the soak growth judge) is its own case.
publish_receipt() {
    local status=$?
    trap - EXIT
    if [ "$status" -ne 0 ]; then
        printf '%s\n' "$status" >"$work/runner.status"
        receipt_cases+=("runner=$status:runner.status")
    fi
    local -a arguments=(--runner "$receipt_runner" --work "$work" --canonical "$canonical")
    local entry
    for entry in "${receipt_cases[@]}"; do arguments+=(--case "$entry"); done
    for entry in "${receipt_products[@]}"; do arguments+=(--product "$entry"); done
    for entry in STRESS_CASES="$stress_cases" STRESS_TIMEOUT="$stress_timeout" SOAK_SEEDS="$soak_seeds" \
        SOAK_ROUNDS="$soak_rounds" SOAK_WORKERS="$soak_workers" SOAK_INTERVAL="$soak_interval" \
        SOAK_WATCHDOG="$soak_watchdog" SKIP="$skip"; do
        arguments+=(--parameter "$entry")
    done
    python3 -B "$ROOT/compat/x86_64/native_shadow_receipt.py" write "${arguments[@]}" || status=1
    exit "$status"
}
trap publish_receipt EXIT

# Verify the pinned archive and extract the exact stress member and the
# public headers it includes; nothing else from the archive is compiled.
python3 -B - "$ROOT/compat/upstreams.toml" "$archive" "$work/mimalloc" <<'PY'
import hashlib
import sys
import tarfile
import tomllib
from pathlib import Path
pins, archive, output = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
with open(pins, 'rb') as stream:
    pin = tomllib.load(stream)['mimalloc']
if not archive.is_file():
    raise SystemExit(f'{archive}: missing; run scripts/lanes/prepare-worktree.sh or an allocator command first')
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
if digest != pin['sha256']:
    raise SystemExit(f'{archive}: sha256 {digest} is not the pinned {pin["sha256"]}')
root = pin['archive_root']
members = [f'{root}/test/test-stress.c', f'{root}/include/mimalloc.h', f'{root}/include/mimalloc-stats.h']
with tarfile.open(archive) as tar:
    for name in members:
        member = tar.getmember(name)
        if not member.isfile():
            raise SystemExit(f'{name}: not a regular archive member')
        target = output / Path(name).relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(tar.extractfile(member).read())
print(f'pinned mimalloc {pin["version"]} archive {digest}')
PY
readonly stress_source="$work/mimalloc/test/test-stress.c"
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend accepted-c \
    --output "$work/c-static-sysroot" >"$work/c-static-build.json"
readonly c_static_sysroot="$work/c-static-sysroot"
if [ -z "$static_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow \
        --allocator-lifecycle-test-audit --output "$work/static-sysroot" >"$work/static-build.json"
    static_sysroot="$work/static-sysroot"
fi
if [ -z "$dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow \
        --allocator-lifecycle-test-audit --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    dynamic_sysroot="$work/dynamic-sysroot"
fi
python3 -B - "$static_sysroot" "$dynamic_sysroot" <<'PY'
import json
import sys
from pathlib import Path
static, dynamic = map(Path, sys.argv[1:])
def load(path):
    with open(path, encoding='utf-8') as stream:
        return json.load(stream)
selections = (
    (load(static / 'share/crabc/manifest.json').get('allocator_backend'),
     load(static / 'share/crabc/libc-static.provenance.json').get('allocator_lifecycle_test_audit'), static),
    (load(dynamic / 'share/crabc/libc-shared.provenance.json').get('allocator_backend'),
     load(dynamic / 'share/crabc/libc-shared.provenance.json').get('allocator_lifecycle_test_audit'), dynamic),
)
for backend, audit, product in selections:
    if backend != 'native-shadow' or audit is not True:
        raise SystemExit(f'{product}: not a native-shadow product with the lifecycle test audit')
PY
receipt_products+=(
    "c-static-manifest=$c_static_sysroot/share/crabc/manifest.json"
    "static-manifest=$static_sysroot/share/crabc/manifest.json"
    "static-libc-provenance=$static_sysroot/share/crabc/libc-static.provenance.json"
    "dynamic-libc-provenance=$dynamic_sysroot/share/crabc/libc-shared.provenance.json"
)

# Builds the soak probe for every mode; product builds add the audit.
build_soak() {
    local -a flags=(-std=c11 -O2 -pthread)
    "$oracle_cc" -static -fno-pie -no-pie "${flags[@]}" "$soak_probe" -o "$work/soak-oracle"
    "$c_static_sysroot/bin/crabc-cc" -static-pie "${flags[@]}" "$soak_probe" -o "$work/soak-c-static-pie"
    "$static_sysroot/bin/crabc-cc" -static-pie -DCRABC_NATIVE_ALLOCATOR_AUDIT "${flags[@]}" \
        "$soak_probe" -o "$work/soak-static-pie"
    "$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -DCRABC_NATIVE_ALLOCATOR_AUDIT "${flags[@]}" \
        "$soak_probe" -o "$work/soak-dynamic-pie"
    cp "$work/soak-dynamic-pie" "$work/execution-root/soak-dynamic-pie"
    local mode
    for mode in "${modes[@]}"; do receipt_products+=("soak-$mode=$work/soak-$mode"); done
}

# Builds the pinned stress source for every mode. Its `<mimalloc.h>` include
# is an application header the installed drivers do not search, so each
# product object is translated exactly as that driver translates a source
# (its own `-nostdinc` header root and flags) with the pinned public header
# directory added after the product headers, then linked by the driver.
build_stress() {
    local -a flags=(-std=c11 -O2 -pthread -DUSE_STD_MALLOC)
    local -a translate=(gcc -nostdinc -ffreestanding -fno-builtin)
    "$oracle_cc" -static -fno-pie -no-pie "${flags[@]}" -I "$work/mimalloc/include" \
        "$stress_source" -o "$work/stress-oracle"
    "${translate[@]}" -isystem "$static_sysroot/usr/include" -isystem "$work/mimalloc/include" \
        -fno-stack-protector "${flags[@]}" -fPIE -c "$stress_source" -o "$work/stress-static-pie.o"
    "$static_sysroot/bin/crabc-cc" -static-pie -pthread "$work/stress-static-pie.o" -o "$work/stress-static-pie"
    "$c_static_sysroot/bin/crabc-cc" -static-pie -pthread "$work/stress-static-pie.o" -o "$work/stress-c-static-pie"
    "${translate[@]}" -isystem "$dynamic_sysroot/usr/include" -isystem "$work/mimalloc/include" \
        -fstack-protector-strong "${flags[@]}" -fPIE -c "$stress_source" -o "$work/stress-dynamic-pie.o"
    "$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -pthread "$work/stress-dynamic-pie.o" \
        -o "$work/stress-dynamic-pie"
    cp "$work/stress-dynamic-pie" "$work/execution-root/stress-dynamic-pie"
    local mode
    for mode in "${modes[@]}"; do receipt_products+=("stress-$mode=$work/stress-$mode"); done
}

# Runs one built program in one mode; retains stdout, stderr, status, and
# elapsed seconds under $work/$label.*.
run_mode() {
    local name="$1"
    local mode="$2"
    local label="$3"
    local watchdog="$4"
    shift 4
    local -a command=("$work/$name-$mode")
    [ "$mode" != dynamic-pie ] || command=(chroot "$work/execution-root" "/$name-dynamic-pie")
    local status=0
    local start end
    start=$(date +%s)
    timeout "$watchdog" "${command[@]}" "$@" >"$work/$label.stdout" 2>"$work/$label.stderr" || status=$?
    end=$(date +%s)
    printf '%s\n' "$status" >"$work/$label.status"
    printf '%s\n' "$((end - start))" >"$work/$label.seconds"
    receipt_cases+=("$label=$status:$label.stdout,$label.stderr,$label.status,$label.seconds")
    if [ "$status" -ne 0 ] || [ -s "$work/$label.stderr" ]; then
        printf 'native-allocator-stress: %s exited %s after %ss\n' "$label" "$status" "$((end - start))" >&2
        head -c 4096 "$work/$label.stderr" >&2
        return 1
    fi
}

cp -a "$dynamic_sysroot" "$work/execution-root"

if [ "$skip" != stress ]; then
    build_stress
    IFS=, read -r -a cases <<<"$stress_cases"
    for case in "${cases[@]}"; do
        read -r threads scale iterations <<<"$case"
        for mode in "${modes[@]}"; do
            label="stress-$threads-$scale-$iterations-$mode"
            run_mode stress "$mode" "$label" "$stress_timeout" "$threads" "$scale" "$iterations"
            if [ "$mode" != oracle ] && ! cmp -s "$work/stress-$threads-$scale-$iterations-oracle.stdout" \
                "$work/$label.stdout"; then
                printf 'native-allocator-stress: %s stdout differs from musl\n' "$label" >&2
                exit 1
            fi
            printf 'stress %s %s %s %s: pass (%ss)\n' "$threads" "$scale" "$iterations" "$mode" \
                "$(cat "$work/$label.seconds")"
        done
    done
fi

if [ "$skip" != soak ]; then
    build_soak
    for seed in $soak_seeds; do
        for mode in "${modes[@]}"; do
            label="soak-$seed-$mode"
            run_mode soak "$mode" "$label" "$((soak_watchdog + 60))" \
                "$seed" "$soak_rounds" "$soak_workers" "$soak_interval" "$soak_watchdog"
            printf 'soak %s %s: pass (%ss)\n' "$seed" "$mode" "$(cat "$work/$label.seconds")"
        done
    done
    python3 -B - "$work" <<'PY'
import json
import sys
from pathlib import Path
work = Path(sys.argv[1])
# At a drained checkpoint every worker has joined and every block is free.
EXACT = {'live_threads': 1, 'metadata_live': 0, 'later_theaps': 0, 'abandoned_pages': 0,
         'attached_workers': 0}
# Capacity counts that may fluctuate but must plateau across equivalent churn.
# Current RSS is -1 where the execution root mounts no /proc; the getrusage
# high-water only records the largest transient peak and is reported only.
BOUNDED = ('page_map_entries', 'page_map_submaps', 'arenas', 'metadata_high_water', 'rss_kib')
def fields(line):
    return {key: value for key, value in (item.split('=', 1) for item in line.split()[1:])}
summary, failures = {}, []
for stdout in sorted(work.glob('soak-*.stdout')):
    label = stdout.stem
    lines = stdout.read_text().splitlines()
    checkpoints = [fields(line) for line in lines if line.startswith('checkpoint ')]
    record = {
        'header': fields(lines[0]),
        'summary': fields(next(line for line in lines if line.startswith('summary '))),
        'checkpoints': checkpoints,
    }
    if len(checkpoints) < 4:
        failures.append(f'{label}: {len(checkpoints)} checkpoints are too few to judge growth')
    half = len(checkpoints) // 2
    growth = {}
    for key in BOUNDED:
        if key not in checkpoints[0] or int(checkpoints[0][key]) < 0:
            continue
        first = max(int(point[key]) for point in checkpoints[:half])
        later = max(int(point[key]) for point in checkpoints[half:])
        growth[key] = {'first_half_max': first, 'second_half_max': later}
        if later > first + first // 10:
            failures.append(f'{label}: {key} grew from {first} to {later} across equivalent churn')
    record['growth'] = growth
    for point in checkpoints:
        for key, expected in EXACT.items():
            if key in point and int(point[key]) != expected:
                failures.append(f"{label}: round {point['round']} {key}={point[key]}, expected {expected}")
    summary[label] = record
(work / 'soak-summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
for label, record in summary.items():
    last = record['checkpoints'][-1]
    print(f"{label}: {record['summary']} final {last}")
if failures:
    raise SystemExit('native-allocator-soak: ' + '; '.join(failures))
PY
    receipt_cases+=("soak-growth=0:soak-summary.json")
fi
printf 'owned native-allocator stress/soak: PASS (musl, pinned-C static-PIE, audited native-shadow static-PIE/dynamic PIE); evidence: %s\n' "$work"
