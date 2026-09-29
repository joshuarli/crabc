#!/usr/bin/env bash
# Run one compiled signal-handler-fork receiver through both selected backends.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [ "$#" -ne 4 ]; then
    printf 'usage: %s ACCEPTED_STATIC ACCEPTED_DYNAMIC NATIVE_STATIC NATIVE_DYNAMIC\n' "$0" >&2
    exit 2
fi
readonly accepted_static="$(realpath -e "$1")"
readonly accepted_dynamic="$(realpath -e "$2")"
readonly native_static="$(realpath -e "$3")"
readonly native_dynamic="$(realpath -e "$4")"
readonly work="$(mktemp -d "$ROOT/.work/x86_64/tmp/native-signal-fork-reaping.XXXXXX")"
chmod a+rx "$work"
printf 'native signal/fork reaping evidence: %s\n' "$work"

python3 -B - "$ROOT" "$work" <<'PY'
from pathlib import Path
import hashlib, json, sys
root, work = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_libc_test import ensure_source
source, pin = ensure_source()
upstream = source / 'src/regression/raise-race.c'
probe = root / 'compat/x86_64/tests/native_signal_fork_reaping_probe.c'
(work / 'sources.json').write_text(json.dumps({
    'pinned_source': pin,
    'upstream_raise_race_sha256': hashlib.sha256(upstream.read_bytes()).hexdigest(),
    'receiver_sha256': hashlib.sha256(probe.read_bytes()).hexdigest(),
}, sort_keys=True, indent=2) + '\n')
PY

"$accepted_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$ROOT/compat/x86_64/tests/native_signal_fork_reaping_probe.c" -o "$work/receiver.o"
sha256sum "$work/receiver.o" >"$work/receiver-object.sha256"
/usr/local/bin/crabc-x86_64-musl-gcc -static -fno-pie -no-pie -pthread \
    "$work/receiver.o" -o "$work/oracle"

mkdir -p "$work/root/oracle"
cp "$work/oracle" "$work/root/oracle/receiver"
printf 'case\tmode\tstatus\tsummary\n' >"$work/results.tsv"
run_case() {
    local label="$1" mode="$2" root="$3" status summary
    set +e
    timeout 35 env -i PATH="$PATH" chroot "$root" /receiver "$mode" \
        >"$work/$label-$mode.stdout" 2>"$work/$label-$mode.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/$label-$mode.status"
    summary="$(sed -n '/^summary /p' "$work/$label-$mode.stdout" | tail -1)"
    printf '%s\t%s\t%s\t%s\n' "$label" "$mode" "$status" "$summary" >>"$work/results.tsv"
}
for mode in worker-wait main-wait worker-wait-guarded main-wait-guarded; do
    run_case oracle "$mode" "$work/root/oracle"
done

for backend in accepted native; do
    if [ "$backend" = accepted ]; then
        static="$accepted_static"; dynamic="$accepted_dynamic"
    else
        static="$native_static"; dynamic="$native_dynamic"
    fi
    for link in static static-pie; do
        root="$work/root/$backend-$link"
        mkdir -p "$root"
        "$static/bin/crabc-cc" "-$link" "$work/receiver.o" -o "$root/receiver"
        for mode in worker-wait main-wait worker-wait-guarded main-wait-guarded; do
            run_case "$backend-$link" "$mode" "$root"
        done
    done
    for link in pie non-pie; do
        root="$work/root/$backend-$link"
        mkdir -p "$root"
        cp -a "$dynamic/." "$root/"
        "$dynamic/bin/crabc-cc-dynamic" "--dynamic-$link" "$work/receiver.o" -o "$root/receiver"
        for mode in worker-wait main-wait worker-wait-guarded main-wait-guarded; do
            run_case "$backend-$link-kernel" "$mode" "$root"
            set +e
            timeout 35 env -i PATH="$PATH" chroot "$root" /lib/ld-crabc-x86_64.so.1 /receiver "$mode" \
                >"$work/$backend-$link-direct-$mode.stdout" \
                2>"$work/$backend-$link-direct-$mode.stderr"
            status=$?
            set -e
            printf '%s\n' "$status" >"$work/$backend-$link-direct-$mode.status"
            summary="$(sed -n '/^summary /p' "$work/$backend-$link-direct-$mode.stdout" | tail -1)"
            printf '%s\t%s\t%s\t%s\n' "$backend-$link-direct" "$mode" "$status" "$summary" >>"$work/results.tsv"
        done
    done
done
cat "$work/results.tsv"
python3 -B - "$work/results.tsv" <<'PY'
from pathlib import Path
import csv, sys
rows = list(csv.DictReader(Path(sys.argv[1]).open(), delimiter='\t'))
guarded = [row for row in rows if row['mode'].endswith('-guarded')]
failed = [row['case'] + '/' + row['mode'] for row in guarded
          if row['status'] != '0' or 'reaped=100 echild=0' not in row['summary']
          or 'missing=0' not in row['summary']]
print(f'guarded controls: {len(guarded) - len(failed)}/{len(guarded)} pass')
if failed:
    raise SystemExit('guarded controls failed: ' + ', '.join(failed))
PY
