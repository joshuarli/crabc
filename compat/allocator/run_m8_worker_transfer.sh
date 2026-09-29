#!/usr/bin/env bash
# Compare one installed libc worker-exit transfer through the public C ABI.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly RUNNER=owned-native-allocator-worker-transfer
readonly FIXTURE="$ROOT/compat/allocator/x86_64_m8_worker_transfer.c"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

[ "$#" -eq 0 ] || { printf 'usage: %s\n' "$0" >&2; exit 2; }
work="$(mktemp -d "$TMPDIR/$RUNNER.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'native-allocator-worker-transfer evidence: %s\n' "$work"
rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$RUNNER/latest"
cases=()
products=("fixture=$FIXTURE")
publish() {
    local status=$?
    trap - EXIT
    printf '%s\n' "$status" >"$work/runner.status"
    cases+=("runner=$status:runner.status")
    local -a arguments=(--runner "$RUNNER" --work "$work" --canonical yes
        --parameter 'MODES=musl,accepted-c,native-shadow'
        --parameter 'ENTRY=static-pie'
        --parameter 'TIMEOUT=60')
    local entry
    for entry in "${cases[@]}"; do arguments+=(--case "$entry"); done
    for entry in "${products[@]}"; do arguments+=(--product "$entry"); done
    python3 -B "$ROOT/compat/x86_64/native_shadow_receipt.py" write "${arguments[@]}" || status=1
    exit "$status"
}
trap publish EXIT

"$ORACLE_CC" -std=c11 -O2 -pthread -static -fno-pie -no-pie "$FIXTURE" -o "$work/musl"
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend accepted-c \
    --output "$work/accepted-c-sysroot" >"$work/accepted-c-build.json"
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow \
    --output "$work/native-shadow-sysroot" >"$work/native-shadow-build.json"
for mode in accepted-c native-shadow; do
    sysroot="$work/$mode-sysroot"
    "$sysroot/bin/crabc-cc" -std=c11 -O2 -pthread -static-pie "$FIXTURE" -o "$work/$mode"
    products+=(
        "$mode-manifest=$sysroot/share/crabc/manifest.json"
        "$mode-provenance=$sysroot/share/crabc/libc-static.provenance.json"
        "$mode-build=$work/$mode-build.json"
    )
done
for mode in musl accepted-c native-shadow; do products+=("binary-$mode=$work/$mode"); done

for mode in musl accepted-c native-shadow; do
    status=0
    timeout 60 env -i PATH=/usr/bin:/bin "$work/$mode" >"$work/$mode.stdout" 2>"$work/$mode.stderr" || status=$?
    cases+=("$mode=$status:$mode.stdout,$mode.stderr")
    [ "$status" -eq 0 ] || { printf '%s failed: %s\n' "$mode" "$status" >&2; exit 1; }
    [ ! -s "$work/$mode.stderr" ] || { printf '%s wrote stderr\n' "$mode" >&2; exit 1; }
done
cmp "$work/musl.stdout" "$work/accepted-c.stdout"
cmp "$work/musl.stdout" "$work/native-shadow.stdout"
printf 'native-allocator-worker-transfer: PASS (musl, source-built accepted-c, source-built native-shadow)\n'
