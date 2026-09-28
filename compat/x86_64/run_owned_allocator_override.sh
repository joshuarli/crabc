#!/usr/bin/env bash
# Installed native-shadow application allocator replacement against pinned musl.
#
# The probe defines its own allocator in the executable, replacing either the
# complete malloc family (`full`) or only malloc/free/realloc (`trio`), and
# rejects any pointer it did not allocate. Each native-shadow static,
# static-PIE and dynamic PIE/non-PIE (kernel and direct loader) product mode
# must link it and reproduce the musl transcript. Dynamic modes also take the
# replacement from an initial DSO. Without supplied products
# the runner builds both native-shadow sysroots.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_allocator_override_probe.c"
readonly scenarios=(full trio)
readonly receipt_runner=owned-allocator-override
readonly case_timeout=30

source_seal() {
    python3 -B - "$ROOT" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
from native_shadow_receipt import source_seal
print(json.dumps(source_seal(root), sort_keys=True, separators=(',', ':')))
PY
}

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

python3 -B - "$ROOT" "${TMPDIR:-}" "$static_sysroot" "$dynamic_sysroot" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('allocator-override TMPDIR must be a physical checkout .work directory')
for argument in sys.argv[3:]:
    if argument and not Path(argument).is_relative_to(root / '.work'):
        raise SystemExit('allocator-override products must be checkout .work directories')
PY

work="$(mktemp -d "$TMPDIR/owned-allocator-override.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'allocator-override evidence: %s\n' "$work"

rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
receipt_cases=()
receipt_products=()
source_before="$(source_seal)"
publish_receipt() {
    local status=$?
    trap - EXIT
    local source_after=''
    if ! source_after="$(source_seal)" || [ "$source_after" != "$source_before" ]; then
        printf 'allocator-override: source changed during the run\n' >&2
        status=1
    fi
    printf '%s\n' "$status" >"$work/runner.status"
    receipt_cases+=("runner=$status:runner.status")
    local -a arguments=(--runner "$receipt_runner" --work "$work" --canonical yes
        --parameter "CASE_TIMEOUT=$case_timeout"
        --parameter 'SCENARIOS=full,trio'
        --parameter 'STATIC_MODES=static,static-pie'
        --parameter 'DYNAMIC_MODES=kernel-pie,direct-pie,kernel-non-pie,direct-non-pie'
        --parameter 'PROVIDERS=executable,initial-dso')
    local entry
    for entry in "${receipt_cases[@]}"; do arguments+=(--case "$entry"); done
    for entry in "${receipt_products[@]}"; do arguments+=(--product "$entry"); done
    if ! python3 -B "$ROOT/compat/x86_64/native_shadow_receipt.py" write "${arguments[@]}"; then
        status=1
    elif [ "$(source_seal)" != "$source_before" ]; then
        rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
        printf 'allocator-override: source changed while publishing the receipt\n' >&2
        status=1
    fi
    exit "$status"
}
trap publish_receipt EXIT

if [ -z "$static_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow \
        --output "$work/static-sysroot" >"$work/static-build.json"
    static_sysroot="$work/static-sysroot"
fi
if [ -z "$dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    dynamic_sysroot="$work/dynamic-sysroot"
fi
python3 -B - "$static_sysroot/share/crabc/manifest.json" \
    "$dynamic_sysroot/share/crabc/libc-shared.provenance.json" <<'PY'
import json
import sys
for path in sys.argv[1:]:
    with open(path, encoding='utf-8') as stream:
        backend = json.load(stream).get('allocator_backend')
    if backend != 'native-shadow':
        raise SystemExit(f'{path}: allocator_backend is {backend!r}, not native-shadow')
PY
receipt_products+=(
    "static-manifest=$static_sysroot/share/crabc/manifest.json"
    "static-libc-provenance=$static_sysroot/share/crabc/libc-static.provenance.json"
    "static-libc-archive=$static_sysroot/usr/lib/libc.a"
    "dynamic-manifest=$dynamic_sysroot/share/crabc/manifest.json"
    "dynamic-product-state=$dynamic_sysroot/share/crabc/dynamic-product-state.json"
    "dynamic-libc-provenance=$dynamic_sysroot/share/crabc/libc-shared.provenance.json"
    "dynamic-libc=$dynamic_sysroot/usr/lib/libc.so"
    "dynamic-loader=$dynamic_sysroot/lib/ld-crabc-x86_64.so.1"
)
if [ -f "$work/static-build.json" ]; then receipt_products+=("static-build=$work/static-build.json"); fi
if [ -f "$work/dynamic-build.json" ]; then receipt_products+=("dynamic-build=$work/dynamic-build.json"); fi

# Run one mode and scenario; retain stdout, stderr and status, then compare
# with the oracle transcript for the same scenario.
run_case() {
    local mode="$1"
    local scenario="$2"
    local name="$mode-$scenario"
    shift 2
    local status=0
    timeout "$case_timeout" "$@" >"$work/$name.stdout" 2>"$work/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$name.status"
    receipt_cases+=("$name=$status:$name.stdout,$name.stderr,$name.status")
    if [ "$status" -ne 0 ]; then
        printf 'allocator-override: %s exited %s\n' "$name" "$status" >&2
        cat "$work/$name.stderr" >&2
        return 1
    fi
    [ ! -s "$work/$name.stderr" ] || { cat "$work/$name.stderr" >&2; return 1; }
    [ "$mode" != oracle ] || return 0
    cmp "$work/oracle-$scenario.stdout" "$work/$name.stdout" || {
        printf 'allocator-override: %s transcript differs from musl\n' "$name" >&2
        return 1
    }
}

# `full` also replaces calloc, the aligned entries and malloc_usable_size.
scenario_flags() { [ "$1" = full ] && printf '%s\n' -DFULL_OVERRIDE || true; }

cp -a "$dynamic_sysroot" "$work/execution-root"
for scenario in "${scenarios[@]}"; do
    mapfile -t flags < <(scenario_flags "$scenario")
    "$oracle_cc" -static -fno-pie -no-pie -std=c11 -pthread "${flags[@]}" "$probe" -o "$work/oracle-$scenario.exe"
    receipt_products+=("oracle-$scenario=$work/oracle-$scenario.exe")
    run_case oracle "$scenario" "$work/oracle-$scenario.exe"
    for mode in static static-pie; do
        "$static_sysroot/bin/crabc-cc" "-$mode" -std=c11 -pthread "${flags[@]}" "$probe" \
            -o "$work/$mode-$scenario.exe"
        receipt_products+=("$mode-$scenario=$work/$mode-$scenario.exe")
        run_case "$mode" "$scenario" "$work/$mode-$scenario.exe"
    done
    for mode in pie non-pie; do
        "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 -pthread "${flags[@]}" \
            "$probe" -o "$work/dynamic-$mode-$scenario.exe"
        receipt_products+=("dynamic-$mode-$scenario=$work/dynamic-$mode-$scenario.exe")
        cp "$work/dynamic-$mode-$scenario.exe" "$work/execution-root/consumer-$mode-$scenario"
        run_case "kernel-$mode" "$scenario" chroot "$work/execution-root" "/consumer-$mode-$scenario"
        run_case "direct-$mode" "$scenario" chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode-$scenario"
    done
done

# A dynamic process may take its replacement from an initial DSO instead:
# the allocator alone is a DT_NEEDED library that preempts libc.so, and the
# executable holds only the client.
mkdir "$work/oracle-dso"
for scenario in "${scenarios[@]}"; do
    mapfile -t flags < <(scenario_flags "$scenario")
    library="liboverride-$scenario.so"
    "$oracle_cc" -shared -fPIC -std=c11 -pthread "${flags[@]}" -DOVERRIDE_PROVIDER_ONLY "$probe" \
        -Wl,-soname,"$library" -o "$work/oracle-dso/$library"
    receipt_products+=("oracle-dso-provider-$scenario=$work/oracle-dso/$library")
    "$oracle_cc" -std=c11 -pthread "${flags[@]}" -DOVERRIDE_CLIENT_ONLY "$probe" -L"$work/oracle-dso" \
        -Wl,-rpath,"$work/oracle-dso" -l:"$library" -o "$work/oracle-dso-$scenario.exe"
    receipt_products+=("oracle-dso-client-$scenario=$work/oracle-dso-$scenario.exe")
    run_case oracle "dso-$scenario" "$work/oracle-dso-$scenario.exe"
    "$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-shared-object -std=c11 -pthread "${flags[@]}" \
        -DOVERRIDE_PROVIDER_ONLY "$probe" -o "$work/$library"
    receipt_products+=("override-dso-$scenario=$work/$library")
    cp "$work/$library" "$work/execution-root/usr/lib/"
    for mode in pie non-pie; do
        "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 -pthread "${flags[@]}" \
            -DOVERRIDE_CLIENT_ONLY "$probe" --application-dso "$work/$library" \
            -o "$work/execution-root/consumer-dso-$mode-$scenario"
        receipt_products+=("dso-client-$mode-$scenario=$work/execution-root/consumer-dso-$mode-$scenario")
        run_case "kernel-$mode" "dso-$scenario" chroot "$work/execution-root" "/consumer-dso-$mode-$scenario"
        run_case "direct-$mode" "dso-$scenario" chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-dso-$mode-$scenario"
    done
done
printf 'owned allocator override: PASS (musl + native-shadow static/static-PIE/dynamic PIE/non-PIE kernel/direct; full-family and malloc/free/realloc replacement from the executable, and from an initial DSO in dynamic modes); evidence: %s\n' "$work"
