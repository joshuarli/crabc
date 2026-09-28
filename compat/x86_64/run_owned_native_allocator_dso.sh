#!/usr/bin/env bash
# Installed native-shadow allocation across DSOs and dlopen against pinned musl.
#
# One executable, one initial DSO and one runtime-loaded plugin allocate,
# grow and free each other's blocks, compare their malloc family identities
# and errno contracts, and keep the plugin's blocks and code across dlclose,
# which musl retains. The native-shadow dynamic product runs the objects
# compiled once by its driver, as PIE and non-PIE, through the kernel and the
# direct loader, and must reproduce the musl transcript. libc.so must bind
# the malloc family exactly as musl's libc.so does. Without a supplied product
# the runner builds a native-shadow dynamic sysroot.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly dso_linker="$ROOT/compat/x86_64/owned_native_allocator_dso.py"
readonly probe="$ROOT/compat/x86_64/owned_native_allocator_dso_probe.c"
readonly library="$ROOT/compat/x86_64/owned_native_allocator_dso_library.c"
readonly musl_interpreter=/lib/ld-musl-x86_64.so.1
readonly receipt_runner=owned-native-allocator-dso
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

[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
dynamic_sysroot=''
[ "$#" -eq 0 ] || dynamic_sysroot="$(realpath -e "$1")"

python3 -B - "$ROOT" "${TMPDIR:-}" "$dynamic_sysroot" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('native-allocator-dso TMPDIR must be a physical checkout .work directory')
if sys.argv[3] and not Path(sys.argv[3]).is_relative_to(root / '.work'):
    raise SystemExit('native-allocator-dso product must be a checkout .work directory')
PY

work="$(mktemp -d "$TMPDIR/owned-native-allocator-dso.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'native-allocator-dso evidence: %s\n' "$work"

rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
receipt_cases=()
receipt_products=()
source_before="$(source_seal)"
publish_receipt() {
    local status=$?
    trap - EXIT
    local source_after=''
    if ! source_after="$(source_seal)" || [ "$source_after" != "$source_before" ]; then
        printf 'native-allocator-dso: source changed during the run\n' >&2
        status=1
    fi
    printf '%s\n' "$status" >"$work/runner.status"
    receipt_cases+=("runner=$status:runner.status")
    local -a arguments=(--runner "$receipt_runner" --work "$work" --canonical yes
        --parameter "CASE_TIMEOUT=$case_timeout"
        --parameter 'MODES=pie,non-pie'
        --parameter 'ENTRIES=kernel,direct'
        --parameter 'DSOS=initial,dlopen-plugin'
        --parameter 'ENVIRONMENT=empty-with-pinned-PATH')
    local entry
    for entry in "${receipt_cases[@]}"; do arguments+=(--case "$entry"); done
    for entry in "${receipt_products[@]}"; do arguments+=(--product "$entry"); done
    if ! python3 -B "$ROOT/compat/x86_64/native_shadow_receipt.py" write "${arguments[@]}"; then
        status=1
    elif [ "$(source_seal)" != "$source_before" ]; then
        rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
        printf 'native-allocator-dso: source changed while publishing the receipt\n' >&2
        status=1
    fi
    exit "$status"
}
trap publish_receipt EXIT

if [ -z "$dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    dynamic_sysroot="$work/dynamic-sysroot"
fi
readonly driver="$dynamic_sysroot/bin/crabc-cc-dynamic"
python3 -B - "$dynamic_sysroot/share/crabc/libc-shared.provenance.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as stream:
    backend = json.load(stream).get('allocator_backend')
if backend != 'native-shadow':
    raise SystemExit(f'{sys.argv[1]}: allocator_backend is {backend!r}, not native-shadow')
PY
receipt_products+=(
    "dynamic-manifest=$dynamic_sysroot/share/crabc/manifest.json"
    "dynamic-product-state=$dynamic_sysroot/share/crabc/dynamic-product-state.json"
    "dynamic-libc-provenance=$dynamic_sysroot/share/crabc/libc-shared.provenance.json"
    "dynamic-libc=$dynamic_sysroot/usr/lib/libc.so"
    "dynamic-loader=$dynamic_sysroot/lib/ld-crabc-x86_64.so.1"
    "dynamic-driver=$driver"
    "musl-libc=/opt/musl-1.2.6/lib/libc.so"
    "musl-interpreter=$musl_interpreter"
)
if [ -f "$work/dynamic-build.json" ]; then receipt_products+=("dynamic-build=$work/dynamic-build.json"); fi

# The malloc family keeps musl's libc.so type, binding and visibility.
family='malloc|free|calloc|realloc|reallocarray|aligned_alloc|posix_memalign|memalign|valloc|malloc_usable_size'
bindings() {
    readelf --dyn-syms -W "$1" | awk -v family="^($family)\$" '$4 == "FUNC" && $7 != "UND" && $8 ~ family { print $8, $4, $5, $6 }' | sort
}
bindings /opt/musl-1.2.6/lib/libc.so >"$work/musl-family.bindings"
bindings "$dynamic_sysroot/usr/lib/libc.so" >"$work/candidate-family.bindings"
receipt_products+=(
    "musl-family-bindings=$work/musl-family.bindings"
    "candidate-family-bindings=$work/candidate-family.bindings"
)
[ -s "$work/musl-family.bindings" ] || { printf 'native-allocator-dso: musl libc.so defines no malloc family\n' >&2; exit 1; }
cmp "$work/musl-family.bindings" "$work/candidate-family.bindings" || {
    printf 'native-allocator-dso: libc.so malloc-family bindings differ from musl\n' >&2
    exit 1
}

# Compile once through the installed driver; link each object for both sides.
mkdir "$work/objects" "$work/oracle"
receipt_products+=(
    "source-library=$library"
    "link-producer=$dso_linker"
    "oracle-wrapper=$oracle_cc"
    "oracle-gcc=/usr/bin/gcc"
    "oracle-specs=/opt/musl-1.2.6/lib/musl-gcc.specs"
)
for name in initial plugin; do
    "$driver" --dynamic-shared-object -std=c11 -fno-builtin \
        "-DDSO_NAME=\"$name\"" "-DDSO_SYMBOL=$name" -c "$library" -o "$work/objects/$name.o"
    python3 -B "$dso_linker" --work "$work" --product "$dynamic_sysroot" \
        --arm candidate --role "$name"
    python3 -B "$dso_linker" --work "$work" --arm oracle --role "$name"
    receipt_products+=(
        "object-$name=$work/objects/$name.o"
        "link-candidate-$name=$work/link-candidate-$name.json"
        "link-oracle-$name=$work/link-oracle-$name.json"
        "candidate-link-sidecar-$name=$work/libdso-$name.so.crabc-link.json"
        "oracle-$name-dso=$work/oracle/libdso-$name.so"
    )
done
candidate_linker="$(python3 -B - "$work/libdso-initial.so.crabc-link.json" <<'PY'
import json
import sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text())["resolved_linker"]["path"])
PY
)"
receipt_products+=("candidate-linker=$candidate_linker")
"$driver" --dynamic-pie -std=c11 -fno-builtin -c "$probe" -o "$work/objects/probe.o"
receipt_products+=("object-probe=$work/objects/probe.o")

run_case() {
    local name="$1"
    shift
    local status=0
    timeout "$case_timeout" env -i PATH="$PATH" "$@" >"$work/$name.stdout" 2>"$work/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$name.status"
    receipt_cases+=("$name=$status:$name.stdout,$name.stderr,$name.status")
    if [ "$status" -ne 0 ] || [ -s "$work/$name.stderr" ]; then
        printf 'native-allocator-dso: %s exited %s\n' "$name" "$status" >&2
        cat "$work/$name.stderr" >&2
        return 1
    fi
}

cp -a "$dynamic_sysroot" "$work/execution-root"
cp "$work/libdso-initial.so" "$work/execution-root/usr/lib/"
cp "$work/libdso-plugin.so" "$work/execution-root/libdso-plugin.so"
receipt_products+=(
    "candidate-initial-dso=$work/execution-root/usr/lib/libdso-initial.so"
    "candidate-plugin-dso=$work/execution-root/libdso-plugin.so"
)
for mode in pie non-pie; do
    oracle_entry=(-fPIE -pie)
    [ "$mode" = pie ] || oracle_entry=(-fno-pie -no-pie)
    "$oracle_cc" "${oracle_entry[@]}" "$work/objects/probe.o" -L"$work/oracle" \
        -Wl,-rpath,"$work/oracle" -l:libdso-initial.so -o "$work/oracle/probe-$mode"
    receipt_products+=("oracle-probe-$mode=$work/oracle/probe-$mode")
    run_case "oracle-$mode" "$work/oracle/probe-$mode" "$work/oracle/libdso-plugin.so"
    "$driver" "--dynamic-$mode" "$work/objects/probe.o" --application-dso "$work/libdso-initial.so" \
        -o "$work/execution-root/probe-$mode"
    receipt_products+=("candidate-probe-$mode=$work/execution-root/probe-$mode")
    for entry in kernel direct; do
        loader=()
        [ "$entry" = kernel ] || loader=(/lib/ld-crabc-x86_64.so.1)
        run_case "$entry-$mode" chroot "$work/execution-root" "${loader[@]}" "/probe-$mode" /libdso-plugin.so
        cmp "$work/oracle-$mode.stdout" "$work/$entry-$mode.stdout" || {
            printf 'native-allocator-dso: %s-%s transcript differs from musl\n' "$entry" "$mode" >&2
            exit 1
        }
    done
done
printf 'owned native-allocator DSO composition: PASS (musl + native-shadow dynamic PIE/non-PIE kernel/direct; executable/initial DSO/plugin transfers, dlclose retention, errno, musl malloc-family bindings); evidence: %s\n' "$work"
