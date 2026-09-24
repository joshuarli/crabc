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
readonly probe="$ROOT/compat/x86_64/owned_native_allocator_dso_probe.c"
readonly library="$ROOT/compat/x86_64/owned_native_allocator_dso_library.c"
readonly musl_interpreter=/lib/ld-musl-x86_64.so.1

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

# The malloc family keeps musl's libc.so type, binding and visibility.
family='malloc|free|calloc|realloc|reallocarray|aligned_alloc|posix_memalign|memalign|valloc|malloc_usable_size'
bindings() {
    readelf --dyn-syms -W "$1" | awk -v family="^($family)\$" '$4 == "FUNC" && $7 != "UND" && $8 ~ family { print $8, $4, $5, $6 }' | sort
}
bindings /opt/musl-1.2.6/lib/libc.so >"$work/musl-family.bindings"
bindings "$dynamic_sysroot/usr/lib/libc.so" >"$work/candidate-family.bindings"
[ -s "$work/musl-family.bindings" ] || { printf 'native-allocator-dso: musl libc.so defines no malloc family\n' >&2; exit 1; }
cmp "$work/musl-family.bindings" "$work/candidate-family.bindings" || {
    printf 'native-allocator-dso: libc.so malloc-family bindings differ from musl\n' >&2
    exit 1
}

# Compile once through the installed driver; link each object for both sides.
mkdir "$work/objects" "$work/oracle"
for name in initial plugin; do
    "$driver" --dynamic-shared-object -std=c11 -fno-builtin \
        "-DDSO_NAME=\"$name\"" "-DDSO_SYMBOL=$name" -c "$library" -o "$work/objects/$name.o"
    "$driver" --dynamic-shared-object "$work/objects/$name.o" -o "$work/libdso-$name.so"
    "$oracle_cc" -shared "$work/objects/$name.o" -Wl,-z,now,-soname,"libdso-$name.so" \
        -o "$work/oracle/libdso-$name.so"
done
"$driver" --dynamic-pie -std=c11 -fno-builtin -c "$probe" -o "$work/objects/probe.o"

run_case() {
    local name="$1"
    shift
    local status=0
    timeout 30 env -i PATH="$PATH" "$@" >"$work/$name.stdout" 2>"$work/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$name.status"
    if [ "$status" -ne 0 ] || [ -s "$work/$name.stderr" ]; then
        printf 'native-allocator-dso: %s exited %s\n' "$name" "$status" >&2
        cat "$work/$name.stderr" >&2
        return 1
    fi
}

cp -a "$dynamic_sysroot" "$work/execution-root"
cp "$work/libdso-initial.so" "$work/execution-root/usr/lib/"
cp "$work/libdso-plugin.so" "$work/execution-root/libdso-plugin.so"
for mode in pie non-pie; do
    oracle_entry=(-fPIE -pie)
    [ "$mode" = pie ] || oracle_entry=(-fno-pie -no-pie)
    "$oracle_cc" "${oracle_entry[@]}" "$work/objects/probe.o" -L"$work/oracle" \
        -Wl,-rpath,"$work/oracle" -l:libdso-initial.so -o "$work/oracle/probe-$mode"
    run_case "oracle-$mode" "$work/oracle/probe-$mode" "$work/oracle/libdso-plugin.so"
    "$driver" "--dynamic-$mode" "$work/objects/probe.o" --application-dso "$work/libdso-initial.so" \
        -o "$work/execution-root/probe-$mode"
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
