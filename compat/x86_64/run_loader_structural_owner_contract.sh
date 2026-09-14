#!/usr/bin/env bash
# Collect only the finite loader structural-owner normal-consumer matrix.
#
# The two probes use public dl*/pthread APIs.  Their transcripts establish
# ordinary consumer behavior; source guards in the paired reader establish the
# selected graph, registry, lock and constructor ordering.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly READER="$ROOT/compat/x86_64/loader_structural_owner_contract_reader.py"
readonly IMAGE='sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d'
readonly PATH_VALUE='/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_SHARED=/opt/musl-1.2.6/lib/libc.so
readonly TIMEOUT=/usr/bin/timeout
readonly CHROOT=/usr/sbin/chroot

usage() {
    printf 'usage: %s --output DIR --static-product DIR --dynamic-product DIR --static-preparation FILE --base-inventory FILE --full-facts FILE --loader-debug-report FILE --loader-runtime-registry-report FILE\n' "$0" >&2
    exit 2
}

OUTPUT= STATIC_PRODUCT= DYNAMIC_PRODUCT= STATIC_PREPARATION= BASE_INVENTORY= FULL_FACTS=
LOADER_DEBUG_REPORT= LOADER_RUNTIME_REGISTRY_REPORT=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        --static-product) STATIC_PRODUCT="$2"; shift 2 ;;
        --dynamic-product) DYNAMIC_PRODUCT="$2"; shift 2 ;;
        --static-preparation) STATIC_PREPARATION="$2"; shift 2 ;;
        --base-inventory) BASE_INVENTORY="$2"; shift 2 ;;
        --full-facts) FULL_FACTS="$2"; shift 2 ;;
        --loader-debug-report) LOADER_DEBUG_REPORT="$2"; shift 2 ;;
        --loader-runtime-registry-report) LOADER_RUNTIME_REGISTRY_REPORT="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$OUTPUT" ] && [ -n "$STATIC_PRODUCT" ] && [ -n "$DYNAMIC_PRODUCT" ] && [ -n "$STATIC_PREPARATION" ] && [ -n "$BASE_INVENTORY" ] && [ -n "$FULL_FACTS" ] && [ -n "$LOADER_DEBUG_REPORT" ] && [ -n "$LOADER_RUNTIME_REGISTRY_REPORT" ] || usage

case "$OUTPUT" in "$ROOT/.work"/*) ;; *) printf 'output must be beneath checkout .work\n' >&2; exit 2 ;; esac
case "$STATIC_PRODUCT" in "$ROOT/.work"/*) ;; *) printf 'static product must be beneath checkout .work\n' >&2; exit 2 ;; esac
case "$DYNAMIC_PRODUCT" in "$ROOT/.work"/*) ;; *) printf 'dynamic product must be beneath checkout .work\n' >&2; exit 2 ;; esac
[ ! -e "$OUTPUT" ] || { printf 'output already exists: %s\n' "$OUTPUT" >&2; exit 2; }
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_SHARED" ] && [ -x "$TIMEOUT" ] && [ -x "$CHROOT" ] || { printf 'pinned image tools are unavailable\n' >&2; exit 2; }

python3 -B "$READER" begin-collection --root "$ROOT" --output "$OUTPUT" --image "$IMAGE" \
    --static-product "$STATIC_PRODUCT" --dynamic-product "$DYNAMIC_PRODUCT" \
    --static-preparation "$STATIC_PREPARATION" --base-inventory "$BASE_INVENTORY" --full-facts "$FULL_FACTS" \
    --loader-debug-report "$LOADER_DEBUG_REPORT" --loader-runtime-registry-report "$LOADER_RUNTIME_REGISTRY_REPORT" \
    --oracle-compiler "$ORACLE_CC" --musl-shared "$MUSL_SHARED"

readonly DYNAMIC_DRIVER="$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic"
mkdir -p "$OUTPUT/commands" "$OUTPUT/objects" "$OUTPUT/executables" "$OUTPUT/roots"
chmod 00755 "$OUTPUT" "$OUTPUT/commands" "$OUTPUT/objects" "$OUTPUT/executables" "$OUTPUT/roots"

record() {
    local name="$1"
    shift
    python3 -B - "$OUTPUT/commands/$name.argv.json" "$OUTPUT" "$PATH_VALUE" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps({
    'argv': sys.argv[4:], 'cwd': sys.argv[2],
    'environment': {'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC', 'PATH': sys.argv[3]},
    'stdin': '/dev/null',
}, sort_keys=True) + '\n', encoding='utf-8')
PY
    local status=0
    (cd "$OUTPUT" && env -i LC_ALL=C LANG=C TZ=UTC PATH="$PATH_VALUE" "$@") \
        </dev/null >"$OUTPUT/commands/$name.stdout" 2>"$OUTPUT/commands/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$OUTPUT/commands/$name.status"
    [ "$status" -eq 0 ] || { printf 'loader structural-owner command failed: %s\n' "$name" >&2; exit "$status"; }
}

capture_root() {
    python3 -B "$READER" capture-runtime-root --output "$OUTPUT" --runtime-root "$5" \
        --probe "$1" --lane "$2" --mode "$3" --phase "$4"
}

normalize_root() {
    python3 -B - "$1" <<'PY'
from pathlib import Path
import os
import stat
import sys
root = Path(sys.argv[1])
for path in [root, *sorted(root.rglob('*'))]:
    if path.is_symlink():
        continue
    if path.is_dir():
        os.chmod(path, 0o755)
    elif path.is_file():
        os.chmod(path, 0o755 if path.name in {'consumer', 'crabc-cc-dynamic', 'ld-musl-x86_64.so.1', 'ld-crabc-x86_64.so.1', 'libc.so'} else 0o644)
    else:
        raise SystemExit(f'unsupported runtime root entry: {path}')
PY
}

prepare_candidate_root() {
    local root="$1" executable="$2" plugin="$3"
    mkdir -p "$(dirname "$root")"
    cp -a "$DYNAMIC_PRODUCT" "$root"
    cp "$executable" "$root/consumer"
    cp "$plugin" "$root/usr/lib/libloader-structural-owner-plugin.so"
    # The copied selected product is already mode-sealed. Only these two
    # component additions have the receipt's explicit runtime-root modes.
    chmod 0755 "$root/consumer"
    chmod 0644 "$root/usr/lib/libloader-structural-owner-plugin.so"
}

prepare_pinned_root() {
    local root="$1" executable="$2" plugin="$3"
    mkdir -p "$root/lib" "$root/usr/lib"
    cp "$MUSL_SHARED" "$root/lib/ld-musl-x86_64.so.1"
    cp "$MUSL_SHARED" "$root/usr/lib/libc.so"
    cp "$executable" "$root/consumer"
    cp "$plugin" "$root/usr/lib/libloader-structural-owner-plugin.so"
    normalize_root "$root"
}

record compile-startup-entry-public-dlfcn "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -fno-builtin -fno-stack-protector -pthread -c \
    "$ROOT/compat/x86_64/loader_structural_owner_startup_probe.c" -o "$OUTPUT/objects/startup-entry-public-dlfcn.o"
record compile-registration-replacement-before-worker "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -fno-builtin -fno-stack-protector -pthread -c \
    "$ROOT/compat/x86_64/loader_structural_owner_registration_probe.c" -o "$OUTPUT/objects/registration-replacement-before-worker.o"
record compile-plugin "$DYNAMIC_DRIVER" --dynamic-shared-object -std=c11 -fno-builtin -fno-stack-protector -c \
    "$ROOT/compat/x86_64/loader_structural_owner_plugin.c" -o "$OUTPUT/objects/loader-structural-owner-plugin.o"
mkdir -p "$OUTPUT/plugins"
record link-plugin-candidate "$DYNAMIC_DRIVER" --dynamic-shared-object \
    "$OUTPUT/objects/loader-structural-owner-plugin.o" -o "$OUTPUT/plugins/candidate-plugin.so"
record link-plugin-pinned-musl-1.2.6 "$ORACLE_CC" -shared \
    "$OUTPUT/objects/loader-structural-owner-plugin.o" -o "$OUTPUT/plugins/pinned-musl-plugin.so"
chmod 0644 "$OUTPUT/plugins/candidate-plugin.so" "$OUTPUT/plugins/pinned-musl-plugin.so"

for probe in startup-entry-public-dlfcn registration-replacement-before-worker; do
    object="$OUTPUT/objects/$probe.o"
    for lane in pinned-musl-1.2.6 candidate; do
        for mode in dynamic-pie-kernel dynamic-pie-direct dynamic-non-pie-kernel dynamic-non-pie-direct; do
            link_mode=pie
            case "$mode" in dynamic-non-pie-*) link_mode=non-pie ;; esac
            directory="$OUTPUT/executables/$probe/$lane/$mode"
            root="$OUTPUT/roots/$probe/$lane/$mode"
            mkdir -p "$directory"
            plugin="$directory/libloader-structural-owner-plugin.so"
            consumer="$directory/consumer"
            if [ "$lane" = candidate ]; then
                record "$probe-$lane-$mode-link" "$DYNAMIC_DRIVER" "--dynamic-$link_mode" -pthread "$object" -o "$consumer"
                prepare_candidate_root "$root" "$consumer" "$OUTPUT/plugins/candidate-plugin.so"
            else
                flags=(-fPIE -pie)
                [ "$link_mode" = pie ] || flags=(-fno-pie -no-pie)
                record "$probe-$lane-$mode-link" "$ORACLE_CC" -pthread "${flags[@]}" \
                    -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 "$object" -o "$consumer"
                prepare_pinned_root "$root" "$consumer" "$OUTPUT/plugins/pinned-musl-plugin.so"
            fi
            capture_root "$probe" "$lane" "$mode" before "$root"
            case "$lane/$mode" in
                candidate/*-kernel) record "$probe-$lane-$mode-run" "$TIMEOUT" 30 "$CHROOT" "$root" /consumer ;;
                candidate/*-direct) record "$probe-$lane-$mode-run" "$TIMEOUT" 30 "$CHROOT" "$root" /lib/ld-crabc-x86_64.so.1 /consumer ;;
                pinned-musl-1.2.6/*-kernel) record "$probe-$lane-$mode-run" "$TIMEOUT" 30 "$CHROOT" "$root" /consumer ;;
                pinned-musl-1.2.6/*-direct) record "$probe-$lane-$mode-run" "$TIMEOUT" 30 "$CHROOT" "$root" /lib/ld-musl-x86_64.so.1 /consumer ;;
            esac
            capture_root "$probe" "$lane" "$mode" after "$root"
        done
    done
done

python3 -B "$READER" collect-report --root "$ROOT" --output "$OUTPUT" --image "$IMAGE" \
    --static-product "$STATIC_PRODUCT" --dynamic-product "$DYNAMIC_PRODUCT" \
    --static-preparation "$STATIC_PREPARATION" --base-inventory "$BASE_INVENTORY" --full-facts "$FULL_FACTS" \
    --loader-debug-report "$LOADER_DEBUG_REPORT" --loader-runtime-registry-report "$LOADER_RUNTIME_REGISTRY_REPORT" \
    --oracle-compiler "$ORACLE_CC" --musl-shared "$MUSL_SHARED"
python3 -B "$READER" validate-report "$OUTPUT/report.json" --root "$ROOT" \
    --static-product "$STATIC_PRODUCT" --dynamic-product "$DYNAMIC_PRODUCT" \
    --static-preparation "$STATIC_PREPARATION" --base-inventory "$BASE_INVENTORY" --full-facts "$FULL_FACTS" \
    --loader-debug-report "$LOADER_DEBUG_REPORT" --loader-runtime-registry-report "$LOADER_RUNTIME_REGISTRY_REPORT" \
    --oracle-compiler "$ORACLE_CC" --musl-shared "$MUSL_SHARED"
printf 'loader structural-owner component: PASS (%s)\n' "$OUTPUT"
