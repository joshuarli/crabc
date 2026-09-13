#!/usr/bin/env bash
# Installed native x86 errno/h_errno storage lifecycle evidence.
#
# A static workload object and a dynamic workload object are each compiled
# through the supplied installed candidate headers.  Each stays unchanged while
# it crosses the pinned-musl/candidate provider boundary.  The dynamic workload
# dlopens a separately linked DSO that uses only public accessors.
set -euo pipefail
ulimit -c 0
export LC_ALL=C

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly READER="$ROOT/compat/x86_64/owned_errno_storage_lifecycle.py"
readonly PROBE="$ROOT/compat/x86_64/owned_errno_storage_lifecycle_probe.c"
readonly DSO="$ROOT/compat/x86_64/owned_errno_storage_lifecycle_dso.c"
readonly DOC="$ROOT/compat/x86_64/owned-errno-storage-lifecycle.md"
readonly ERRNO_SOURCE="$ROOT/libc/src/c_abi/x86_64/errno.rs"
readonly H_ERRNO_SOURCE="$ROOT/libc/src/c_abi/x86_64/h_errno.rs"
readonly PTHREAD_SOURCE="$ROOT/libc/src/c_abi/x86_64/pthread_create_join.rs"
readonly PRODUCT_VALIDATOR="$ROOT/compat/x86_64/owned_posix_product_evidence.py"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly MUSL_ARCHIVE="$MUSL_ROOT/lib/libc.a"
readonly MUSL_LIBRARY="$MUSL_ROOT/lib/libc.so"
readonly MUSL_LOADER=/lib/ld-musl-x86_64.so.1
readonly CRABC_LOADER=/lib/ld-crabc-x86_64.so.1
readonly TIMEOUT=30
readonly EXPECTED_OUTPUT='errno-storage-lifecycle: PASS'

usage() {
    printf 'usage: %s --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned errno/h_errno storage lifecycle: %s\n' "$*" >&2
    exit 1
}

static_product=''
dynamic_product=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$static_product" ] && [ -n "$2" ] || usage
            static_product="$2"
            shift 2
            ;;
        -*) usage ;;
        *)
            [ -z "$dynamic_product" ] && [ -n "$1" ] || usage
            dynamic_product="$1"
            shift
            ;;
    esac
done
[ -n "$static_product" ] && [ -n "$dynamic_product" ] || usage

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -n "${TMPDIR:-}" ] || fail 'requires explicit checkout-local TMPDIR'
for tool in chroot cmp cp env git grep mkdir mktemp python3 readelf realpath sha256sum timeout; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
[ -f "$MUSL_ARCHIVE" ] && [ -f "$MUSL_LIBRARY" ] || fail 'missing pinned musl archive/shared library'
for path in "$READER" "$PROBE" "$DSO" "$DOC" "$ERRNO_SOURCE" "$H_ERRNO_SOURCE" \
            "$PTHREAD_SOURCE" "$PRODUCT_VALIDATOR"; do
    [ -f "$path" ] || fail "missing errno storage input: $path"
done

work_parent="$(realpath -e "$TMPDIR")"
case "$work_parent" in "$ROOT"/.work/*) ;; *) fail 'TMPDIR must remain below this checkout .work' ;; esac
[ ! -L "$work_parent" ] || fail 'TMPDIR must be physical'
[ "$(git rev-parse --show-toplevel)" = "$ROOT" ] || fail 'runner must execute from its checkout'
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] ||
    fail 'source must be clean before a source-bound installed-product proof'

static_product="$(realpath -e "$static_product")"
dynamic_product="$(realpath -e "$dynamic_product")"
for product in "$static_product" "$dynamic_product"; do
    [ -d "$product" ] && [ ! -L "$product" ] || fail "product root must be a physical directory: $product"
done
[ -x "$static_product/bin/crabc-cc" ] || fail 'static product lacks installed driver'
[ -x "$dynamic_product/bin/crabc-cc-dynamic" ] || fail 'dynamic product lacks installed driver'

python3 -B - "$ROOT" "$static_product" "$dynamic_product" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
static = Path(sys.argv[2])
dynamic = Path(sys.argv[3])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_posix_product_evidence as products

products._validate_static_product(static)
products._validate_dynamic_product(dynamic)
PY

work="$(mktemp -d "$work_parent/owned-errno-storage-lifecycle.XXXXXX")"
chmod a+rx "$work"
trap 'chmod -R a+rX "$work" 2>/dev/null || true' EXIT
printf 'owned errno/h_errno storage lifecycle evidence: %s\n' "$work"

record_argv() {
    local path="$1"
    shift
    python3 -B - "$path" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(
    json.dumps({'argv': sys.argv[2:]}, sort_keys=True, separators=(',', ':')) + '\n',
    encoding='utf-8',
)
PY
}

action() {
    local stem="$1"
    shift
    record_argv "$work/$stem.argv.json" "$@"
    local status
    set +e
    timeout "$TIMEOUT" "$@" >"$work/$stem.stdout" 2>"$work/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status; evidence: $work"
}

observe() {
    local stem="$1" output="$2"
    shift 2
    record_argv "$work/$stem.argv.json" "$@"
    local status
    set +e
    timeout "$TIMEOUT" "$@" >"$output" 2>"$work/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status; evidence: $work"
}

require_transcript() {
    local label="$1"
    [ "$(cat "$work/$label.stdout")" = "$EXPECTED_OUTPUT" ] ||
        fail "$label stdout drifted"
    [ ! -s "$work/$label.stderr" ] || fail "$label emitted stderr"
}

seal_object() {
    local name="$1" phase="$2"
    local object="$work/$name"
    record_argv "$work/$name.$phase.argv.json" sha256sum "$object"
    sha256sum "$object" >"$work/$name.$phase.sha256"
    printf '0\n' >"$work/$name.$phase.status"
    : >"$work/$name.$phase.stderr"
}

prepare_static_root() {
    local root="$1" executable="$2"
    mkdir -p "$root"
    cp "$executable" "$root/consumer"
}

prepare_oracle_root() {
    local root="$1" executable="$2"
    mkdir -p "$root/lib" "$root/usr/lib"
    cp "$MUSL_LIBRARY" "$root/lib/ld-musl-x86_64.so.1"
    cp "$MUSL_LIBRARY" "$root/usr/lib/libc.so"
    cp "$work/oracle-plugin.so" "$root/usr/lib/liberrno-storage-lifecycle-probe.so"
    cp "$executable" "$root/consumer"
}

prepare_candidate_root() {
    local root="$1" executable="$2"
    mkdir -p "$root"
    cp -a "$dynamic_product/." "$root/"
    mkdir -p "$root/usr/lib"
    cp "$work/candidate-plugin.so" "$root/usr/lib/liberrno-storage-lifecycle-probe.so"
    cp "$executable" "$root/consumer"
}

python3 -B "$READER" snapshot --root "$ROOT" --output "$work/source-before.json"

# The sealed dynamic driver intentionally does not offer diagnostic -H. Trace
# the exact supplied installed tree with the pinned compiler, then compile all
# workload objects only through that installed driver.
action installed-header-preprocess /usr/bin/clang --target=x86_64-linux-musl -std=c11 -nostdinc \
    -isystem "$dynamic_product/usr/include" -D_GNU_SOURCE -DCRABC_ERRNO_STORAGE_DYNAMIC_DSO -H -E "$PROBE"
for header in errno.h netdb.h pthread.h dlfcn.h; do
    grep -Fq "$dynamic_product/usr/include/$header" "$work/installed-header-preprocess.stderr" ||
        fail "workload did not include supplied installed $header"
done

action compile-core-static "$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie \
    -std=c11 -D_GNU_SOURCE -DCRABC_ERRNO_STORAGE_STATIC_ALIAS -fno-builtin -fno-stack-protector \
    -c "$PROBE" -o "$work/core-static.o"
action compile-core-dynamic "$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie \
    -std=c11 -D_GNU_SOURCE -DCRABC_ERRNO_STORAGE_DYNAMIC_DSO -fno-builtin -fno-stack-protector \
    -c "$PROBE" -o "$work/core-dynamic.o"
action compile-plugin "$dynamic_product/bin/crabc-cc-dynamic" --dynamic-shared-object \
    -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -c "$DSO" -o "$work/plugin.o"
for name in core-static.o core-dynamic.o plugin.o; do
    seal_object "$name" before
done

observe core-static-symbols "$work/core-static-symbols.txt" readelf -Ws "$work/core-static.o"
observe core-dynamic-symbols "$work/core-dynamic-symbols.txt" readelf -Ws "$work/core-dynamic.o"
observe plugin-symbols "$work/plugin-symbols.txt" readelf -Ws "$work/plugin.o"

# Pinned musl static-PIE output is retained as an ELF input but is not an
# execution oracle: even a zero-workload static-PIE binary from this pinned
# compiler faults before main in this native image. The ordinary static musl
# executable is the same-object behavior oracle; candidate static PIE runs.
action oracle-static-link "$ORACLE_CC" -static -no-pie -pthread "$work/core-static.o" \
    -Wl,-Map,"$work/oracle-static.map" -o "$work/oracle-static"
action candidate-static-link "$static_product/bin/crabc-cc" -static "$work/core-static.o" \
    -Wl,-Map,"$work/candidate-static.map" -o "$work/candidate-static"
action candidate-static-pie-link "$static_product/bin/crabc-cc" -static-pie "$work/core-static.o" \
    -Wl,-Map,"$work/candidate-static-pie.map" -o "$work/candidate-static-pie"

prepare_static_root "$work/oracle-static-root" "$work/oracle-static"
prepare_static_root "$work/candidate-static-root" "$work/candidate-static"
prepare_static_root "$work/candidate-static-pie-root" "$work/candidate-static-pie"
action oracle-static-exec chroot "$work/oracle-static-root" /consumer
require_transcript oracle-static-exec
action candidate-static-exec chroot "$work/candidate-static-root" /consumer
require_transcript candidate-static-exec
action candidate-static-pie chroot "$work/candidate-static-pie-root" /consumer
require_transcript candidate-static-pie

# Link one plugin object with each provider. Dynamic consumers load it by its
# contained absolute path; no application-DSO link edge preloads the witness.
action oracle-plugin-link "$ORACLE_CC" -shared -fPIC "$work/plugin.o" \
    -Wl,-soname,liberrno-storage-lifecycle-probe.so,-Map,"$work/oracle-plugin.map" \
    -o "$work/oracle-plugin.so"
action candidate-plugin-link "$dynamic_product/bin/crabc-cc-dynamic" --dynamic-shared-object \
    "$work/plugin.o" -Wl,-Map,"$work/candidate-plugin.map" -o "$work/candidate-plugin.so"

for mode in pie non-pie; do
    case "$mode" in
        pie) oracle_flags=(-fPIE -pie);;
        non-pie) oracle_flags=(-fno-pie -no-pie);;
    esac
    action "oracle-dynamic-$mode-link" "$ORACLE_CC" "${oracle_flags[@]}" -pthread "$work/core-dynamic.o" \
        -Wl,--dynamic-linker,"$MUSL_LOADER",-rpath,/usr/lib,-Map,"$work/oracle-dynamic-$mode.map" \
        -o "$work/oracle-dynamic-$mode"
    action "candidate-dynamic-$mode-link" "$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        "$work/core-dynamic.o" -Wl,-Map,"$work/candidate-dynamic-$mode.map" \
        -o "$work/candidate-dynamic-$mode"
done

for name in core-static.o core-dynamic.o plugin.o; do
    seal_object "$name" after
done

for mode in pie non-pie; do
    prepare_oracle_root "$work/oracle-dynamic-$mode-root" "$work/oracle-dynamic-$mode"
    prepare_candidate_root "$work/candidate-dynamic-$mode-root" "$work/candidate-dynamic-$mode"
    action "oracle-dynamic-$mode-kernel" chroot "$work/oracle-dynamic-$mode-root" /consumer
    require_transcript "oracle-dynamic-$mode-kernel"
    action "oracle-dynamic-$mode-direct" chroot "$work/oracle-dynamic-$mode-root" "$MUSL_LOADER" /consumer
    require_transcript "oracle-dynamic-$mode-direct"
    action "candidate-dynamic-$mode-kernel" chroot "$work/candidate-dynamic-$mode-root" /consumer
    require_transcript "candidate-dynamic-$mode-kernel"
    action "candidate-dynamic-$mode-direct" chroot "$work/candidate-dynamic-$mode-root" "$CRABC_LOADER" /consumer
    require_transcript "candidate-dynamic-$mode-direct"
done

observe oracle-static-symbols "$work/oracle-static-symbols.txt" readelf -Ws "$MUSL_ARCHIVE"
observe oracle-shared-symbols "$work/oracle-shared-symbols.txt" readelf -Ws "$MUSL_LIBRARY"
observe oracle-dynamic-symbols "$work/oracle-dynamic-symbols.txt" readelf --dyn-syms -W "$MUSL_LIBRARY"
observe candidate-static-symbols "$work/candidate-static-symbols.txt" readelf -Ws "$static_product/usr/lib/libc.a"
observe candidate-shared-symbols "$work/candidate-shared-symbols.txt" readelf -Ws "$dynamic_product/usr/lib/libc.so"
observe candidate-dynamic-symbols "$work/candidate-dynamic-symbols.txt" readelf --dyn-syms -W "$dynamic_product/usr/lib/libc.so"

python3 -B "$READER" snapshot --root "$ROOT" --output "$work/source-after.json"
action collect-receipt python3 -B "$READER" collect --root "$ROOT" --work "$work" \
    --static-product "$static_product" --dynamic-product "$dynamic_product" --output "$work/report.json"
action replay-receipt python3 -B "$READER" replay --root "$ROOT" --report "$work/report.json"
printf 'owned errno/h_errno storage lifecycle: PASS; evidence: %s\n' "$work"
