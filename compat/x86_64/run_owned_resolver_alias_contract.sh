#!/usr/bin/env bash
# Current-product collector for the finite resolver alias/private-body receipt.
# It never builds a replacement runtime: all candidate links use the supplied
# sealed static/dynamic product drivers.
set -euo pipefail
export LC_ALL=C
export PATH=/opt/cargo/bin:/usr/bin:/bin

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly READER="$ROOT/compat/x86_64/owned_resolver_alias_contract_reader.py"
readonly PROBE="$ROOT/compat/x86_64/owned_resolver_alias_contract_probe.c"
readonly OVERRIDE_PROBE="$ROOT/compat/x86_64/owned_resolver_alias_override_probe.c"
readonly OVERRIDE_CALLER="$ROOT/compat/x86_64/owned_resolver_alias_override_caller.c"
readonly HEADER_C="$ROOT/compat/x86_64/resolver_runtime_header_abi_probe.c"
readonly HEADER_CPP="$ROOT/compat/x86_64/resolver_runtime_header_abi_probe.cpp"
readonly RAW_HEADER_COMPILER=/usr/bin/gcc
readonly READELF=/usr/bin/readelf
readonly TIMEOUT=/usr/bin/timeout
readonly CHROOT=/usr/sbin/chroot
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly MUSL_SHARED=/opt/musl-1.2.6/lib/libc.so
readonly IMAGE='crabc-core-evidence@sha256:307d75f06680c631437f9faa5f7c726613fcea6f1875dda8cf368ad4b6da1b3d'

fail() { printf 'owned resolver alias receipt: %s\n' "$*" >&2; exit 1; }

STATIC_PRODUCT=''
DYNAMIC_PRODUCT=''
STATIC_PREPARATION=''
PRODUCT_REPORT=''
ELF_FACTS=''
BASE_INVENTORY=''
RECEIPT_DIR=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-product|--dynamic-product|--static-preparation|--product-report|--elf-facts|--base-inventory|--receipt-dir)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            case "$1" in
                --static-product) STATIC_PRODUCT="$2" ;;
                --dynamic-product) DYNAMIC_PRODUCT="$2" ;;
                --static-preparation) STATIC_PREPARATION="$2" ;;
                --product-report) PRODUCT_REPORT="$2" ;;
                --elf-facts) ELF_FACTS="$2" ;;
                --base-inventory) BASE_INVENTORY="$2" ;;
                --receipt-dir) RECEIPT_DIR="$2" ;;
            esac
            shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
for value in "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$STATIC_PREPARATION" "$PRODUCT_REPORT" "$ELF_FACTS" "$BASE_INVENTORY" "$RECEIPT_DIR"; do
    [ -n "$value" ] || fail 'all selected product, measurement, and receipt arguments are required'
done

python3 -B - "$ROOT" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$STATIC_PREPARATION" \
    "$PRODUCT_REPORT" "$ELF_FACTS" "$BASE_INVENTORY" "$RECEIPT_DIR" <<'PY'
from pathlib import Path
import os
import stat
import sys

root_raw = Path(sys.argv[1])
if root_raw.is_symlink():
    raise SystemExit(f'resolver alias checkout root may not be a symlink: {root_raw}')
root = root_raw.resolve(strict=True)
raw_values = [Path(item) for item in sys.argv[2:8]]
for raw in raw_values:
    if raw.is_symlink():
        raise SystemExit(f'resolver alias input may not be a symlink: {raw}')
values = [item.resolve(strict=True) for item in raw_values]
receipt_raw = Path(sys.argv[8])
if receipt_raw.is_symlink():
    raise SystemExit('resolver alias receipt directory may not be a symlink')
receipt = receipt_raw.resolve(strict=False)
for path in values:
    if not path.is_relative_to(root / '.work'):
        raise SystemExit(f'resolver alias input must be below checkout .work: {path}')
if receipt.exists() or not receipt.is_relative_to(root / '.work'):
    raise SystemExit('resolver alias receipt directory must be a new checkout .work directory')
static, dynamic = values[:2]
for path in (static / 'bin/crabc-cc', static / 'usr/lib/libc.a', static / 'usr/lib/crt1.o',
             static / 'usr/lib/rcrt1.o', static / 'usr/lib/crti.o', static / 'usr/lib/crtn.o',
             static / 'usr/lib/libcrabc-builtins.a', dynamic / 'bin/crabc-cc-dynamic',
             dynamic / 'usr/lib/libc.so', dynamic / 'lib/ld-crabc-x86_64.so.1',
             dynamic / 'usr/lib/crt1.o', dynamic / 'usr/lib/Scrt1.o', dynamic / 'usr/lib/crti.o',
             dynamic / 'usr/lib/crtn.o', dynamic / 'usr/lib/crabc-dynamic-attach.o',
             dynamic / 'usr/lib/libcrabc-builtins.a'):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f'resolver alias selected product file is not physical: {path}')
if static == dynamic or static in dynamic.parents or dynamic in static.parents:
    raise SystemExit('resolver alias selected product roots overlap')
PY

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ "$(id -u)" -eq 0 ] || fail 'requires root for the local resolver fixture chroot'
for tool in cp mkdir python3 rm; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
[ "${CRABC_RESOLVER_ALIAS_IMAGE_ID:-}" = "$IMAGE" ] ||
    fail 'collector is not bound to the pinned core evidence image'
for tool in "$RAW_HEADER_COMPILER" "$READELF" "$TIMEOUT" "$CHROOT" "$ORACLE_CC"; do
    [ -x "$tool" ] || fail "missing pinned command program: $tool"
done
[ -f "$MUSL_ARCHIVE" ] && [ -f "$MUSL_SHARED" ] || fail 'missing pinned musl oracle files'

readonly STATIC_PRODUCT="$(realpath -e "$STATIC_PRODUCT")"
readonly DYNAMIC_PRODUCT="$(realpath -e "$DYNAMIC_PRODUCT")"
readonly STATIC_PREPARATION="$(realpath -e "$STATIC_PREPARATION")"
readonly PRODUCT_REPORT="$(realpath -e "$PRODUCT_REPORT")"
readonly ELF_FACTS="$(realpath -e "$ELF_FACTS")"
readonly BASE_INVENTORY="$(realpath -e "$BASE_INVENTORY")"
readonly RECEIPT_DIR="$(realpath -m "$RECEIPT_DIR")"
readonly STATIC_DRIVER="$STATIC_PRODUCT/bin/crabc-cc"
readonly DYNAMIC_DRIVER="$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic"
readonly DYNAMIC_LOADER=/lib/ld-crabc-x86_64.so.1

mkdir "$RECEIPT_DIR"
readonly WORK="$RECEIPT_DIR"
mkdir -p "$WORK/commands" "$WORK/objects" "$WORK/outputs" "$WORK/runtime" "$WORK/roots"
chmod 0755 "$WORK" "$WORK/commands" "$WORK/objects" "$WORK/outputs" "$WORK/runtime" "$WORK/roots"
cd "$WORK"

# Admission and retained input capture happen before the first compiler,
# linker, inspection, or runtime command. Final sealing rejects any later
# source/product/measurement change rather than copying a later cohort.
python3 -B "$READER" --begin-collection --root "$ROOT" --work "$WORK" \
    --static-product "$STATIC_PRODUCT" --dynamic-product "$DYNAMIC_PRODUCT" \
    --static-preparation "$STATIC_PREPARATION" --product-report "$PRODUCT_REPORT" \
    --elf-facts "$ELF_FACTS" --base-inventory "$BASE_INVENTORY" --image "$IMAGE"

record() {
    local name="$1"; shift
    python3 -B - "$WORK/commands/$name.argv.json" "$WORK" "$PATH" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps({
    'argv': sys.argv[4:],
    'cwd': sys.argv[2],
    'environment': {'LC_ALL': 'C', 'PATH': sys.argv[3]},
    'stdin': '/dev/null',
}, sort_keys=True) + '\n', encoding='utf-8')
PY
    local status=0
    "$@" >"$WORK/commands/$name.stdout" 2>"$WORK/commands/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$WORK/commands/$name.status"
    [ "$status" -eq 0 ] || fail "command failed: $name (status $status; retained at $WORK/commands)"
}

capture_runtime_root() {
    local name="$1" phase="$2" root="$3"
    python3 -B "$READER" --capture-runtime-root --work "$WORK" \
        --runtime-root-name "$name" --runtime-root-phase "$phase" --runtime-root "$root" >/dev/null
}

prepare_fixture() {
    local fixture="$1"
    mkdir -p "$fixture/etc"
    chmod 00755 "$fixture" "$fixture/etc"
    printf '%s\n' '192.0.2.44 host.fixture host-alias' >"$fixture/etc/hosts"
    printf '%s\n' 'nameserver 127.0.0.1' 'search fixture.test' 'options ndots:1 timeout:1 attempts:1' >"$fixture/etc/resolv.conf"
    chmod 0644 "$fixture/etc/hosts" "$fixture/etc/resolv.conf"
}

prepare_dynamic_root() {
    local root="$1" executable="$2"
    mkdir -p "$root/lib" "$root/usr/lib" "$root/fixture"
    chmod 00755 "$root" "$root/lib" "$root/usr" "$root/usr/lib" "$root/fixture"
    cp "$DYNAMIC_PRODUCT/lib/ld-crabc-x86_64.so.1" "$root/lib/ld-crabc-x86_64.so.1"
    cp "$DYNAMIC_PRODUCT/usr/lib/libc.so" "$root/usr/lib/libc.so"
    cp "$executable" "$root/contract"
    prepare_fixture "$root/fixture"
}

# Header ABI is a source check through the pinned raw compiler. `-nostdinc`
# and `-nostdinc++` admit only the selected installed header root; the sealed
# dynamic driver deliberately remains link-only.
record header-c "$RAW_HEADER_COMPILER" -x c -std=c11 -nostdinc -I "$DYNAMIC_PRODUCT/usr/include" \
    -U_GNU_SOURCE -D_GNU_SOURCE -fno-builtin \
    -fsyntax-only "$HEADER_C"
record header-cpp "$RAW_HEADER_COMPILER" -x c++ -std=c++17 -nostdinc -nostdinc++ \
    -I "$DYNAMIC_PRODUCT/usr/include" \
    -U_GNU_SOURCE -D_GNU_SOURCE -fno-builtin -c -o "$WORK/objects/header.cpp.o" "$HEADER_CPP"
# Compile this public-caller object once. Every normal oracle/static/dynamic
# link consumes these exact bytes; no lane silently recompiles it.
record compile-public-probe "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -c "$PROBE" -o "$WORK/objects/public-probe.o"
record public-probe-relocations "$READELF" --relocs --wide "$WORK/objects/public-probe.o"
# Keep the public caller and the strong replacement in separate translation
# units. The relocation streams below therefore prove the compiler emitted a
# public call before the supplied product links resolve it.
record compile-override-mkquery "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -DCRABC_RESOLVER_ALIAS_OVERRIDE=1 \
    -c "$OVERRIDE_PROBE" -o "$WORK/objects/override-mkquery-definition.o"
record compile-override-mkquery-caller "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -DCRABC_RESOLVER_ALIAS_OVERRIDE=1 \
    -c "$OVERRIDE_CALLER" -o "$WORK/objects/override-mkquery-caller.o"
record override-mkquery-public-relocation "$READELF" --relocs --wide "$WORK/objects/override-mkquery-caller.o"
record compile-override-send "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -DCRABC_RESOLVER_ALIAS_OVERRIDE=2 \
    -c "$OVERRIDE_PROBE" -o "$WORK/objects/override-send-definition.o"
record compile-override-send-caller "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -DCRABC_RESOLVER_ALIAS_OVERRIDE=2 \
    -c "$OVERRIDE_CALLER" -o "$WORK/objects/override-send-caller.o"
record override-send-public-relocation "$READELF" --relocs --wide "$WORK/objects/override-send-caller.o"
record compile-override-search "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -DCRABC_RESOLVER_ALIAS_OVERRIDE=3 \
    -c "$OVERRIDE_PROBE" -o "$WORK/objects/override-search-definition.o"
record compile-override-search-caller "$DYNAMIC_DRIVER" --dynamic-pie -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -DCRABC_RESOLVER_ALIAS_OVERRIDE=3 \
    -c "$OVERRIDE_CALLER" -o "$WORK/objects/override-search-caller.o"
record override-search-public-relocation "$READELF" --relocs --wide "$WORK/objects/override-search-caller.o"

record oracle-symbols "$READELF" --symbols --wide "$MUSL_ARCHIVE"
record oracle-runtime-link "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector -I "$ROOT/include" \
    "$WORK/objects/public-probe.o" -o "$WORK/outputs/oracle-contract"
prepare_fixture "$WORK/runtime/oracle-root"
capture_runtime_root oracle before "$WORK/runtime/oracle-root"
record oracle-runtime-run "$TIMEOUT" 15 "$WORK/outputs/oracle-contract" "$WORK/runtime/oracle-root"
capture_runtime_root oracle after "$WORK/runtime/oracle-root"

record static-symbols "$READELF" --symbols --wide "$STATIC_PRODUCT/usr/lib/libc.a"
record static-private-calls "$READELF" --relocs --wide "$STATIC_PRODUCT/usr/lib/libc.a"
prepare_fixture "$WORK/runtime/static-root"
record static-normal-et-exec-link "$STATIC_DRIVER" -static -pthread "$WORK/objects/public-probe.o" \
    --link-receipt static-contract.link.json -o "$WORK/outputs/static-contract"
capture_runtime_root static-et-exec before "$WORK/runtime/static-root"
record static-normal-et-exec-runtime "$TIMEOUT" 15 "$WORK/outputs/static-contract" "$WORK/runtime/static-root"
capture_runtime_root static-et-exec after "$WORK/runtime/static-root"
record static-normal-pie-link "$STATIC_DRIVER" -static-pie -pthread "$WORK/objects/public-probe.o" \
    --link-receipt static-pie-contract.link.json -o "$WORK/outputs/static-pie-contract"
prepare_fixture "$WORK/runtime/static-pie-root"
capture_runtime_root static-pie before "$WORK/runtime/static-pie-root"
record static-normal-pie-runtime "$TIMEOUT" 15 "$WORK/outputs/static-pie-contract" "$WORK/runtime/static-pie-root"
capture_runtime_root static-pie after "$WORK/runtime/static-pie-root"

record dynamic-symbols "$READELF" --symbols --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so"
record dynamic-normal-pie-link "$DYNAMIC_DRIVER" --dynamic-pie -pthread -rdynamic "$WORK/objects/public-probe.o" \
    -o "$WORK/outputs/dynamic-pie-contract"
record dynamic-normal-pie-dynsym "$READELF" --dyn-syms --wide "$WORK/outputs/dynamic-pie-contract"
prepare_dynamic_root "$WORK/roots/dynamic-pie" "$WORK/outputs/dynamic-pie-contract"
capture_runtime_root dynamic-pie before "$WORK/roots/dynamic-pie"
record dynamic-normal-pie-runtime "$CHROOT" "$WORK/roots/dynamic-pie" /contract /fixture
capture_runtime_root dynamic-pie after "$WORK/roots/dynamic-pie"
record dynamic-normal-nopie-link "$DYNAMIC_DRIVER" --dynamic-non-pie -pthread -rdynamic "$WORK/objects/public-probe.o" \
    -o "$WORK/outputs/dynamic-non-pie-contract"
record dynamic-normal-nopie-dynsym "$READELF" --dyn-syms --wide "$WORK/outputs/dynamic-non-pie-contract"
prepare_dynamic_root "$WORK/roots/dynamic-non-pie" "$WORK/outputs/dynamic-non-pie-contract"
capture_runtime_root dynamic-non-pie before "$WORK/roots/dynamic-non-pie"
record dynamic-normal-nopie-runtime "$CHROOT" "$WORK/roots/dynamic-non-pie" "$DYNAMIC_LOADER" /contract /fixture
capture_runtime_root dynamic-non-pie after "$WORK/roots/dynamic-non-pie"

for name in mkquery send search; do
    record "static-override-$name" "$STATIC_DRIVER" -static -pthread \
        "$WORK/objects/override-$name-caller.o" "$WORK/objects/override-$name-definition.o" \
        --link-receipt "static-override-$name.link.json" -o "$WORK/outputs/static-override-$name"
    record "static-override-$name-runtime" "$WORK/outputs/static-override-$name"
    record "dynamic-override-$name" "$DYNAMIC_DRIVER" --dynamic-pie -pthread -rdynamic \
        "$WORK/objects/override-$name-caller.o" "$WORK/objects/override-$name-definition.o" \
        -o "$WORK/outputs/dynamic-override-$name"
    record "dynamic-override-$name-dynsym" "$READELF" --dyn-syms --wide "$WORK/outputs/dynamic-override-$name"
    prepare_dynamic_root "$WORK/roots/dynamic-override-$name" "$WORK/outputs/dynamic-override-$name"
    capture_runtime_root "dynamic-override-$name" before "$WORK/roots/dynamic-override-$name"
    record "dynamic-override-$name-runtime" "$CHROOT" "$WORK/roots/dynamic-override-$name" /contract
    capture_runtime_root "dynamic-override-$name" after "$WORK/roots/dynamic-override-$name"
done

# The reader seals the pre-execution component/product/source capture only if
# every selected current input still matches, then immediately performs replay.
python3 -B "$READER" --collect-report --root "$ROOT" --work "$WORK" \
    --static-product "$STATIC_PRODUCT" --dynamic-product "$DYNAMIC_PRODUCT" \
    --static-preparation "$STATIC_PREPARATION" --product-report "$PRODUCT_REPORT" \
    --elf-facts "$ELF_FACTS" --base-inventory "$BASE_INVENTORY" --image "$IMAGE"
python3 -B "$READER" --validate-report "$WORK/report.json" --root "$ROOT" \
    --static-product "$STATIC_PRODUCT" --dynamic-product "$DYNAMIC_PRODUCT" \
    --static-preparation "$STATIC_PREPARATION" --product-report "$PRODUCT_REPORT" \
    --elf-facts "$ELF_FACTS" --base-inventory "$BASE_INVENTORY"
printf 'owned resolver alias component receipt: PASS (%s)\n' "$WORK"
