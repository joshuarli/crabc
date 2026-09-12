#!/usr/bin/env bash
# Native x86-64 musl locale/time weak-alias and internal-call proof.
#
# One C application object is compiled through installed candidate headers, then
# linked separately to pinned musl and the selected static/dynamic products.
# Its strong public replacements must link and run, while calls inside libc
# retain the source-selected private implementations.
set -euo pipefail
export LC_ALL=C

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/locale_alias_contract_probe.c"
readonly CONTRACT="$ROOT/compat/x86_64/locale_alias_contract.json"
readonly SYMBOLS="$ROOT/compat/x86_64/locale_alias_contract_symbols.py"
readonly TIMEOUT=20

usage() {
    printf 'usage: %s --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'locale alias contract: %s\n' "$*" >&2
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
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64, got $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires explicit checkout-local TMPDIR'
for tool in ar chroot cmp cp env grep mkdir mktemp readelf sha256sum timeout; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
[ -f "$PROBE" ] && [ -f "$CONTRACT" ] && [ -f "$SYMBOLS" ] ||
    fail 'missing probe, alias contract, or selected-symbol validator'

static_product="$(realpath -e "$static_product")"
dynamic_product="$(realpath -e "$dynamic_product")"
for path in "$static_product" "$dynamic_product"; do
    [ -d "$path" ] || fail "product is not a directory: $path"
    [ ! -L "$path" ] || fail "product root must be physical: $path"
done
[ -x "$static_product/bin/crabc-cc" ] || fail 'static product lacks installed driver'
[ -x "$dynamic_product/bin/crabc-cc-dynamic" ] || fail 'dynamic product lacks installed driver'

python3 -B - "$ROOT" "$static_product" "$dynamic_product" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
static = Path(sys.argv[2])
dynamic = Path(sys.argv[3])
sys.path.insert(0, str(root / "compat/x86_64"))
import owned_posix_product_evidence as products

products._validate_static_product(static)
products._validate_dynamic_product(dynamic)
PY

work="$(mktemp -d "$TMPDIR/locale-alias-contract.XXXXXX")"
chmod a+rx "$work"
trap 'chmod -R a+rX "$work" 2>/dev/null || true' EXIT
printf 'locale alias contract evidence: %s\n' "$work"

capture() {
    local stem="$1"
    shift
    python3 -B - "$work/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], separators=(",", ":")) + "\n",
                             encoding="utf-8")
PY
    local status
    set +e
    timeout "$TIMEOUT" "$@" >"$work/$stem.stdout" 2>"$work/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/$stem.status"
    [ "$status" -eq 0 ] || {
        printf 'locale alias contract: %s failed with %s; evidence: %s\n'             "$stem" "$status" "$work" >&2
        return 1
    }
}

snapshot() {
    local point="$1"
    sha256sum "$PROBE" "$CONTRACT" "$SYMBOLS" \
        "$static_product/usr/lib/libc.a" "$dynamic_product/usr/lib/libc.so" \
        >"$work/$point.sha256"
}

snapshot before
capture compile "$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11     -D_GNU_SOURCE -fno-builtin -fno-stack-protector -c "$PROBE" -o "$work/probe.o"

# The pinned wrapper's static-PIE specs do not select the self-relocating
# rcrt1.o used by the installed static driver.  As in the established static
# product harness, the ET_EXEC musl link supplies the reference transcript for
# this one installed-header object; the candidate static-PIE link remains an
# independently shaped and executed ET_DYN proof.
capture oracle-static-link "$ORACLE_CC" -static -no-pie "$work/probe.o" -o "$work/oracle-static"
capture candidate-static-link "$static_product/bin/crabc-cc" -static \
    "$work/probe.o" -o "$work/candidate-static"
capture candidate-static-pie-link "$static_product/bin/crabc-cc" -static-pie \
    "$work/probe.o" -o "$work/candidate-static-pie"
for mode in pie non-pie; do
    if [ "$mode" = pie ]; then
        oracle_flags=(-rdynamic -fPIE -pie)
    else
        oracle_flags=(-rdynamic -no-pie)
    fi
    capture "oracle-dynamic-$mode-link" "$ORACLE_CC" "${oracle_flags[@]}" "$work/probe.o" \
        -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -o "$work/oracle-dynamic-$mode"
    capture "candidate-dynamic-$mode-link" "$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -rdynamic "$work/probe.o" -o "$work/candidate-dynamic-$mode"
done

for executable in oracle-static candidate-static candidate-static-pie \
                  oracle-dynamic-pie oracle-dynamic-non-pie \
                  candidate-dynamic-pie candidate-dynamic-non-pie; do
    capture "$executable-header" readelf -h "$work/$executable"
done
require_elf_type() {
    local executable="$1"
    local expected="$2"
    grep -Eq "^[[:space:]]*Type:[[:space:]]+$expected\b" "$work/$executable-header.stdout" ||
        fail "$executable has wrong ELF type; expected $expected"
}
require_elf_type oracle-static EXEC
require_elf_type candidate-static EXEC
require_elf_type candidate-static-pie DYN
require_elf_type oracle-dynamic-pie DYN
require_elf_type oracle-dynamic-non-pie EXEC
require_elf_type candidate-dynamic-pie DYN
require_elf_type candidate-dynamic-non-pie EXEC

capture oracle-static-run env -i TZ=UTC "$work/oracle-static"
for mode in static static-pie; do
    capture "candidate-$mode-run" env -i TZ=UTC "$work/candidate-$mode"
    cmp "$work/oracle-static-run.stdout" "$work/candidate-$mode-run.stdout"
    cmp "$work/oracle-static-run.stderr" "$work/candidate-$mode-run.stderr"
    cmp "$work/oracle-static-run.status" "$work/candidate-$mode-run.status"
done

prepare_oracle_root() {
    local root="$1"
    mkdir -p "$root/lib"
    cp /opt/musl-1.2.6/lib/libc.so "$root/lib/ld-musl-x86_64.so.1"
    ln -s ld-musl-x86_64.so.1 "$root/lib/libc.so"
    for mode in pie non-pie; do
        cp "$work/oracle-dynamic-$mode" "$root/consumer-$mode"
    done
}

prepare_candidate_root() {
    local root="$1"
    cp -a "$dynamic_product/." "$root"
    for mode in pie non-pie; do
        cp "$work/candidate-dynamic-$mode" "$root/consumer-$mode"
    done
}

oracle_root="$work/oracle-dynamic-root"
candidate_root="$work/candidate-dynamic-root"
prepare_oracle_root "$oracle_root"
prepare_candidate_root "$candidate_root"

for mode in pie non-pie; do
    for entry in kernel direct; do
        if [ "$entry" = kernel ]; then
            capture "oracle-dynamic-$mode-$entry" chroot "$oracle_root" "/consumer-$mode"
            capture "candidate-dynamic-$mode-$entry" chroot "$candidate_root" "/consumer-$mode"
        else
            capture "oracle-dynamic-$mode-$entry" chroot "$oracle_root" \
                /lib/ld-musl-x86_64.so.1 "/consumer-$mode"
            capture "candidate-dynamic-$mode-$entry" chroot "$candidate_root" \
                /lib/ld-crabc-x86_64.so.1 "/consumer-$mode"
        fi
        cmp "$work/oracle-dynamic-$mode-$entry.stdout" \
            "$work/candidate-dynamic-$mode-$entry.stdout"
        cmp "$work/oracle-dynamic-$mode-$entry.stderr" \
            "$work/candidate-dynamic-$mode-$entry.stderr"
        cmp "$work/oracle-dynamic-$mode-$entry.status" \
            "$work/candidate-dynamic-$mode-$entry.status"
    done
done

capture oracle-static-symbols readelf -Ws /opt/musl-1.2.6/lib/libc.a
capture oracle-dynamic-symbols readelf --dyn-syms -W /opt/musl-1.2.6/lib/libc.so
capture oracle-shared-symbols readelf -Ws /opt/musl-1.2.6/lib/libc.so
capture candidate-static-symbols readelf -Ws "$static_product/usr/lib/libc.a"
capture candidate-dynamic-symbols readelf --dyn-syms -W "$dynamic_product/usr/lib/libc.so"
capture candidate-shared-symbols readelf -Ws "$dynamic_product/usr/lib/libc.so"
capture executable-dynamic-pie-symbols readelf --dyn-syms -W "$work/candidate-dynamic-pie"
capture executable-dynamic-non-pie-symbols readelf --dyn-syms -W "$work/candidate-dynamic-non-pie"
capture alias-symbol-observation python3 -B "$SYMBOLS" \
    "$CONTRACT" \
    "$work/oracle-static-symbols.stdout" \
    "$work/oracle-dynamic-symbols.stdout" \
    "$work/oracle-shared-symbols.stdout" \
    "$work/candidate-static-symbols.stdout" \
    "$work/candidate-dynamic-symbols.stdout" \
    "$work/candidate-shared-symbols.stdout" \
    "$work/executable-dynamic-pie-symbols.stdout" \
    "$work/executable-dynamic-non-pie-symbols.stdout" \
    "$work/alias-observation.json"

snapshot after
cmp "$work/before.sha256" "$work/after.sha256" ||
    fail 'probe, contract, or supplied product changed during the proof'
printf 'locale alias contract: PASS (one installed-header object; static ET_EXEC/static-PIE and dynamic PIE/non-PIE kernel/direct links; public overrides, retained internal calls, and selected .dynsym/.symtab observations); evidence: %s\n' "$work"
