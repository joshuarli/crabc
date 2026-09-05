#!/usr/bin/env bash
# Source-faithful owned VM mechanisms through each installed product.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_vm_mechanisms_probe.c"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }

provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
product_argument = sys.argv[3]
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned VM mechanisms TMPDIR must be a physical checkout .work directory")
if product_argument:
    product = Path(product_argument)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit("owned VM mechanisms product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-vm-mechanisms.XXXXXX")"
chmod a+rx "$work"
printf 'owned VM mechanisms evidence: %s\n' "$work"

run_in_root() {
    local root="$1" output="$2"
    shift 2
    mkdir -p "$root/tmp"
    timeout 30 env -i PATH="$PATH" chroot "$root" "$@" >"$output" 2>"${output%.stdout}.stderr"
}

assert_static_symbols() {
    local archive="$1" requested="$2" table symbol
    table="$work/static-symbols.txt"
    nm -g --defined-only "$archive" >"$table"
    for symbol in $requested; do
        [ "$(awk -v symbol="$symbol" '$3 == symbol { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned VM mechanisms: static symbol missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_dynamic_symbols() {
    local shared="$1" requested="$2" table symbol binding
    table="$work/dynamic-symbols.txt"
    readelf --dyn-syms -W "$shared" >"$table"
    for symbol in $requested; do
        binding=GLOBAL
        [ "$symbol" != mremap ] || binding=WEAK
        [ "$(awk -v symbol="$symbol" -v binding="$binding" '$4 == "FUNC" && $5 == binding && $6 == "DEFAULT" && $7 != "UND" && $8 == symbol { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned VM mechanisms: dynamic symbol missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

# Musl's mremap source keeps a hidden `__mremap` implementation and gives only
# its same-address public alias weak/default visibility. The other three
# source files define ordinary strong/default public entries. Static outputs
# retain both mremap spellings; the dynamic provider exports only the public
# one, so an application may interpose it without seeing the internal body.
assert_owned_vm_bindings() {
    local binary="$1" table="$2" output="$3"
    readelf --wide "$table" "$binary" >"$output"
    python3 -B - "$output" "$table" <<'PYTHON'
from pathlib import Path
import sys

records = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in {
        "__mremap", "mremap", "brk", "sbrk", "remap_file_pages",
    }:
        records.setdefault(fields[7], []).append(fields)

symbols = {}
for name, entries in records.items():
    # A shared object's full table repeats its dynamic symbols in `.symtab`.
    # Both records must describe the same binding rather than masking drift.
    assert all(entry[1:] == entries[0][1:] for entry in entries), (name, entries)
    symbols[name] = entries[0]

for name in ("brk", "sbrk", "remap_file_pages"):
    entry = symbols[name]
    assert entry[3:6] == ["FUNC", "GLOBAL", "DEFAULT"], entry
    assert entry[6] != "UND", entry

public = symbols["mremap"]
assert public[3:6] == ["FUNC", "WEAK", "DEFAULT"], public
assert public[6] != "UND", public
if sys.argv[2] == "--dyn-syms":
    assert "__mremap" not in symbols, symbols
else:
    internal = symbols["__mremap"]
    # Linkers may localize a hidden static-final symbol, but it remains the
    # same hidden function at the weak alias's address and is never exported.
    assert internal[3] == "FUNC" and internal[5] == "HIDDEN", internal
    assert internal[1:3] == public[1:3] and internal[6] == public[6], (internal, public)
PYTHON
}

# Both dynamic application modes must retain normal preemptible PLT imports.
# A direct local binding would defeat the weak public mremap alias and would
# also blur the strong source entry points with a product-private wrapper.
assert_dynamic_vm_imports() {
    local binary="$1" symbols="$2" relocations="$3"
    readelf --wide --dyn-syms "$binary" >"$symbols"
    readelf --wide --relocs "$binary" >"$relocations"
    python3 -B - "$symbols" "$relocations" <<'PYTHON'
from pathlib import Path
import sys

requested = ("mremap", "brk", "sbrk", "remap_file_pages")
symbols = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in requested:
        assert fields[7] not in symbols, (fields[7], symbols[fields[7]], fields)
        symbols[fields[7]] = fields
for name in requested:
    entry = symbols[name]
    assert entry[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and entry[6] == "UND", entry
    assert f"R_X86_64_JUMP_SLOT" in Path(sys.argv[2]).read_text() and any(
        f"{name} + 0" in line and "R_X86_64_JUMP_SLOT" in line
        for line in Path(sys.argv[2]).read_text().splitlines()
    ), name
PYTHON
}

assert_owned_vm_wait() {
    local binary="$1" symbol="$2" disassembly
    disassembly="$work/${symbol}-owned-vmlock-disassembly.txt"
    objdump -d --disassemble="$symbol" "$binary" >"$disassembly"
    grep -Eq '\$0xca(,|[[:space:]]|$)' "$disassembly" || {
        printf 'owned VM mechanisms: %s lacks the selected vmlock futex syscall\n' "$symbol" >&2
        return 1
    }
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" || {
        printf 'owned VM mechanisms: %s lacks a selected VM wait syscall instruction\n' "$symbol" >&2
        return 1
    }
}

if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"
readonly owned_symbols='brk mremap remap_file_pages sbrk'

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
assert_owned_vm_bindings "$work/oracle" --syms "$work/oracle-vm-bindings.txt"
mkdir -p "$work/oracle-root"
cp "$work/oracle" "$work/oracle-root/consumer"
run_in_root "$work/oracle-root" "$work/oracle.stdout" /consumer
grep -qx owned-vm-mechanisms-ok "$work/oracle.stdout"

if [ "$#" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
    assert_static_symbols "$work/static-product/usr/lib/libc.a" "$owned_symbols"
    assert_owned_vm_bindings "$work/static-product/usr/lib/libc.a" --syms "$work/static-archive-vm-bindings.txt"
    for mode in static static-pie; do
        "$work/static-product/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/consumer-$mode"
        assert_owned_vm_bindings "$work/consumer-$mode" --syms "$work/$mode-vm-bindings.txt"
        for symbol in mmap munmap mremap; do
            assert_owned_vm_wait "$work/consumer-$mode" "$symbol"
        done
        mkdir -p "$work/$mode-root"
        cp "$work/consumer-$mode" "$work/$mode-root/consumer"
        run_in_root "$work/$mode-root" "$work/$mode.stdout" /consumer
        cmp "$work/oracle.stdout" "$work/$mode.stdout"
    done
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so" "$owned_symbols"
assert_owned_vm_bindings "$installed/usr/lib/libc.so" --syms "$work/dynamic-provider-full-vm-bindings.txt"
assert_owned_vm_bindings "$installed/usr/lib/libc.so" --dyn-syms "$work/dynamic-provider-vm-bindings.txt"
for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/consumer-$mode"
    assert_dynamic_vm_imports "$work/consumer-$mode" "$work/$mode-vm-imports.txt" "$work/$mode-vm-relocations.txt"
    for entry in kernel direct; do
        root="$work/$mode-$entry-root"
        cp -a "$installed" "$root"
        cp "$work/consumer-$mode" "$root/consumer"
        if [ "$entry" = direct ]; then
            run_in_root "$root" "$work/$mode-$entry.stdout" /lib/ld-crabc-x86_64.so.1 /consumer
        else
            run_in_root "$root" "$work/$mode-$entry.stdout" /consumer
        fi
        cmp "$work/oracle.stdout" "$work/$mode-$entry.stdout"
    done
done

printf 'owned VM mechanisms: PASS (same workload object, pinned musl, static/static-PIE/dynamic PIE/non-PIE kernel/direct chroots, exact weak/hidden and strong ELF bindings with preemptible dynamic imports, emitted selected vmlock waits, resize/fixed/zero-size remaps, lifetime/protection/error behavior, musl break limit, and raw legacy-remap error translation); evidence: %s\n' "$work"
