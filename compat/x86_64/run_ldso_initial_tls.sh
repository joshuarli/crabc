#!/usr/bin/env bash
# Native evidence for the fixed x86 Variant-II initial-TLS interpreter graph.
#
# This is deliberately a sibling of `run_ldso_initial_graph.sh`: the older
# graph continues to prove its no-TLS relocation/RELRO contract unchanged,
# while this runner makes the next loader boundary explicit.  The candidate
# interpreter must own the PT_TLS images for two DSOs and resolve the GNU
# dynamic TLS module/offset pair without selecting an ambient libc or loader.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE="$ROOT_DIR/ldso/src/x86_64_initial_graph.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_tls_leaf.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_tls_mid.c"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_initial_tls_main.c"
readonly MUSL_LOADER="/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
readonly MUSL_LIBC_ARCHIVE="/opt/musl-1.2.6/lib/libc.a"

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: initial-TLS evidence requires native Linux/x86-64' >&2
    exit 2
fi
if [ ! -x "$MUSL_LOADER" ] || [ ! -f "$MUSL_LIBC_ARCHIVE" ]; then
    printf '%s\n' 'ERROR: the pinned musl 1.2.6 loader and static archive are required' >&2
    exit 2
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"

work_dir="$(mktemp -d)"
if [ "${CRABC_LDSO_INITIAL_TLS_KEEP_WORK:-0}" = 1 ]; then
    printf '%s\n' "retained initial-TLS work directory: $work_dir" >&2
else
    trap 'rm -rf "$work_dir"' EXIT
fi

# The interpreter itself stays TLS-free: it owns application TLS explicitly
# and must not accidentally inherit a host thread-runtime contract.
rustc --edition=2021 --crate-type staticlib --cfg crabc_initial_tls_graph -C panic=abort -C relocation-model=pic \
    "$SOURCE" -o "$work_dir/libinitial_tls_graph.a"
cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
    -Wl,--whole-archive "$work_dir/libinitial_tls_graph.a" -Wl,--no-whole-archive \
    -o "$work_dir/ld-crabc-x86_64-initial-tls.so"

interpreter_program_headers="$(readelf -lW "$work_dir/ld-crabc-x86_64-initial-tls.so")"
if grep -Fq ' TLS ' <<<"$interpreter_program_headers"; then
    printf '%s\n' 'ERROR: candidate interpreter unexpectedly selected PT_TLS' >&2
    exit 1
fi
interpreter_dynamic="$(readelf -dW "$work_dir/ld-crabc-x86_64-initial-tls.so")"
if grep -Eq '\(NEEDED\)|\(INTERP\)' <<<"$interpreter_dynamic"; then
    printf '%s\n' 'ERROR: candidate interpreter selected an external runtime' >&2
    exit 1
fi

cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf-tls.so "$LEAF" -o "$work_dir/libleaf-tls.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libmid-tls.so -Wl,-rpath,"$work_dir" "$MID" \
    -L"$work_dir" -Wl,--no-as-needed -l:libleaf-tls.so -o "$work_dir/libmid-tls.so"

build_main() {
    local interpreter="$1"
    local output="$2"
    local mode="$3"
    local -a linker_inputs
    case "$mode" in
        # The bare reference graph has no libc DT_NEEDED edge.  Force exactly
        # musl's static __tls_get_addr object into the reference main so its
        # DTV lookup remains a pinned-oracle implementation rather than a
        # harness reimplementation. The candidate receives no such input.
        musl-reference) linker_inputs=(-Wl,-u,__tls_get_addr "$MUSL_LIBC_ARCHIVE") ;;
        # The candidate main directly probes the private resolver's invalid
        # module/offset behavior. Permit that one executable import at link
        # time; the checks below require it to remain exactly an undefined
        # `__tls_get_addr` symbol resolved only by the candidate interpreter.
        candidate) linker_inputs=(-DCRABC_CANDIDATE_TLS_LAYOUT -Wl,--unresolved-symbols=ignore-all) ;;
        *)
            printf '%s\n' "ERROR: unknown initial-TLS main mode: $mode" >&2
            exit 1
            ;;
    esac
    cc -nostdlib -fPIE -pie -mtls-dialect=gnu -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
        -Wl,--dynamic-linker,"$interpreter" -Wl,-rpath,"$work_dir" \
        "$START" "$MAIN" -L"$work_dir" -Wl,--no-as-needed -l:libmid-tls.so "${linker_inputs[@]}" -o "$output"
}
build_main "$MUSL_LOADER" "$work_dir/main-musl" musl-reference
build_main "$work_dir/ld-crabc-x86_64-initial-tls.so" "$work_dir/main-crabc" candidate

require_needed_names() {
    local binary="$1"
    shift
    local dynamic actual expected=''
    dynamic="$(readelf -dW "$binary")"
    actual="$(sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p' <<<"$dynamic")"
    for name in "$@"; do
        if [ -n "$expected" ]; then
            expected+=$'\n'
        fi
        expected+="$name"
    done
    if [ "$actual" != "$expected" ]; then
        printf '%s\n' "ERROR: unexpected DT_NEEDED graph in $binary" >&2
        printf '%s\n' "$dynamic" >&2
        exit 1
    fi
}

# The fixture intentionally has exactly one dependency edge at each layer.
# In particular, the candidate's TLS resolver comes from its interpreter, not
# a host libc; the pinned-musl reference carries only musl's static resolver
# object and no libc DT_NEEDED edge.
require_needed_names "$work_dir/main-musl" libmid-tls.so
require_needed_names "$work_dir/main-crabc" libmid-tls.so
require_needed_names "$work_dir/libmid-tls.so" libleaf-tls.so
require_needed_names "$work_dir/libleaf-tls.so"

dynamic_symbol_exists() {
    local binary="$1"
    local binding="$2"
    readelf -Ws "$binary" | awk -v binding="$binding" '
        $8 == "__tls_get_addr" && ((binding == "defined" && $7 != "UND") || (binding == "undefined" && $7 == "UND")) {
            found = 1
        }
        END { exit found ? 0 : 1 }
    '
}

require_undefined_dynamic_names() {
    local binary="$1"
    shift
    local actual expected
    actual="$(readelf --dyn-syms -W "$binary" | awk '$7 == "UND" && $8 != "" { print $8 }' | LC_ALL=C sort -u)"
    expected="$(printf '%s\n' "$@" | LC_ALL=C sort -u)"
    if [ "$actual" != "$expected" ]; then
        printf '%s\n' "ERROR: unexpected undefined dynamic symbols in $binary" >&2
        printf '%s\n' "$actual" >&2
        exit 1
    fi
}

if ! dynamic_symbol_exists "$work_dir/ld-crabc-x86_64-initial-tls.so" defined \
    || dynamic_symbol_exists "$work_dir/main-crabc" defined \
    || ! dynamic_symbol_exists "$work_dir/main-crabc" undefined \
    || ! dynamic_symbol_exists "$work_dir/main-musl" defined; then
    printf '%s\n' 'ERROR: initial-TLS resolver ownership drifted' >&2
    exit 1
fi
for binary in "$work_dir/libmid-tls.so" "$work_dir/libleaf-tls.so"; do
    if ! dynamic_symbol_exists "$binary" undefined; then
        printf '%s\n' "ERROR: fixture stopped importing __tls_get_addr: $binary" >&2
        exit 1
    fi
done
require_undefined_dynamic_names "$work_dir/main-crabc" \
    __tls_get_addr mid_leaf_tls_alignment mid_leaf_zero_tls_value mid_tls_bump mid_tls_value
require_undefined_dynamic_names "$work_dir/libmid-tls.so" \
    __tls_get_addr leaf_aligned_tls_alignment leaf_general_tls leaf_tls_bump leaf_tls_value leaf_zero_tls_value
require_undefined_dynamic_names "$work_dir/libleaf-tls.so" __tls_get_addr

for binary in "$work_dir/libmid-tls.so" "$work_dir/libleaf-tls.so"; do
    binary_program_headers="$(readelf -lW "$binary")"
    if ! grep -Fq ' TLS ' <<<"$binary_program_headers"; then
        printf '%s\n' "ERROR: fixture lacks PT_TLS: $binary" >&2
        exit 1
    fi
done

relocations="$(readelf -rW "$work_dir/main-crabc" "$work_dir/libmid-tls.so" "$work_dir/libleaf-tls.so")"
for relocation in R_X86_64_DTPMOD64 R_X86_64_DTPOFF64; do
    if ! grep -q "$relocation" <<<"$relocations"; then
        printf '%s\n' "ERROR: fixture did not exercise $relocation" >&2
        exit 1
    fi
done
if ! grep -q '__tls_get_addr' <<<"$relocations"; then
    printf '%s\n' 'ERROR: fixture did not require __tls_get_addr' >&2
    exit 1
fi
leaf_dynamic="$(readelf -dW "$work_dir/libleaf-tls.so")"
if ! grep -Fq '(RELR)' <<<"$leaf_dynamic"; then
    printf '%s\n' 'ERROR: TLS leaf did not retain the fixed graph RELR boundary' >&2
    exit 1
fi
if grep -Eq 'R_X86_64_(TPOFF64|TPOFF32|GOTTPOFF|TLSDESC|GOTPC32_TLSDESC|TLSDESC_CALL)' <<<"$relocations"; then
    printf '%s\n' 'ERROR: initial-TLS fixture escaped its GNU-Dynamic relocation boundary' >&2
    exit 1
fi

main_musl_interpreter="$(readelf -lW "$work_dir/main-musl" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
main_crabc_interpreter="$(readelf -lW "$work_dir/main-crabc" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
if [ "$main_musl_interpreter" != "$MUSL_LOADER" ] || [ "$main_crabc_interpreter" != "$work_dir/ld-crabc-x86_64-initial-tls.so" ]; then
    printf '%s\n' 'ERROR: fixture PT_INTERP selection drifted' >&2
    exit 1
fi

(cd "$work_dir" && env -i PATH=/usr/bin:/bin "$work_dir/main-musl")
(cd "$work_dir" && env -i PATH=/usr/bin:/bin "$work_dir/main-crabc")

expect_candidate_rejection() {
    local expected_message="$1"
    local output status
    set +e
    output="$(cd "$work_dir" && env -i PATH=/usr/bin:/bin "$work_dir/main-crabc" 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 127 ] || ! grep -Fq "$expected_message" <<<"$output"; then
        printf '%s\n' "ERROR: candidate did not fail closed for $expected_message" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

dynamic_entry_offset() {
    local binary="$1"
    local wanted_tag="$2"
    local dynamic_offset dynamic_size entry tag
    dynamic_offset="$(objdump -h "$binary" | awk '$2 == ".dynamic" { print "0x" $6; exit }')"
    dynamic_size="$(objdump -h "$binary" | awk '$2 == ".dynamic" { print "0x" $3; exit }')"
    if [ -z "$dynamic_offset" ] || [ -z "$dynamic_size" ]; then
        return 1
    fi
    for ((entry = dynamic_offset; entry < dynamic_offset + dynamic_size; entry += 16)); do
        tag="$(od -An -tx8 -j"$entry" -N8 "$binary" | tr -d '[:space:]')"
        if [ "$tag" = "$wanted_tag" ]; then
            printf '%s\n' "$entry"
            return 0
        fi
    done
    return 1
}

rela_info_offset_for_type() {
    local binary="$1"
    local wanted_type="$2"
    local rela_offset rela_size record info expected_type
    rela_offset="$(objdump -h "$binary" | awk '$2 == ".rela.dyn" { print "0x" $6; exit }')"
    rela_size="$(objdump -h "$binary" | awk '$2 == ".rela.dyn" { print "0x" $3; exit }')"
    if [ -z "$rela_offset" ] || [ -z "$rela_size" ] || (( rela_size % 24 != 0 )); then
        return 1
    fi
    expected_type="$(printf '%08x' "$wanted_type")"
    for ((record = rela_offset; record < rela_offset + rela_size; record += 24)); do
        info="$(od -An -tx8 -j$((record + 8)) -N8 "$binary" | tr -d '[:space:]')"
        if [ "${info: -8}" = "$expected_type" ]; then
            printf '%s\n' $((record + 8))
            return 0
        fi
    done
    return 1
}

program_header_offset_for_type() {
    local binary="$1"
    local wanted_type="$2"
    local program_header_count index offset kind
    program_header_count="$(od -An -tu2 -j56 -N2 "$binary" | tr -d '[:space:]')"
    for ((index = 0; index < program_header_count; index++)); do
        offset=$((64 + index * 56))
        kind="$(od -An -tx4 -j"$offset" -N4 "$binary" | tr -d '[:space:]')"
        if [ "$kind" = "$wanted_type" ]; then
            printf '%s\n' "$offset"
            return 0
        fi
    done
    return 1
}

write_u64_le() {
    local binary="$1"
    local offset="$2"
    local value="$3"
    local byte escape
    {
        for ((index = 0; index < 8; index++)); do
            byte=$((value & 255))
            printf -v escape '\\%03o' "$byte"
            printf '%b' "$escape"
            value=$((value >> 8))
        done
    } | dd of="$binary" bs=1 seek="$offset" conv=notrunc status=none
}

# A PT_TLS initialized prefix cannot exceed its memory image.  Mutate only the
# leaf header after the positive run, preserving every dependency/relocation
# shape, and require the candidate to reject it before it reaches main.
cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
program_header_count="$(od -An -tu2 -j56 -N2 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
tls_header_offset=''
for ((index = 0; index < program_header_count; index++)); do
    offset=$((64 + index * 56))
    kind="$(od -An -tx4 -j"$offset" -N4 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
    if [ "$kind" = 00000007 ]; then
        tls_header_offset="$offset"
        break
    fi
done
if [ -z "$tls_header_offset" ]; then
    printf '%s\n' 'ERROR: fixture has no readable PT_TLS header' >&2
    exit 1
fi
tls_memsz="$(od -An -tu8 -j$((tls_header_offset + 40)) -N8 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
tls_align="$(od -An -tu8 -j$((tls_header_offset + 48)) -N8 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
if [ -z "$tls_memsz" ] || [ -z "$tls_align" ] || (( tls_memsz == 0 || tls_align == 0 || (tls_align & (tls_align - 1)) != 0 )); then
    printf '%s\n' 'ERROR: fixture has an unusable PT_TLS layout' >&2
    exit 1
fi
printf '\377\377\377\377\377\377\377\177' | dd of="$work_dir/libleaf-tls.so" bs=1 seek=$((tls_header_offset + 32)) conv=notrunc status=none
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

# Every PT_TLS image has one power-of-two alignment and matching file/virtual
# phases. These mutations preserve the rest of the ELF and fixed graph so the
# parser must reject the exact malformed-header condition before mapping.
cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
write_u64_le "$work_dir/libleaf-tls.so" $((tls_header_offset + 48)) 3
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
tls_file_offset="$(od -An -tu8 -j$((tls_header_offset + 8)) -N8 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
write_u64_le "$work_dir/libleaf-tls.so" $((tls_header_offset + 8)) $((tls_file_offset + 1))
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

# A second PT_TLS record would make one object ambiguous even if its empty
# fields otherwise look harmless. Retag only the disposable GNU-stack header.
cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
gnu_stack_header_offset="$(program_header_offset_for_type "$work_dir/libleaf-tls.so" 6474e551 || true)"
if [ -z "$gnu_stack_header_offset" ]; then
    printf '%s\n' 'ERROR: fixture has no disposable PT_GNU_STACK header' >&2
    exit 1
fi
printf '\007\000\000\000' | dd of="$work_dir/libleaf-tls.so" bs=1 seek="$gnu_stack_header_offset" conv=notrunc status=none
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

# Point PT_TLS at a one-byte BSS range inside a real readable PT_LOAD. It fits
# the mapping but is not file-backed, exercising the initialized-prefix check
# independently of p_filesz <= p_memsz and phase validation above.
non_file_load_header_offset=''
program_header_count="$(od -An -tu2 -j56 -N2 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
for ((index = 0; index < program_header_count; index++)); do
    offset=$((64 + index * 56))
    kind="$(od -An -tx4 -j"$offset" -N4 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
    flags="$(od -An -tu4 -j$((offset + 4)) -N4 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
    filesz="$(od -An -tu8 -j$((offset + 32)) -N8 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
    memsz="$(od -An -tu8 -j$((offset + 40)) -N8 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
    if [ "$kind" = 00000001 ] && (( (flags & 4) != 0 && memsz > filesz )); then
        non_file_load_header_offset="$offset"
        break
    fi
done
if [ -z "$non_file_load_header_offset" ]; then
    printf '%s\n' 'ERROR: TLS leaf lacks the required readable BSS PT_LOAD' >&2
    exit 1
fi
bss_virtual_address="$(od -An -tu8 -j$((non_file_load_header_offset + 16)) -N8 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
bss_file_size="$(od -An -tu8 -j$((non_file_load_header_offset + 32)) -N8 "$work_dir/libleaf-tls.so" | tr -d '[:space:]')"
bss_virtual_address=$((bss_virtual_address + bss_file_size))
cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
write_u64_le "$work_dir/libleaf-tls.so" $((tls_header_offset + 8)) $((bss_virtual_address & (tls_align - 1)))
write_u64_le "$work_dir/libleaf-tls.so" $((tls_header_offset + 16)) "$bss_virtual_address"
write_u64_le "$work_dir/libleaf-tls.so" $((tls_header_offset + 32)) 1
write_u64_le "$work_dir/libleaf-tls.so" $((tls_header_offset + 40)) 1
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

# GNU Dynamic TLS is intentionally the only selected access model.  Mutate a
# live DTPMOD64 record into a TP-relative TPOFF64 record without changing its
# symbol, table, or destination; the candidate must reject it in relocation
# preflight rather than treating the foreign model as a DTV lookup.
cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
dtpmod_info_offset="$(rela_info_offset_for_type "$work_dir/libleaf-tls.so" 16 || true)"
if [ -z "$dtpmod_info_offset" ]; then
    printf '%s\n' 'ERROR: fixture has no DTPMOD64 record to mutate' >&2
    exit 1
fi
printf '\022\000\000\000' | dd of="$work_dir/libleaf-tls.so" bs=1 seek="$dtpmod_info_offset" conv=notrunc status=none
leaf_relocations="$(readelf -rW "$work_dir/libleaf-tls.so")"
if ! grep -Fq 'R_X86_64_TPOFF64' <<<"$leaf_relocations"; then
    printf '%s\n' 'ERROR: TPOFF64 mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'reloc'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

# GNU DTPMOD64 carries the module ID alone; a nonzero addend is malformed.
cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
write_u64_le "$work_dir/libleaf-tls.so" $((dtpmod_info_offset + 8)) 1
expect_candidate_rejection 'reloc'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

# A DTPOFF64 addend must remain inside the selected module's PT_TLS memory
# image. Keep the symbol and relocation kind intact while crossing p_memsz.
cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
dtpoff_info_offset="$(rela_info_offset_for_type "$work_dir/libleaf-tls.so" 17 || true)"
if [ -z "$dtpoff_info_offset" ]; then
    printf '%s\n' 'ERROR: fixture has no DTPOFF64 record to mutate' >&2
    exit 1
fi
write_u64_le "$work_dir/libleaf-tls.so" $((dtpoff_info_offset + 8)) $((tls_memsz + 1))
expect_candidate_rejection 'reloc'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

# DF_STATIC_TLS would authorize the unsupported TPOFF static-layout route.
# Change only the leaf's otherwise inert eager-binding flags word and require
# parse-time rejection before this fixed graph reaches relocation or main.
cp "$work_dir/libleaf-tls.so" "$work_dir/libleaf-tls-valid.so"
flags_dynamic_entry="$(dynamic_entry_offset "$work_dir/libleaf-tls.so" 000000000000001e || true)"
if [ -z "$flags_dynamic_entry" ]; then
    printf '%s\n' 'ERROR: fixture has no DT_FLAGS entry for static-TLS mutation' >&2
    exit 1
fi
printf '\020\000\000\000\000\000\000\000' | dd of="$work_dir/libleaf-tls.so" bs=1 seek=$((flags_dynamic_entry + 8)) conv=notrunc status=none
leaf_dynamic="$(readelf -dW "$work_dir/libleaf-tls.so")"
if ! grep -Fq 'STATIC_TLS' <<<"$leaf_dynamic"; then
    printf '%s\n' 'ERROR: DF_STATIC_TLS mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-tls-valid.so" "$work_dir/libleaf-tls.so"

printf '%s\n' 'x86 initial TLS loader graph PT_TLS/DTPMOD/DTPOFF/TPOFF/static-TLS boundary: PASS'
