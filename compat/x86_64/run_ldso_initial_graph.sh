#!/usr/bin/env bash
# Native evidence for the intentionally bounded x86 ET_DYN interpreter graph.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE="$ROOT_DIR/ldso/src/x86_64_initial_graph.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_graph_leaf.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_graph_mid.c"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_initial_graph_main.c"
readonly ORACLE_MAIN="$ROOT_DIR/compat/x86_64/ldso_initial_graph_oracle_main.c"
readonly MUSL_LOADER="/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
readonly MAX_RELR_ENTRIES=512

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: initial-graph evidence requires native Linux/x86-64' >&2
    exit 2
fi
if [ ! -x "$MUSL_LOADER" ]; then
    printf '%s\n' 'ERROR: the pinned musl 1.2.6 oracle loader is required' >&2
    exit 2
fi

# Bind this graph's direct-main reference executable to the checked pinned
# oracle rather than merely accepting a loader path with the expected name.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"

work_dir="$(mktemp -d)"
if [ "${CRABC_LDSO_INITIAL_GRAPH_KEEP_WORK:-0}" = 1 ]; then
    printf '%s\n' "retained initial-graph work directory: $work_dir" >&2
else
    trap 'rm -rf "$work_dir"' EXIT
fi

# A static Rust archive avoids selecting the host runtime while retaining the
# toolchain's compiler-builtins.  The final link is explicitly ET_DYN and
# keeps every x86 interpreter self-relocation symbol-free.
rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
    "$SOURCE" -o "$work_dir/libinitial_graph.a"
cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
    -Wl,--whole-archive "$work_dir/libinitial_graph.a" -Wl,--no-whole-archive \
    -o "$work_dir/ld-crabc-x86_64-initial-graph.so"

test "$(readelf -h "$work_dir/ld-crabc-x86_64-initial-graph.so" | awk '/Type:/{print $2}')" = DYN
if readelf -dW "$work_dir/ld-crabc-x86_64-initial-graph.so" | grep -Eq '\(NEEDED\)|\(INTERP\)'; then
    printf '%s\n' 'ERROR: interpreter selected an external runtime' >&2
    exit 1
fi
if readelf -lW "$work_dir/ld-crabc-x86_64-initial-graph.so" | grep -q ' TLS '; then
    printf '%s\n' 'ERROR: interpreter selected PT_TLS' >&2
    exit 1
fi
if ! readelf -lW "$work_dir/ld-crabc-x86_64-initial-graph.so" | grep -q 'GNU_RELRO'; then
    printf '%s\n' 'ERROR: interpreter did not emit PT_GNU_RELRO' >&2
    exit 1
fi
if readelf -dW "$work_dir/ld-crabc-x86_64-initial-graph.so" | grep -Eq '\((RELR|RELRSZ|RELRENT)\)'; then
    printf '%s\n' 'ERROR: interpreter selected unsupported packed relative relocations' >&2
    exit 1
fi
if ! readelf -dW "$work_dir/ld-crabc-x86_64-initial-graph.so" | grep -q '(RELA)'; then
    printf '%s\n' 'ERROR: interpreter bootstrap has no DT_RELA table' >&2
    exit 1
fi
if ! readelf -dW "$work_dir/ld-crabc-x86_64-initial-graph.so" | grep -Eq '\(RELAENT\)[[:space:]]+24 \(bytes\)'; then
    printf '%s\n' 'ERROR: interpreter bootstrap RELA entry size drifted' >&2
    exit 1
fi
rela_byte_len="$(readelf -dW "$work_dir/ld-crabc-x86_64-initial-graph.so" | awk '/\(RELASZ\)/ { print $(NF - 1); exit }')"
if ! [[ "$rela_byte_len" =~ ^[0-9]+$ ]] || (( rela_byte_len == 0 || rela_byte_len % 24 != 0 )); then
    printf '%s\n' 'ERROR: interpreter bootstrap RELA byte length drifted' >&2
    exit 1
fi
if ! readelf -rW "$work_dir/ld-crabc-x86_64-initial-graph.so" | awk '
    /R_X86_64_/ {
        count += 1
        if ($2 != "0000000000000008" || $3 != "R_X86_64_RELATIVE") exit 1
    }
    END { exit count == 0 }
'; then
    printf '%s\n' 'ERROR: interpreter bootstrap relocation shape drifted' >&2
    exit 1
fi

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf.so \
    "$LEAF" -o "$work_dir/libleaf.so"
# Build two deliberately over-cap siblings only for negative evidence. The
# dense one exceeds the target cap while retaining a compact table; the sparse
# one exceeds the record cap. Neither is the ordinary valid graph dependency.
cc -DCRABC_RELR_TARGET_OVER_CAP=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf.so \
    "$LEAF" -o "$work_dir/libleaf-target-overcap.so"
cc -DCRABC_RELR_RECORD_OVER_CAP=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf.so \
    "$LEAF" -o "$work_dir/libleaf-record-overcap.so"
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libmid.so \
    -Wl,-rpath,"$work_dir" "$MID" -L"$work_dir" -Wl,--no-as-needed -l:libleaf.so \
    -o "$work_dir/libmid.so"

build_main() {
    local interpreter="$1"
    local source="$2"
    local output="$3"
    cc -nostdlib -fPIE -pie -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,--dynamic-linker,"$interpreter" -Wl,-rpath,"$work_dir" \
        "$START" "$source" -L"$work_dir" -Wl,--no-as-needed -l:libmid.so -o "$output"
}
build_main "$MUSL_LOADER" "$ORACLE_MAIN" "$work_dir/main-musl"
build_main "$work_dir/ld-crabc-x86_64-initial-graph.so" "$MAIN" "$work_dir/main-crabc"

main_musl_interpreter="$(readelf -lW "$work_dir/main-musl" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
main_crabc_interpreter="$(readelf -lW "$work_dir/main-crabc" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
if [ "$main_musl_interpreter" != "$MUSL_LOADER" ] || [ "$main_crabc_interpreter" != "$work_dir/ld-crabc-x86_64-initial-graph.so" ]; then
    printf '%s\n' 'ERROR: fixture PT_INTERP selection drifted' >&2
    exit 1
fi

for binary in "$work_dir/main-musl" "$work_dir/main-crabc" "$work_dir/libmid.so"; do
    if ! readelf -dW "$binary" | grep -Fq "Library runpath: [$work_dir]"; then
        printf '%s\n' "ERROR: fixture RUNPATH is not the one absolute owned directory: $binary" >&2
        exit 1
    fi
done

for binary in "$work_dir/main-musl" "$work_dir/main-crabc" "$work_dir/libmid.so" "$work_dir/libleaf.so"; do
    if readelf -lW "$binary" | grep -q ' TLS '; then
        printf '%s\n' "ERROR: fixture unexpectedly selected TLS: $binary" >&2
        exit 1
    fi
done
if ! readelf -dW "$work_dir/libleaf.so" | grep -q '(RELR)'; then
    printf '%s\n' 'ERROR: packed leaf fixture has no DT_RELR' >&2
    exit 1
fi
if ! readelf -dW "$work_dir/libleaf.so" | grep -Eq '\(RELRSZ\)[[:space:]]+[1-9][0-9]* \(bytes\)'; then
    printf '%s\n' 'ERROR: packed leaf fixture has no nonempty DT_RELRSZ' >&2
    exit 1
fi
if ! readelf -dW "$work_dir/libleaf.so" | grep -Eq '\(RELRENT\)[[:space:]]+8 \(bytes\)'; then
    printf '%s\n' 'ERROR: packed leaf fixture DT_RELRENT drifted' >&2
    exit 1
fi
for binary in "$work_dir/main-musl" "$work_dir/main-crabc" "$work_dir/libmid.so" "$work_dir/libleaf.so"; do
    if ! readelf -lW "$binary" | grep -q 'GNU_RELRO'; then
        printf '%s\n' "ERROR: fixture did not emit PT_GNU_RELRO: $binary" >&2
        exit 1
    fi
done
for binary in "$work_dir/main-musl" "$work_dir/main-crabc" "$work_dir/libmid.so" "$work_dir/libleaf.so"; do
    if readelf -rW "$binary" | awk '/R_X86_64_/ { if ($3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" && $3 != "R_X86_64_JUMP_SLOT") exit 1 }'; then :; else
        printf '%s\n' "ERROR: fixture escaped the relocation whitelist: $binary" >&2
        exit 1
    fi
done
relocations="$(readelf -rW "$work_dir/main-crabc" "$work_dir/libmid.so" "$work_dir/libleaf.so")"
for relocation in R_X86_64_RELATIVE R_X86_64_GLOB_DAT R_X86_64_JUMP_SLOT; do
    if ! grep -q "$relocation" <<<"$relocations"; then
        printf '%s\n' "ERROR: fixture did not exercise $relocation" >&2
        exit 1
    fi
done

(cd "$work_dir" && CRABC_EXECUTION_MODE=native "$work_dir/main-musl")
(cd "$work_dir" && CRABC_EXECUTION_MODE=native "$work_dir/main-crabc")

expect_candidate_rejection() {
    local expected_message="$1"
    local output
    local status
    set +e
    output="$(cd "$work_dir" && CRABC_EXECUTION_MODE=native "$work_dir/main-crabc" 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 127 ] || ! grep -Fq "$expected_message" <<<"$output"; then
        printf '%s\n' "ERROR: candidate did not fail closed for $expected_message" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

# The DSO mapper must reject file offsets that cannot supply the declared
# PT_LOAD bytes rather than exposing a later page fault/SIGBUS as its error
# behavior.  Keep the changed offset page-congruent with the executable
# segment's vaddr so this isolates file-range validation from ELF alignment.
cp "$work_dir/libmid.so" "$work_dir/libmid-valid.so"
program_header_count="$(od -An -tu2 -j56 -N2 "$work_dir/libmid.so" | tr -d '[:space:]')"
executable_load_header_offset=''
for ((index = 0; index < program_header_count; index++)); do
    offset=$((64 + index * 56))
    kind="$(od -An -tx4 -j"$offset" -N4 "$work_dir/libmid.so" | tr -d '[:space:]')"
    flags="$(od -An -tx4 -j$((offset + 4)) -N4 "$work_dir/libmid.so" | tr -d '[:space:]')"
    if [ "$kind" = 00000001 ] && (( (16#$flags) & 1 )); then
        executable_load_header_offset="$offset"
        break
    fi
done
if [ -z "$executable_load_header_offset" ]; then
    printf '%s\n' 'ERROR: fixture has no executable PT_LOAD header' >&2
    exit 1
fi
printf '\000\000\020\000\000\000\000\000' | dd of="$work_dir/libmid.so" bs=1 seek=$((executable_load_header_offset + 8)) conv=notrunc status=none
if [ "$(od -An -tx8 -j$((executable_load_header_offset + 8)) -N8 "$work_dir/libmid.so" | tr -d '[:space:]')" != 0000000000100000 ]; then
    printf '%s\n' 'ERROR: out-of-file PT_LOAD offset mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'midmap'
mv "$work_dir/libmid-valid.so" "$work_dir/libmid.so"

dynamic_entry_offset() {
    local binary="$1"
    local wanted_tag="$2"
    local dynamic_offset dynamic_size entry tag
    dynamic_offset="$(objdump -h "$binary" | awk '$2 == ".dynamic" { print "0x" $6; exit }')"
    dynamic_size="$(objdump -h "$binary" | awk '$2 == ".dynamic" { print "0x" $3; exit }')"
    if [ -z "$dynamic_offset" ] || [ -z "$dynamic_size" ]; then
        return 1
    fi
    for ((entry = 0; entry < dynamic_size / 16; entry++)); do
        tag="$(od -An -tx8 -j$((dynamic_offset + entry * 16)) -N8 "$binary" | tr -d '[:space:]')"
        if [ "$tag" = "$wanted_tag" ]; then
            printf '%s\n' "$((dynamic_offset + entry * 16))"
            return 0
        fi
    done
    return 1
}

relr_section_offset() {
    objdump -h "$1" | awk '$2 == ".relr.dyn" { print "0x" $6; exit }'
}

relr_section_size() {
    objdump -h "$1" | awk '$2 == ".relr.dyn" { print "0x" $3; exit }'
}

relr_entry_kind() {
    local binary="$1"
    local offset="$2"
    local word
    word="$(od -An -tx8 -j"$offset" -N8 "$binary" | tr -d '[:space:]')"
    case "${word: -1}" in
        1|3|5|7|9|b|d|f) printf '%s\n' bitmap ;;
        0|2|4|6|8|a|c|e) printf '%s\n' direct ;;
        *) return 1 ;;
    esac
}

relr_offset="$(relr_section_offset "$work_dir/libleaf.so")"
relr_size="$(relr_section_size "$work_dir/libleaf.so")"
if [ -z "$relr_offset" ] || [ -z "$relr_size" ] || (( relr_size == 0 || relr_size % 8 != 0 )); then
    printf '%s\n' 'ERROR: packed leaf fixture has no integral .relr.dyn payload' >&2
    exit 1
fi
relr_direct_count=0
relr_bitmap_count=0
for ((entry = 0; entry < relr_size / 8; entry++)); do
    case "$(relr_entry_kind "$work_dir/libleaf.so" $((relr_offset + entry * 8)))" in
        direct) relr_direct_count=$((relr_direct_count + 1)) ;;
        bitmap) relr_bitmap_count=$((relr_bitmap_count + 1)) ;;
        *)
            printf '%s\n' 'ERROR: packed leaf fixture has an unreadable .relr.dyn word' >&2
            exit 1
            ;;
    esac
done
if (( relr_direct_count == 0 || relr_bitmap_count == 0 )); then
    printf '%s\n' 'ERROR: packed leaf fixture did not exercise both direct and bitmap RELR records' >&2
    exit 1
fi
if [ "$(relr_entry_kind "$work_dir/libleaf.so" "$relr_offset")" != direct ]; then
    printf '%s\n' 'ERROR: packed leaf fixture does not begin its RELR stream with a direct address' >&2
    exit 1
fi
relr_dynamic_entry="$(dynamic_entry_offset "$work_dir/libleaf.so" 0000000000000024 || true)"
relrent_dynamic_entry="$(dynamic_entry_offset "$work_dir/libleaf.so" 0000000000000025 || true)"
rela_dynamic_entry="$(dynamic_entry_offset "$work_dir/libleaf.so" 0000000000000007 || true)"
if [ -z "$relr_dynamic_entry" ] || [ -z "$relrent_dynamic_entry" ] || [ -z "$rela_dynamic_entry" ]; then
    printf '%s\n' 'ERROR: packed leaf fixture lacks required relocation dynamic entries' >&2
    exit 1
fi

# A packed RELR stream is accepted only with its complete dynamic-tag triple.
# Retag DT_RELRENT to an unknown processor-specific value: the ordinary table
# bytes remain unchanged, so the parser must fail solely because the triple is
# incomplete rather than treating the existing stream as an unscoped tag.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
printf '\000\000\000\160\000\000\000\000' | dd of="$work_dir/libleaf.so" bs=1 seek="$relrent_dynamic_entry" conv=notrunc status=none
if readelf -dW "$work_dir/libleaf.so" | grep -q '(RELRENT)'; then
    printf '%s\n' 'ERROR: incomplete DT_RELR mutation retained DT_RELRENT' >&2
    exit 1
fi
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# RELRENT has an exact ELF64 word size. A valid table with a wrong entry size
# must be rejected at parse time before the loader looks at any payload word.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
printf '\020\000\000\000\000\000\000\000' | dd of="$work_dir/libleaf.so" bs=1 seek=$((relrent_dynamic_entry + 8)) conv=notrunc status=none
if ! readelf -dW "$work_dir/libleaf.so" | grep -Eq '\(RELRENT\)[[:space:]]+16 \(bytes\)'; then
    printf '%s\n' 'ERROR: malformed DT_RELRENT mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# The table address itself is an object-relative checked-load-range value.
# Keep every tag present while moving only DT_RELR outside every PT_LOAD.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
printf '\377\377\377\377\377\377\377\177' | dd of="$work_dir/libleaf.so" bs=1 seek=$((relr_dynamic_entry + 8)) conv=notrunc status=none
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# The packed table cannot alias a RELA table. Copy the existing DT_RELA
# address into DT_RELR while preserving an in-range table pointer and every
# other RELR tag; preflight must reject the overlapping table windows before
# it decodes a relocation or changes a target.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
dd if="$work_dir/libleaf-valid.so" of="$work_dir/libleaf.so" bs=1 skip=$((rela_dynamic_entry + 8)) seek=$((relr_dynamic_entry + 8)) count=8 conv=notrunc status=none
if [ "$(od -An -tx8 -j$((relr_dynamic_entry + 8)) -N8 "$work_dir/libleaf.so" | tr -d '[:space:]')" != "$(od -An -tx8 -j$((rela_dynamic_entry + 8)) -N8 "$work_dir/libleaf-valid.so" | tr -d '[:space:]')" ]; then
    printf '%s\n' 'ERROR: overlapping relocation-table mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'reloc'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# RELR's first bitmap needs a preceding direct address cursor. Corrupt only
# the first packed word's low byte after the checked dynamic table has pointed
# at it; the candidate must reject during relocation before control reaches
# the mapped main entry.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
printf '\001' | dd of="$work_dir/libleaf.so" bs=1 seek=$((relr_offset)) conv=notrunc status=none
if [ "$(relr_entry_kind "$work_dir/libleaf.so" "$relr_offset")" != bitmap ]; then
    printf '%s\n' 'ERROR: bitmap-without-address mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'reloc'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# A direct RELR address must name one aligned writable word in this object.
# ELF virtual address zero is the fixture's non-writable first PT_LOAD, so it
# isolates writable-target validation without changing the table range.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
printf '\000\000\000\000\000\000\000\000' | dd of="$work_dir/libleaf.so" bs=1 seek=$((relr_offset)) conv=notrunc status=none
expect_candidate_rejection 'reloc'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# Copy the first direct record over the final record. The preceding stream is
# unchanged and the replacement is itself a valid direct address, so the only
# new condition is that two RELR records target the same writable word.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
last_relr_entry_offset=$((relr_offset + relr_size - 8))
dd if="$work_dir/libleaf-valid.so" of="$work_dir/libleaf.so" bs=1 skip=$((relr_offset)) seek="$last_relr_entry_offset" count=8 conv=notrunc status=none
if [ "$(od -An -tx8 -j"$last_relr_entry_offset" -N8 "$work_dir/libleaf.so" | tr -d '[:space:]')" != "$(od -An -tx8 -j"$relr_offset" -N8 "$work_dir/libleaf-valid.so" | tr -d '[:space:]')" ]; then
    printf '%s\n' 'ERROR: duplicate RELR target mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'reloc'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# The dense runner-only leaf keeps its packed RELR table below the record cap
# while its 513 adjacent pointer slots exceed the target cap. Pinned musl
# proves the object itself is valid and reaches every pointer; this private
# candidate deliberately rejects its over-cap relocation transaction.
target_overcap_relr_offset="$(relr_section_offset "$work_dir/libleaf-target-overcap.so")"
target_overcap_relr_size="$(relr_section_size "$work_dir/libleaf-target-overcap.so")"
if [ -z "$target_overcap_relr_offset" ] || [ -z "$target_overcap_relr_size" ] \
    || (( target_overcap_relr_size == 0 || target_overcap_relr_size % 8 != 0 || target_overcap_relr_size / 8 > MAX_RELR_ENTRIES )); then
    printf '%s\n' 'ERROR: target-over-cap leaf fixture did not retain a compact RELR table' >&2
    exit 1
fi
target_overcap_direct_count=0
target_overcap_bitmap_count=0
for ((entry = 0; entry < target_overcap_relr_size / 8; entry++)); do
    case "$(relr_entry_kind "$work_dir/libleaf-target-overcap.so" $((target_overcap_relr_offset + entry * 8)))" in
        direct) target_overcap_direct_count=$((target_overcap_direct_count + 1)) ;;
        bitmap) target_overcap_bitmap_count=$((target_overcap_bitmap_count + 1)) ;;
        *)
            printf '%s\n' 'ERROR: target-over-cap leaf fixture has an unreadable RELR word' >&2
            exit 1
            ;;
    esac
done
if (( target_overcap_direct_count == 0 || target_overcap_bitmap_count == 0 )); then
    printf '%s\n' 'ERROR: target-over-cap leaf fixture did not retain direct-and-bitmap RELR encoding' >&2
    exit 1
fi
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
cp "$work_dir/libleaf-target-overcap.so" "$work_dir/libleaf.so"
(cd "$work_dir" && CRABC_EXECUTION_MODE=native "$work_dir/main-musl")
expect_candidate_rejection 'reloc'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# The sparse runner-only leaf has more than 512 direct RELR records. The
# candidate must reject this table before iterating it, independently of how
# many destination words it would contain.
record_overcap_relr_offset="$(relr_section_offset "$work_dir/libleaf-record-overcap.so")"
record_overcap_relr_size="$(relr_section_size "$work_dir/libleaf-record-overcap.so")"
if [ -z "$record_overcap_relr_offset" ] || [ -z "$record_overcap_relr_size" ] \
    || (( record_overcap_relr_size % 8 != 0 || record_overcap_relr_size / 8 <= MAX_RELR_ENTRIES )); then
    printf '%s\n' 'ERROR: record-over-cap leaf fixture did not emit more than 512 RELR records' >&2
    exit 1
fi
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
cp "$work_dir/libleaf-record-overcap.so" "$work_dir/libleaf.so"
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# Turn every record after the first valid direct address into an empty bitmap.
# This preserves one real relocation target while retaining the over-cap table
# length, proving that zero-bit runs cannot bypass the separate record bound.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
cp "$work_dir/libleaf-record-overcap.so" "$work_dir/libleaf.so"
{
    for ((entry = 1; entry < record_overcap_relr_size / 8; entry++)); do
        printf '\001\000\000\000\000\000\000\000'
    done
} | dd of="$work_dir/libleaf.so" bs=1 seek=$((record_overcap_relr_offset + 8)) conv=notrunc status=none
if [ "$(relr_entry_kind "$work_dir/libleaf.so" "$record_overcap_relr_offset")" != direct ] \
    || [ "$(od -An -tx8 -j$((record_overcap_relr_offset + 8)) -N8 "$work_dir/libleaf.so" | tr -d '[:space:]')" != 0000000000000001 ] \
    || [ "$(od -An -tx8 -j$((record_overcap_relr_offset + record_overcap_relr_size - 8)) -N8 "$work_dir/libleaf.so" | tr -d '[:space:]')" != 0000000000000001 ]; then
    printf '%s\n' 'ERROR: zero-bit over-cap RELR mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# Change only the unused PT_GNU_STACK header in a disposable leaf copy. The
# parser must reject PT_TLS before it can select a TLS-less graph artifact.
cp "$work_dir/libleaf.so" "$work_dir/libleaf-valid.so"
program_header_count="$(od -An -tu2 -j56 -N2 "$work_dir/libleaf.so" | tr -d '[:space:]')"
tls_header_offset=''
for ((index = 0; index < program_header_count; index++)); do
    offset=$((64 + index * 56))
    kind="$(od -An -tx4 -j"$offset" -N4 "$work_dir/libleaf.so" | tr -d '[:space:]')"
    if [ "$kind" = 6474e551 ]; then
        tls_header_offset="$offset"
        break
    fi
done
if [ -z "$tls_header_offset" ]; then
    printf '%s\n' 'ERROR: fixture has no disposable PT_GNU_STACK header' >&2
    exit 1
fi
printf '\007\000\000\000' | dd of="$work_dir/libleaf.so" bs=1 seek="$tls_header_offset" conv=notrunc status=none
if ! readelf -lW "$work_dir/libleaf.so" | grep -q ' TLS '; then
    printf '%s\n' 'ERROR: PT_TLS mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'leafmap'
mv "$work_dir/libleaf-valid.so" "$work_dir/libleaf.so"

# Rewrite one valid RELATIVE r_info word to R_X86_64_COPY (5). This is a
# precise unsupported-RELA mutation: no loader table size, target, or symbol
# string changes, so a successful run would demonstrate an unsafe fallback.
cp "$work_dir/libmid.so" "$work_dir/libmid-valid.so"
rela_offset="$(objdump -h "$work_dir/libmid.so" | awk '$2 == ".rela.dyn" { print "0x" $6; exit }')"
if [ -z "$rela_offset" ]; then
    printf '%s\n' 'ERROR: fixture has no .rela.dyn table to mutate' >&2
    exit 1
fi
printf '\005\000\000\000\000\000\000\000' | dd of="$work_dir/libmid.so" bs=1 seek=$((rela_offset + 8)) conv=notrunc status=none
if ! readelf -rW "$work_dir/libmid.so" | grep -q R_X86_64_COPY; then
    printf '%s\n' 'ERROR: unsupported relocation mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'reloc'
mv "$work_dir/libmid-valid.so" "$work_dir/libmid.so"

# Corrupt only r_offset in a disposable RELA record.  The relocation table
# remains in range and has a supported type, so this specifically proves that
# the candidate rejects a target outside a writable PT_LOAD before writing it.
cp "$work_dir/libmid.so" "$work_dir/libmid-valid.so"
printf '\377\377\377\377\377\377\377\177' | dd of="$work_dir/libmid.so" bs=1 seek=$((rela_offset)) conv=notrunc status=none
expect_candidate_rejection 'reloc'
mv "$work_dir/libmid-valid.so" "$work_dir/libmid.so"

# Move DT_RELA's address outside every PT_LOAD without changing the table
# bytes.  This is the nearest valid table-pointer mutation for the scoped ABI.
cp "$work_dir/libmid.so" "$work_dir/libmid-valid.so"
rela_dynamic_entry="$(dynamic_entry_offset "$work_dir/libmid.so" 0000000000000007 || true)"
if [ -z "$rela_dynamic_entry" ]; then
    printf '%s\n' 'ERROR: fixture has no DT_RELA entry to mutate' >&2
    exit 1
fi
printf '\377\377\377\377\377\377\377\177' | dd of="$work_dir/libmid.so" bs=1 seek=$((rela_dynamic_entry + 8)) conv=notrunc status=none
expect_candidate_rejection 'midmap'
mv "$work_dir/libmid-valid.so" "$work_dir/libmid.so"

# A lone DT_RELR remains malformed: this private graph accepts only the
# complete DT_RELR/DT_RELRSZ/DT_RELRENT triple. Re-tag a benign DT_FLAGS entry
# so the malformed image reaches the parser without adding a table or changing
# the fixed graph shape.
cp "$work_dir/libmid.so" "$work_dir/libmid-valid.so"
flags_dynamic_entry="$(dynamic_entry_offset "$work_dir/libmid.so" 000000000000001e || true)"
if [ -z "$flags_dynamic_entry" ]; then
    printf '%s\n' 'ERROR: fixture has no disposable DT_FLAGS entry' >&2
    exit 1
fi
printf '\044\000\000\000\000\000\000\000' | dd of="$work_dir/libmid.so" bs=1 seek="$flags_dynamic_entry" conv=notrunc status=none
if ! readelf -dW "$work_dir/libmid.so" | grep -q '(RELR)'; then
    printf '%s\n' 'ERROR: DT_RELR mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'midmap'
mv "$work_dir/libmid-valid.so" "$work_dir/libmid.so"

# Text relocations and static-TLS flags would change unsupported write/TLS
# behavior even though they are represented by otherwise familiar tags.
cp "$work_dir/libmid.so" "$work_dir/libmid-valid.so"
flags_dynamic_entry="$(dynamic_entry_offset "$work_dir/libmid.so" 000000000000001e || true)"
if [ -z "$flags_dynamic_entry" ]; then
    printf '%s\n' 'ERROR: fixture has no DT_FLAGS entry for semantic mutation' >&2
    exit 1
fi
printf '\026\000\000\000\000\000\000\000' | dd of="$work_dir/libmid.so" bs=1 seek="$flags_dynamic_entry" conv=notrunc status=none
if ! readelf -dW "$work_dir/libmid.so" | grep -q '(TEXTREL)'; then
    printf '%s\n' 'ERROR: DT_TEXTREL mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'midmap'
mv "$work_dir/libmid-valid.so" "$work_dir/libmid.so"

cp "$work_dir/libmid.so" "$work_dir/libmid-valid.so"
flags_dynamic_entry="$(dynamic_entry_offset "$work_dir/libmid.so" 000000000000001e || true)"
if [ -z "$flags_dynamic_entry" ]; then
    printf '%s\n' 'ERROR: fixture has no DT_FLAGS entry for static-TLS mutation' >&2
    exit 1
fi
printf '\020\000\000\000\000\000\000\000' | dd of="$work_dir/libmid.so" bs=1 seek=$((flags_dynamic_entry + 8)) conv=notrunc status=none
if ! readelf -dW "$work_dir/libmid.so" | grep -q 'STATIC_TLS'; then
    printf '%s\n' 'ERROR: DF_STATIC_TLS mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'midmap'
mv "$work_dir/libmid-valid.so" "$work_dir/libmid.so"

# The executable's DT_INIT/DT_INIT_ARRAY route is intentionally rejected: the
# candidate transfers to main entry after dependency constructors, while CRT
# handoff remains the only future owner of main-image constructor dispatch.
cp "$work_dir/main-crabc" "$work_dir/main-crabc-valid"
main_flags_dynamic_entry="$(dynamic_entry_offset "$work_dir/main-crabc" 000000000000001e || true)"
if [ -z "$main_flags_dynamic_entry" ]; then
    printf '%s\n' 'ERROR: fixture main has no disposable DT_FLAGS entry' >&2
    exit 1
fi
printf '\014\000\000\000\000\000\000\000' | dd of="$work_dir/main-crabc" bs=1 seek="$main_flags_dynamic_entry" conv=notrunc status=none
if ! readelf -dW "$work_dir/main-crabc" | grep -q '(INIT)'; then
    printf '%s\n' 'ERROR: main DT_INIT mutation did not take effect' >&2
    exit 1
fi
expect_candidate_rejection 'mainelf'
mv "$work_dir/main-crabc-valid" "$work_dir/main-crabc"

printf '%s\n' 'x86 ET_DYN initial graph negative file-range/PT_TLS/RELA/RELR-cap/tag/flags/table/main-init: PASS'
printf '%s\n' 'x86 ET_DYN initial interpreter graph: PASS'
