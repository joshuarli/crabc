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

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libleaf.so \
    "$LEAF" -o "$work_dir/libleaf.so"
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

# DT_RELR is loader-affecting but absent from this deliberately RELA-only
# artifact.  Re-tag a benign DT_FLAGS entry so the malformed image reaches
# the parser without adding a new table or changing the fixed graph shape.
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

printf '%s\n' 'x86 ET_DYN initial graph negative file-range/PT_TLS/RELA/tag/flags/table/main-init: PASS'
printf '%s\n' 'x86 ET_DYN initial interpreter graph: PASS'
