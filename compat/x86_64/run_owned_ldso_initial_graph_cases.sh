#!/usr/bin/env bash
# Installed-product evidence for the initial dependency graph.
#
# The same fixtures that the retired private fixed-graph interpreter proved are
# linked against the installed product's own CRT/libc and executed through its
# loader.  Positive graphs stay musl-differential; malformed mutations must
# fail closed before the application entry.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$(dirname "${BASH_SOURCE[0]}")/native_build_environment.sh"
readonly PRODUCT="${1:?usage: $0 DYNAMIC-SYSROOT [--evidence-parent DIR]}"
readonly START="$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_graph_leaf.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_graph_mid.c"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_initial_graph_main.c"
readonly ORACLE_MAIN="$ROOT_DIR/compat/x86_64/ldso_initial_graph_oracle_main.c"
readonly MUSL_LOADER="/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
readonly MUSL_LIBC="/opt/musl-1.2.6/lib/libc.so"
readonly ORACLE_CC="/usr/local/bin/crabc-x86_64-musl-gcc"

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: initial-graph evidence requires native Linux/x86-64' >&2
    exit 2
fi
[ -d "$PRODUCT" ] || { printf 'ERROR: installed product missing: %s\n' "$PRODUCT" >&2; exit 2; }
[ -x "$MUSL_LOADER" ] || { printf '%s\n' 'ERROR: the pinned musl 1.2.6 oracle loader is required' >&2; exit 2; }
[ -f "$MUSL_LIBC" ] || { printf '%s\n' 'ERROR: the pinned musl 1.2.6 oracle libc is required' >&2; exit 2; }
case "${TMPDIR:-}" in
    "$ROOT_DIR"/.work/*) ;;
    *) printf 'TMPDIR must be under %s/.work\n' "$ROOT_DIR" >&2; exit 2 ;;
esac

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work="$(mktemp -d "$TMPDIR/initial-graph-product.XXXXXX")"
printf 'evidence: %s\n' "$work"

root="$work/root"
oracle_root="$work/oracle-root"
fixtures="$root/fixtures"
oracle_fixtures="$oracle_root/fixtures"
cp -a "$PRODUCT" "$root"
mkdir -p "$fixtures" "$oracle_root/lib" "$oracle_root/usr/lib" "$oracle_fixtures"
cp "$MUSL_LOADER" "$oracle_root/lib/ld-musl-x86_64.so.1"
cp "$MUSL_LIBC" "$oracle_root/usr/lib/libc.so"
chmod 0755 "$oracle_root/lib/ld-musl-x86_64.so.1" "$oracle_root/usr/lib/libc.so"

fail() {
    printf 'ERROR: initial-graph product: %s\n' "$*" >&2
    exit 1
}

# The installed loader is a complete runtime, so its retained ELF facts differ
# from the retired bootstrap interpreter: it owns PT_TLS and packed RELR and
# must publish complete metadata for both instead of omitting them.
loader="$root/lib/ld-crabc-x86_64.so.1"
[ "$(readelf -h "$loader" | awk '/Type:/{print $2}')" = DYN ] ||
    fail 'installed loader is not ET_DYN'
if readelf -dW "$loader" | grep -E '\(NEEDED\)|\(INTERP\)' >/dev/null; then
    fail 'installed loader selected an external runtime'
fi
if ! readelf -lW "$loader" | grep 'GNU_RELRO' >/dev/null; then
    fail 'installed loader did not emit PT_GNU_RELRO'
fi
read -r tls_filesz tls_memsz <<<"$(readelf -lW "$loader" | awk '$1 == "TLS" { print $5, $6 }')"
[[ -n "$tls_filesz" && -n "$tls_memsz" ]] || fail 'installed loader lost its runtime PT_TLS'
[[ "$tls_filesz" =~ ^0x[0-9a-fA-F]+$ && "$tls_memsz" =~ ^0x[0-9a-fA-F]+$ ]] ||
    fail 'installed loader PT_TLS sizes are unreadable'
(( tls_memsz >= tls_filesz )) || fail 'installed loader PT_TLS memsz is below filesz'
if ! readelf -dW "$loader" | grep '(RELA)' >/dev/null; then
    fail 'installed loader has no DT_RELA table'
fi
if ! readelf -dW "$loader" | grep -E '\(RELAENT\)[[:space:]]+24 \(bytes\)' >/dev/null; then
    fail 'installed loader RELA entry size drifted'
fi
rela_byte_len="$(readelf -dW "$loader" | awk '
    /\(RELASZ\)/ { size = $(NF - 1) }
    END { if (size != "") print size }
')"
[[ "$rela_byte_len" =~ ^[0-9]+$ ]] && (( rela_byte_len > 0 && rela_byte_len % 24 == 0 )) ||
    fail 'installed loader RELA byte length drifted'
for tag in RELR RELRSZ RELRENT; do
    readelf -dW "$loader" | grep "($tag)" >/dev/null || fail "installed loader lacks DT_$tag"
done
relr_byte_len="$(readelf -dW "$loader" | awk '
    /\(RELRSZ\)/ { size = $(NF - 1) }
    END { if (size != "") print size }
')"
[[ "$relr_byte_len" =~ ^[0-9]+$ ]] && (( relr_byte_len > 0 && relr_byte_len % 8 == 0 )) ||
    fail 'installed loader RELR byte length drifted'
if ! readelf -dW "$loader" | grep -E '\(RELRENT\)[[:space:]]+8 \(bytes\)' >/dev/null; then
    fail 'installed loader RELR entry size drifted'
fi
if readelf -rW "$loader" | awk '
    /R_X86_64_/ && $3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" &&
    $3 != "R_X86_64_JUMP_SLOT" && $3 != "R_X86_64_TPOFF64" { exit 1 }
'; then :; else
    fail 'installed loader relocation classes escaped the product profile'
fi

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf.so \
    "$LEAF" -o "$fixtures/libleaf.so"
cc -DCRABC_RELR_TARGET_OVER_CAP=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf.so \
    "$LEAF" -o "$fixtures/libleaf-target-overcap.so"
cc -DCRABC_RELR_RECORD_OVER_CAP=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf.so \
    "$LEAF" -o "$fixtures/libleaf-record-overcap.so"
cc -DCRABC_RELR_RECORD_OVER_CAP=1 -DCRABC_RELR_ZERO_BIT_OVER_CAP=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf.so \
    "$LEAF" -o "$fixtures/libleaf-zero-bit-overcap.so"
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libmid.so \
    -Wl,-rpath,/fixtures "$MID" -L"$fixtures" -Wl,--no-as-needed -l:libleaf.so \
    -o "$fixtures/libmid.so"

# The installed product materializes the main thread's initial TLS before the
# application entry.  Give this otherwise TLS-free graph one ordinary main TLS
# image so the same transaction is exercised without changing the DSO facts.
cat >"$work/main-tls.c" <<'EOF'
__thread int crabc_initial_graph_main_tls = 7;
EOF
cc -O2 -fPIE -ftls-model=global-dynamic -c "$work/main-tls.c" -o "$work/main-tls.o"
cc -O2 -fPIE -c "$MAIN" -o "$work/main.o"
cc -O2 -fPIE -c "$START" -o "$work/start.o"
cc -O2 -fPIE -c "$ORACLE_MAIN" -o "$work/oracle-main.o"

cc -nostdlib -fPIE -pie -ftls-model=global-dynamic -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,--dynamic-linker,/lib/ld-crabc-x86_64.so.1 -Wl,-rpath,/fixtures -Wl,-rpath-link,"$fixtures" \
    "$PRODUCT/usr/lib/Scrt1.o" "$PRODUCT/usr/lib/crti.o" \
    "$work/main.o" "$work/main-tls.o" "$PRODUCT/usr/lib/crabc-dynamic-attach.o" \
    -L"$PRODUCT/usr/lib" -lc "$PRODUCT/usr/lib/libcrabc-builtins.a" "$PRODUCT/usr/lib/crtn.o" \
    -L"$fixtures" -Wl,--no-as-needed -l:libmid.so -o "$fixtures/main-crabc"

"$ORACLE_CC" -O2 -fPIE -pie -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -Wl,-rpath,/fixtures -Wl,-rpath-link,"$fixtures" \
    "$work/oracle-main.o" -L"$fixtures" -Wl,--no-as-needed -l:libmid.so \
    -o "$fixtures/main-musl"

cp -a "$fixtures/." "$oracle_fixtures/"

main_crabc_interpreter="$(readelf -lW "$fixtures/main-crabc" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
main_musl_interpreter="$(readelf -lW "$fixtures/main-musl" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
[ "$main_crabc_interpreter" = /lib/ld-crabc-x86_64.so.1 ] || fail 'candidate PT_INTERP drifted'
[ "$main_musl_interpreter" = /lib/ld-musl-x86_64.so.1 ] || fail 'musl reference PT_INTERP drifted'

for binary in "$fixtures/main-crabc" "$fixtures/main-musl" "$fixtures/libmid.so"; do
    if ! readelf -dW "$binary" | grep -F 'Library runpath: [/fixtures]' >/dev/null; then
        fail "fixture RUNPATH is not the one absolute owned directory: $binary"
    fi
done
for binary in "$fixtures/main-musl" "$fixtures/libmid.so" "$fixtures/libleaf.so"; do
    if readelf -lW "$binary" | grep ' TLS ' >/dev/null; then
        fail "fixture unexpectedly selected TLS: $binary"
    fi
done
if ! readelf -lW "$fixtures/main-crabc" | grep ' TLS ' >/dev/null; then
    fail 'candidate main did not retain its initial TLS image'
fi
if ! readelf -dW "$fixtures/libleaf.so" | grep '(RELR)' >/dev/null; then
    fail 'packed leaf fixture has no DT_RELR'
fi
if ! readelf -dW "$fixtures/libleaf.so" | grep -E '\(RELRSZ\)[[:space:]]+[1-9][0-9]* \(bytes\)' >/dev/null; then
    fail 'packed leaf fixture has no nonempty DT_RELRSZ'
fi
if ! readelf -dW "$fixtures/libleaf.so" | grep -E '\(RELRENT\)[[:space:]]+8 \(bytes\)' >/dev/null; then
    fail 'packed leaf fixture DT_RELRENT drifted'
fi
for binary in "$fixtures/main-musl" "$fixtures/main-crabc" "$fixtures/libmid.so" "$fixtures/libleaf.so"; do
    if ! readelf -lW "$binary" | grep 'GNU_RELRO' >/dev/null; then
        fail "fixture did not emit PT_GNU_RELRO: $binary"
    fi
done
for binary in "$fixtures/libmid.so" "$fixtures/libleaf.so"; do
    if readelf -rW "$binary" | awk '/R_X86_64_/ { if ($3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" && $3 != "R_X86_64_JUMP_SLOT") exit 1 }'; then :; else
        fail "fixture escaped the relocation whitelist: $binary"
    fi
done
relocations="$(readelf -rW "$fixtures/main-crabc" "$fixtures/libmid.so" "$fixtures/libleaf.so")"
for relocation in R_X86_64_RELATIVE R_X86_64_GLOB_DAT R_X86_64_JUMP_SLOT; do
    if ! grep "$relocation" <<<"$relocations" >/dev/null; then
        fail "fixture did not exercise $relocation"
    fi
done

run_candidate() {
    chroot "$root" /fixtures/main-crabc
}
run_oracle() {
    chroot "$oracle_root" /fixtures/main-musl
}

run_oracle
run_candidate

expect_candidate_rejection() {
    local expected_message="$1"
    local label="$2"
    local output status
    set +e
    output="$(chroot "$root" /fixtures/main-crabc 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 127 ] || [ "$output" != "$expected_message" ]; then
        printf 'ERROR: candidate did not fail closed for %s (status %s, output %q)\n' \
            "$label" "$status" "$output" >&2
        exit 1
    fi
}

expect_candidate_acceptance() {
    local label="$1"
    set +e
    chroot "$root" /fixtures/main-crabc >/dev/null 2>"$work/rejected.stderr"
    local status=$?
    set -e
    [ "$status" -eq 0 ] || {
        printf 'ERROR: valid %s did not run on the installed product (status %s)\n' \
            "$label" "$status" >&2
        cat "$work/rejected.stderr" >&2
        exit 1
    }
}

# --- malformed file ranges, tags, tables and main lifecycle -----------------
cp "$fixtures/libmid.so" "$work/libmid-valid.so"
program_header_count="$(od -An -tu2 -j56 -N2 "$fixtures/libmid.so" | tr -d '[:space:]')"
executable_load_header_offset=''
for ((index = 0; index < program_header_count; index++)); do
    offset=$((64 + index * 56))
    kind="$(od -An -tx4 -j"$offset" -N4 "$fixtures/libmid.so" | tr -d '[:space:]')"
    flags="$(od -An -tx4 -j$((offset + 4)) -N4 "$fixtures/libmid.so" | tr -d '[:space:]')"
    if [ "$kind" = 00000001 ] && (( (16#$flags) & 1 )); then
        executable_load_header_offset="$offset"
        break
    fi
done
[ -n "$executable_load_header_offset" ] || fail 'fixture has no executable PT_LOAD header'
printf '\000\000\020\000\000\000\000\000' | dd of="$fixtures/libmid.so" bs=1 seek=$((executable_load_header_offset + 8)) conv=notrunc status=none
expect_candidate_rejection graph 'midmap file-range PT_LOAD'
mv "$work/libmid-valid.so" "$fixtures/libmid.so"

dynamic_entry_offset() {
    local binary="$1"
    local wanted_tag="$2"
    local dynamic_offset dynamic_size entry tag
    dynamic_offset="$(objdump -h "$binary" | awk '$2 == ".dynamic" { print "0x" $6 }')"
    dynamic_size="$(objdump -h "$binary" | awk '$2 == ".dynamic" { print "0x" $3 }')"
    [ -n "$dynamic_offset" ] && [ -n "$dynamic_size" ] || return 1
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
    objdump -h "$1" | awk '$2 == ".relr.dyn" { print "0x" $6 }'
}
relr_section_size() {
    objdump -h "$1" | awk '$2 == ".relr.dyn" { print "0x" $3 }'
}
relr_entry_kind() {
    local binary="$1" offset="$2" word
    word="$(od -An -tx8 -j"$offset" -N8 "$binary" | tr -d '[:space:]')"
    case "${word: -1}" in
        1|3|5|7|9|b|d|f) printf '%s\n' bitmap ;;
        0|2|4|6|8|a|c|e) printf '%s\n' direct ;;
        *) return 1 ;;
    esac
}

relr_offset="$(relr_section_offset "$fixtures/libleaf.so")"
relr_size="$(relr_section_size "$fixtures/libleaf.so")"
[ -n "$relr_offset" ] && [ -n "$relr_size" ] && (( relr_size > 0 && relr_size % 8 == 0 )) ||
    fail 'packed leaf fixture has no integral .relr.dyn payload'
relr_direct_count=0
relr_bitmap_count=0
for ((entry = 0; entry < relr_size / 8; entry++)); do
    case "$(relr_entry_kind "$fixtures/libleaf.so" $((relr_offset + entry * 8)))" in
        direct) relr_direct_count=$((relr_direct_count + 1)) ;;
        bitmap) relr_bitmap_count=$((relr_bitmap_count + 1)) ;;
        *) fail 'packed leaf fixture has an unreadable .relr.dyn word' ;;
    esac
done
(( relr_direct_count > 0 && relr_bitmap_count > 0 )) ||
    fail 'packed leaf fixture did not exercise both direct and bitmap RELR records'
[ "$(relr_entry_kind "$fixtures/libleaf.so" "$relr_offset")" = direct ] ||
    fail 'packed leaf fixture does not begin its RELR stream with a direct address'
relr_dynamic_entry="$(dynamic_entry_offset "$fixtures/libleaf.so" 0000000000000024 || true)"
relrent_dynamic_entry="$(dynamic_entry_offset "$fixtures/libleaf.so" 0000000000000025 || true)"
rela_dynamic_entry="$(dynamic_entry_offset "$fixtures/libleaf.so" 0000000000000007 || true)"
[ -n "$relr_dynamic_entry" ] && [ -n "$relrent_dynamic_entry" ] && [ -n "$rela_dynamic_entry" ] ||
    fail 'packed leaf fixture lacks required relocation dynamic entries'

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
printf '\000\000\000\160\000\000\000\000' | dd of="$fixtures/libleaf.so" bs=1 seek="$relrent_dynamic_entry" conv=notrunc status=none
expect_candidate_rejection graph 'incomplete DT_RELR triple'
mv "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
printf '\020\000\000\000\000\000\000\000' | dd of="$fixtures/libleaf.so" bs=1 seek=$((relrent_dynamic_entry + 8)) conv=notrunc status=none
expect_candidate_rejection graph 'DT_RELRENT wrong size'
mv "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
printf '\377\377\377\377\377\377\377\177' | dd of="$fixtures/libleaf.so" bs=1 seek=$((relr_dynamic_entry + 8)) conv=notrunc status=none
expect_candidate_rejection graph 'DT_RELR outside PT_LOAD'
mv "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
dd if="$work/libleaf-valid.so" of="$fixtures/libleaf.so" bs=1 skip=$((rela_dynamic_entry + 8)) seek=$((relr_dynamic_entry + 8)) count=8 conv=notrunc status=none
expect_candidate_rejection reloc 'overlapping RELR/RELA tables'
mv "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
printf '\001' | dd of="$fixtures/libleaf.so" bs=1 seek=$((relr_offset)) conv=notrunc status=none
expect_candidate_rejection reloc 'RELR bitmap without address cursor'
mv "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
printf '\000\000\000\000\000\000\000\000' | dd of="$fixtures/libleaf.so" bs=1 seek=$((relr_offset)) conv=notrunc status=none
expect_candidate_rejection reloc 'RELR direct target not writable'
mv "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
last_relr_entry_offset=$((relr_offset + relr_size - 8))
dd if="$work/libleaf-valid.so" of="$fixtures/libleaf.so" bs=1 skip=$((relr_offset)) seek="$last_relr_entry_offset" count=8 conv=notrunc status=none
expect_candidate_rejection ctorplan 'duplicate RELR target'
mv "$work/libleaf-valid.so" "$fixtures/libleaf.so"

# The installed product is a general loader: a valid over-cap leaf must run,
# exactly as the pinned musl reference does.  This replaces the retired
# private interpreter's deliberate 512-entry cap with interoperability on the
# product's complete relocation path.
cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
cp "$fixtures/libleaf-target-overcap.so" "$fixtures/libleaf.so"
run_oracle
expect_candidate_acceptance 'target-over-cap RELR leaf'
cp "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
cp "$fixtures/libleaf-record-overcap.so" "$fixtures/libleaf.so"
run_oracle
expect_candidate_acceptance 'record-over-cap RELR leaf'
cp "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
cp "$fixtures/libleaf-zero-bit-overcap.so" "$fixtures/libleaf.so"
record_overcap_relr_offset="$(relr_section_offset "$fixtures/libleaf.so")"
record_overcap_relr_size="$(relr_section_size "$fixtures/libleaf.so")"
{
    for ((entry = 1; entry < record_overcap_relr_size / 8; entry++)); do
        printf '\001\000\000\000\000\000\000\000'
    done
} | dd of="$fixtures/libleaf.so" bs=1 seek=$((record_overcap_relr_offset + 8)) conv=notrunc status=none
run_oracle
expect_candidate_acceptance 'zero-bit over-cap RELR leaf'
cp "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libleaf.so" "$work/libleaf-valid.so"
program_header_count="$(od -An -tu2 -j56 -N2 "$fixtures/libleaf.so" | tr -d '[:space:]')"
stack_header_offset=''
for ((index = 0; index < program_header_count; index++)); do
    offset=$((64 + index * 56))
    kind="$(od -An -tx4 -j"$offset" -N4 "$fixtures/libleaf.so" | tr -d '[:space:]')"
    if [ "$kind" = 6474e551 ]; then
        stack_header_offset="$offset"
        break
    fi
done
[ -n "$stack_header_offset" ] || fail 'fixture has no disposable PT_GNU_STACK header'
printf '\007\000\000\000' | dd of="$fixtures/libleaf.so" bs=1 seek="$stack_header_offset" conv=notrunc status=none
expect_candidate_rejection graph 'PT_GNU_STACK retagged as PT_TLS'
mv "$work/libleaf-valid.so" "$fixtures/libleaf.so"

cp "$fixtures/libmid.so" "$work/libmid-valid.so"
rela_offset="$(objdump -h "$fixtures/libmid.so" | awk '$2 == ".rela.dyn" { print "0x" $6 }')"
[ -n "$rela_offset" ] || fail 'fixture has no .rela.dyn table to mutate'
printf '\005\000\000\000\000\000\000\000' | dd of="$fixtures/libmid.so" bs=1 seek=$((rela_offset + 8)) conv=notrunc status=none
expect_candidate_rejection reloc 'R_X86_64_COPY relocation'
mv "$work/libmid-valid.so" "$fixtures/libmid.so"

cp "$fixtures/libmid.so" "$work/libmid-valid.so"
printf '\377\377\377\377\377\377\377\177' | dd of="$fixtures/libmid.so" bs=1 seek=$((rela_offset)) conv=notrunc status=none
expect_candidate_rejection reloc 'RELA target outside writable PT_LOAD'
mv "$work/libmid-valid.so" "$fixtures/libmid.so"

cp "$fixtures/libmid.so" "$work/libmid-valid.so"
rela_dynamic_entry="$(dynamic_entry_offset "$fixtures/libmid.so" 0000000000000007 || true)"
[ -n "$rela_dynamic_entry" ] || fail 'fixture has no DT_RELA entry to mutate'
printf '\377\377\377\377\377\377\377\177' | dd of="$fixtures/libmid.so" bs=1 seek=$((rela_dynamic_entry + 8)) conv=notrunc status=none
expect_candidate_rejection graph 'DT_RELA address outside PT_LOAD'
mv "$work/libmid-valid.so" "$fixtures/libmid.so"

cp "$fixtures/libmid.so" "$work/libmid-valid.so"
flags_dynamic_entry="$(dynamic_entry_offset "$fixtures/libmid.so" 000000000000001e || true)"
[ -n "$flags_dynamic_entry" ] || fail 'fixture has no disposable DT_FLAGS entry'
printf '\044\000\000\000\000\000\000\000' | dd of="$fixtures/libmid.so" bs=1 seek="$flags_dynamic_entry" conv=notrunc status=none
expect_candidate_rejection graph 'lone DT_RELR'
mv "$work/libmid-valid.so" "$fixtures/libmid.so"

cp "$fixtures/libmid.so" "$work/libmid-valid.so"
flags_dynamic_entry="$(dynamic_entry_offset "$fixtures/libmid.so" 000000000000001e || true)"
printf '\026\000\000\000\000\000\000\000' | dd of="$fixtures/libmid.so" bs=1 seek="$flags_dynamic_entry" conv=notrunc status=none
expect_candidate_rejection graph 'DT_TEXTREL'
mv "$work/libmid-valid.so" "$fixtures/libmid.so"

cp "$fixtures/libmid.so" "$work/libmid-valid.so"
flags_dynamic_entry="$(dynamic_entry_offset "$fixtures/libmid.so" 000000000000001e || true)"
printf '\020\000\000\000\000\000\000\000' | dd of="$fixtures/libmid.so" bs=1 seek=$((flags_dynamic_entry + 8)) conv=notrunc status=none
expect_candidate_rejection graph 'DF_STATIC_TLS'
mv "$work/libmid-valid.so" "$fixtures/libmid.so"

cp "$fixtures/main-crabc" "$work/main-crabc-valid"
main_flags_dynamic_entry="$(dynamic_entry_offset "$fixtures/main-crabc" 000000000000001e || true)"
[ -n "$main_flags_dynamic_entry" ] || fail 'fixture main has no disposable DT_FLAGS entry'
printf '\014\000\000\000\000\000\000\000' | dd of="$fixtures/main-crabc" bs=1 seek="$main_flags_dynamic_entry" conv=notrunc status=none
expect_candidate_rejection mainelf 'main DT_INIT'
mv "$work/main-crabc-valid" "$fixtures/main-crabc"

printf '%s\n' 'installed initial dependency graph: PASS (product ELF/relocation facts, musl-differential positive graph, fail-closed malformed ELF/TLS/lifecycle negatives)'
