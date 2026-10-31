#!/usr/bin/env bash
# Installed-product evidence for initial GNU-dynamic TLS materialization.
#
# The retired private general-initial-TLS interpreter proved one bounded
# arbitrary dependency graph with loader-owned generation-one TLS.  The
# installed product owns the same graph transaction unconditionally, so the
# same diamond runs as an ordinary product application and every malformed
# input must still fail before the loader installs FS.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$(dirname "${BASH_SOURCE[0]}")/native_build_environment.sh"
readonly PRODUCT="${1:?usage: $0 DYNAMIC-SYSROOT}"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_main.c"
readonly LEFT="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_left.c"
readonly RIGHT="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_right.c"
readonly SHARED="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_shared.c"
readonly CONSUMER="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_consumer.c"
readonly CAPACITY="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_capacity.c"
readonly TRACE="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_trace.c"
readonly MUSL_LOADER="/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
readonly MUSL_LIBC="/opt/musl-1.2.6/lib/libc.so"
readonly ORACLE_CC="/usr/local/bin/crabc-x86_64-musl-gcc"

fail() {
    printf 'ERROR: initial TLS product: %s\n' "$*" >&2
    exit 1
}

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: initial-TLS evidence requires native Linux/x86-64' >&2
    exit 2
fi
[ -d "$PRODUCT" ] || fail "installed product missing: $PRODUCT"
[ -x "$MUSL_LOADER" ] && [ -f "$MUSL_LIBC" ] || fail 'pinned musl oracle is missing'
case "${TMPDIR:-}" in
    "$ROOT_DIR"/.work/*) ;;
    *) printf 'TMPDIR must be under %s/.work\n' "$ROOT_DIR" >&2; exit 2 ;;
esac
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work="$(mktemp -d "$TMPDIR/initial-tls-product.XXXXXX")"
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

loader="$root/lib/ld-crabc-x86_64.so.1"
[ "$(readelf -h "$loader" | awk '/Type:/{print $2}')" = DYN ] ||
    fail 'installed loader is not ET_DYN'
if readelf -dW "$loader" | grep -E '\(NEEDED\)|\(INTERP\)' >/dev/null; then
    fail 'installed loader selected an external runtime'
fi
readelf -lW "$loader" | grep ' TLS ' >/dev/null ||
    fail 'installed loader lost its runtime PT_TLS'
readelf -lW "$loader" | grep 'GNU_RELRO' >/dev/null ||
    fail 'installed loader lost PT_GNU_RELRO'
for tag in RELR RELRSZ RELRENT; do
    readelf -dW "$loader" | grep "($tag)" >/dev/null || fail "installed loader lacks DT_$tag"
done
if ! readelf --dyn-syms -W "$loader" | awk '$8 == "__tls_get_addr" && $7 != "UND" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'installed loader does not own __tls_get_addr'
fi

left_dir="$fixtures/left"
right_dir="$fixtures/right"
shared_dir="$fixtures/shared"
consumer_dir="$fixtures/consumer"
mkdir "$left_dir" "$right_dir" "$shared_dir" "$consumer_dir"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libshared.so \
    "$SHARED" -o "$shared_dir/libshared.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libleft.so -Wl,-rpath,/fixtures/shared \
    "$LEFT" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$left_dir/libleft.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libright.so -Wl,-rpath,/fixtures/shared \
    "$RIGHT" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$right_dir/libright.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libconsumer.so -Wl,-rpath,/fixtures/shared \
    "$CONSUMER" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$consumer_dir/libconsumer.so"

cc -O2 -fPIE -ftls-model=global-dynamic -DCRABC_PRODUCT_TLS_LAYOUT -c "$MAIN" -o "$work/main.o"
deps=(-L"$left_dir" -L"$right_dir" -L"$shared_dir" -L"$consumer_dir"
      -Wl,--no-as-needed -l:libleft.so -l:libright.so -l:libshared.so -l:libconsumer.so)
cc -nostdlib -fPIE -pie -ftls-model=global-dynamic -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,--dynamic-linker,/lib/ld-crabc-x86_64.so.1 -Wl,-rpath,/fixtures/left:/fixtures/right:/fixtures/shared:/fixtures/consumer \
    -Wl,-rpath-link,"$left_dir" -Wl,-rpath-link,"$right_dir" -Wl,-rpath-link,"$shared_dir" -Wl,-rpath-link,"$consumer_dir" \
    "$PRODUCT/usr/lib/Scrt1.o" "$PRODUCT/usr/lib/crti.o" "$work/main.o" \
    "$PRODUCT/usr/lib/crabc-dynamic-attach.o" -L"$PRODUCT/usr/lib" -lc \
    "$PRODUCT/usr/lib/libcrabc-builtins.a" "$PRODUCT/usr/lib/crtn.o" \
    "${deps[@]}" -o "$fixtures/main-crabc"
"$ORACLE_CC" -O2 -fPIE -pie -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -Wl,-rpath,/fixtures/left:/fixtures/right:/fixtures/shared:/fixtures/consumer \
    "$work/main.o" "${deps[@]}" -o "$fixtures/main-musl"
cp -a "$fixtures/." "$oracle_fixtures/"

require_needed_names() {
    local binary="$1"
    shift
    local actual expected=''
    actual="$(readelf -dW "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    for name in "$@"; do
        [ -z "$expected" ] || expected+=$'\n'
        expected+="$name"
    done
    [ "$actual" = "$expected" ] || fail "unexpected DT_NEEDED graph in $binary"
}
require_needed_names "$fixtures/main-crabc" libc.so libleft.so libright.so libshared.so libconsumer.so
require_needed_names "$fixtures/main-musl" libleft.so libright.so libshared.so libconsumer.so libc.so
require_needed_names "$left_dir/libleft.so" libshared.so
require_needed_names "$right_dir/libright.so" libshared.so
require_needed_names "$shared_dir/libshared.so"
require_needed_names "$consumer_dir/libconsumer.so" libshared.so

if readelf -lW "$consumer_dir/libconsumer.so" | grep ' TLS ' >/dev/null; then
    fail 'consumer unexpectedly owns PT_TLS'
fi
consumer_relocations="$(readelf -rW "$consumer_dir/libconsumer.so")"
for symbol in general_shared_tls general_shared_tbss; do
    for relocation in R_X86_64_DTPMOD64 R_X86_64_DTPOFF64; do
        grep -E "${relocation}.*${symbol}([[:space:]]|$)" <<<"$consumer_relocations" >/dev/null ||
            fail "consumer lacks named $relocation for $symbol"
    done
    if ! readelf -Ws "$consumer_dir/libconsumer.so" | awk -v symbol="$symbol" '$4 == "TLS" && $7 == "UND" && $8 == symbol { found = 1 } END { exit found ? 0 : 1 }'; then
        fail "consumer lacks an undefined TLS import for $symbol"
    fi
done
if grep -E 'R_X86_64_(TPOFF64|TPOFF32|GOTTPOFF|TLSDESC|GOTPC32_TLSDESC|TLSDESC_CALL)' <<<"$consumer_relocations" >/dev/null; then
    fail 'consumer escaped the GNU dynamic-TLS relocation profile'
fi

for binary in "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so"; do
    dynamic="$(readelf -dW "$binary")"
    grep -F '(INIT_ARRAY)' <<<"$dynamic" >/dev/null && grep -F '(INIT_ARRAYSZ)' <<<"$dynamic" >/dev/null ||
        fail "dependency fixture lacks its DT_INIT_ARRAY pair: $binary"
    if grep -E '\((INIT|FINI|FINI_ARRAY|FINI_ARRAYSZ|PREINIT_ARRAY|PREINIT_ARRAYSZ)\)' <<<"$dynamic" >/dev/null; then
        fail "dependency fixture selected an out-of-scope lifecycle tag: $binary"
    fi
done
main_dynamic="$(readelf -dW "$fixtures/main-crabc")"
grep -F '(INIT)' <<<"$main_dynamic" >/dev/null && grep -F '(FINI)' <<<"$main_dynamic" >/dev/null ||
    fail 'main fixture lost its CRT-owned INIT/FINI pair'
if grep -E '\((INIT_ARRAY|INIT_ARRAYSZ|FINI_ARRAY|FINI_ARRAYSZ|PREINIT_ARRAY|PREINIT_ARRAYSZ)\)' <<<"$main_dynamic" >/dev/null; then
    fail 'main fixture selected dependency-style lifecycle metadata'
fi

for binary in "$fixtures/main-crabc" "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so"; do
    readelf -lW "$binary" | grep ' TLS ' >/dev/null || fail "fixture lacks PT_TLS: $binary"
    if readelf -rW "$binary" | awk '/R_X86_64_/ { if ($3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" && $3 != "R_X86_64_JUMP_SLOT" && $3 != "R_X86_64_DTPMOD64" && $3 != "R_X86_64_DTPOFF64" && $3 != "R_X86_64_TPOFF64") exit 1 }'; then :; else
        fail "fixture escaped the initial GNU-Dynamic relocation profile: $binary"
    fi
done
relocations="$(readelf -rW "$fixtures/main-crabc" "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so" "$consumer_dir/libconsumer.so")"
for relocation in R_X86_64_DTPMOD64 R_X86_64_DTPOFF64; do
    grep "$relocation" <<<"$relocations" >/dev/null || fail "fixture did not exercise $relocation"
done
grep '__tls_get_addr' <<<"$relocations" >/dev/null || fail 'fixture did not call __tls_get_addr'
if grep -E 'R_X86_64_(TLSDESC|GOTPC32_TLSDESC|TLSDESC_CALL)' <<<"$relocations" >/dev/null; then
    fail 'fixture escaped the explicit DTPMOD64/DTPOFF64-only TLS boundary'
fi
require_zero_offset_tls_symbol() {
    local binary="$1" symbol="$2"
    if ! readelf -Ws "$binary" | awk -v symbol="$symbol" '$4 == "TLS" && $8 == symbol && $2 == "0000000000000000" { found = 1 } END { exit found ? 0 : 1 }'; then
        fail "direct __tls_get_addr witness no longer has module offset zero: $symbol"
    fi
}
require_zero_offset_tls_symbol "$fixtures/main-crabc" general_main_tls
require_zero_offset_tls_symbol "$left_dir/libleft.so" general_left_tls
require_zero_offset_tls_symbol "$shared_dir/libshared.so" general_shared_tls
require_zero_offset_tls_symbol "$right_dir/libright.so" general_right_tls

main_crabc_interpreter="$(readelf -lW "$fixtures/main-crabc" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
main_musl_interpreter="$(readelf -lW "$fixtures/main-musl" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
[ "$main_crabc_interpreter" = /lib/ld-crabc-x86_64.so.1 ] || fail 'candidate PT_INTERP drifted'
[ "$main_musl_interpreter" = /lib/ld-musl-x86_64.so.1 ] || fail 'musl reference PT_INTERP drifted'

chroot "$oracle_root" /fixtures/main-musl >/dev/null
chroot "$root" /fixtures/main-crabc >/dev/null

cc -D_GNU_SOURCE -std=c11 -static "$TRACE" -o "$root/fixtures/no-arch-set-fs-trace"
expect_candidate_rejection_before_fs() {
    local expected_message="$1" case_name="$2" output status
    set +e
    output="$(chroot "$root" /fixtures/no-arch-set-fs-trace /fixtures/main-crabc 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 0 ] || ! grep -Fx "$expected_message" <<<"$output" >/dev/null; then
        printf 'ERROR: candidate did not reject before ARCH_SET_FS (%s, status %s)\n' "$case_name" "$status" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

program_header_offset_for_type() {
    local binary="$1" wanted_type="$2" count index offset kind
    count="$(od -An -tu2 -j56 -N2 "$binary" | tr -d '[:space:]')"
    for ((index = 0; index < count; index++)); do
        offset=$((64 + index * 56))
        kind="$(od -An -tx4 -j"$offset" -N4 "$binary" | tr -d '[:space:]')"
        if [ "$kind" = "$wanted_type" ]; then printf '%s\n' "$offset"; return 0; fi
    done
    return 1
}
readable_load_header_with_bss() {
    local binary="$1" count index offset kind flags filesz memsz
    count="$(od -An -tu2 -j56 -N2 "$binary" | tr -d '[:space:]')"
    for ((index = 0; index < count; index++)); do
        offset=$((64 + index * 56))
        kind="$(od -An -tx4 -j"$offset" -N4 "$binary" | tr -d '[:space:]')"
        [ "$kind" = 00000001 ] || continue
        flags="$(od -An -tu4 -j$((offset + 4)) -N4 "$binary" | tr -d '[:space:]')"
        filesz="$(od -An -tu8 -j$((offset + 32)) -N8 "$binary" | tr -d '[:space:]')"
        memsz="$(od -An -tu8 -j$((offset + 40)) -N8 "$binary" | tr -d '[:space:]')"
        if (( (flags & 4) != 0 && memsz > filesz )); then printf '%s\n' "$offset"; return 0; fi
    done
    return 1
}
rela_info_offset_for_type() {
    local binary="$1" wanted_type="$2" rela_offset rela_size record info expected_type
    rela_offset="$(objdump -h "$binary" | awk '$2 == ".rela.dyn" { print "0x" $6 }')"
    rela_size="$(objdump -h "$binary" | awk '$2 == ".rela.dyn" { print "0x" $3 }')"
    [ -n "$rela_offset" ] && [ -n "$rela_size" ] || return 1
    (( rela_size % 24 == 0 )) || return 1
    expected_type="$(printf '%08x' "$wanted_type")"
    for ((record = rela_offset; record < rela_offset + rela_size; record += 24)); do
        info="$(od -An -tx8 -j$((record + 8)) -N8 "$binary" | tr -d '[:space:]')"
        if [ "${info: -8}" = "$expected_type" ]; then printf '%s\n' $((record + 8)); return 0; fi
    done
    return 1
}
write_u32_le() {
    local binary="$1" offset="$2" value="$3" byte escape
    {
        for ((index = 0; index < 4; index++)); do
            byte=$((value & 255)); printf -v escape '\\%03o' "$byte"; printf '%b' "$escape"; value=$((value >> 8))
        done
    } | dd of="$binary" bs=1 seek="$offset" conv=notrunc status=none
}
write_u64_le() {
    local binary="$1" offset="$2" value="$3" byte escape
    {
        for ((index = 0; index < 8; index++)); do
            byte=$((value & 255)); printf -v escape '\\%03o' "$byte"; printf '%b' "$escape"; value=$((value >> 8))
        done
    } | dd of="$binary" bs=1 seek="$offset" conv=notrunc status=none
}

shared_binary="$shared_dir/libshared.so"
tls_header_offset="$(program_header_offset_for_type "$shared_binary" 00000007)" || fail 'fixture has no PT_TLS header'
stack_header_offset="$(program_header_offset_for_type "$shared_binary" 6474e551)" || fail 'fixture has no PT_GNU_STACK header'
load_header_offset="$(readable_load_header_with_bss "$shared_binary")" || fail 'fixture lacks a readable PT_LOAD BSS boundary'
tls_filesz="$(od -An -tu8 -j$((tls_header_offset + 32)) -N8 "$shared_binary" | tr -d '[:space:]')"
tls_memsz="$(od -An -tu8 -j$((tls_header_offset + 40)) -N8 "$shared_binary" | tr -d '[:space:]')"
tls_file_offset="$(od -An -tu8 -j$((tls_header_offset + 8)) -N8 "$shared_binary" | tr -d '[:space:]')"
tls_align="$(od -An -tu8 -j$((tls_header_offset + 48)) -N8 "$shared_binary" | tr -d '[:space:]')"
load_file_offset="$(od -An -tu8 -j$((load_header_offset + 8)) -N8 "$shared_binary" | tr -d '[:space:]')"
load_virtual_address="$(od -An -tu8 -j$((load_header_offset + 16)) -N8 "$shared_binary" | tr -d '[:space:]')"
load_filesz="$(od -An -tu8 -j$((load_header_offset + 32)) -N8 "$shared_binary" | tr -d '[:space:]')"
load_memsz="$(od -An -tu8 -j$((load_header_offset + 40)) -N8 "$shared_binary" | tr -d '[:space:]')"
[ -n "$tls_filesz" ] && [ -n "$tls_memsz" ] && [ -n "$tls_file_offset" ] && [ -n "$tls_align" ] &&
    [ -n "$load_file_offset" ] && [ -n "$load_virtual_address" ] && [ -n "$load_filesz" ] && [ -n "$load_memsz" ] ||
    fail 'fixture TLS or PT_LOAD header is unreadable'
(( tls_filesz < tls_memsz )) || fail 'fixture lacks a tbss range for unreadable-prefix testing'
(( tls_align > 1 && (tls_align & (tls_align - 1)) == 0 )) || fail 'fixture lacks a phase-sensitive TLS alignment'
(( load_memsz > load_filesz )) || fail 'fixture PT_LOAD has no BSS boundary'

cp "$shared_binary" "$shared_binary.valid"
write_u64_le "$shared_binary" $((tls_header_offset + 32)) $((tls_memsz + 1))
expect_candidate_rejection_before_fs graph p-filesz-greater-than-p-memsz
mv "$shared_binary.valid" "$shared_binary"

cp "$shared_binary" "$shared_binary.valid"
write_u64_le "$shared_binary" $((tls_header_offset + 48)) 3
expect_candidate_rejection_before_fs graph non-power-of-two-align
mv "$shared_binary.valid" "$shared_binary"

cp "$shared_binary" "$shared_binary.valid"
write_u64_le "$shared_binary" $((tls_header_offset + 8)) $((tls_file_offset + 1))
expect_candidate_rejection_before_fs graph vaddr-offset-phase
mv "$shared_binary.valid" "$shared_binary"

cp "$shared_binary" "$shared_binary.valid"
write_u64_le "$shared_binary" $((tls_header_offset + 8)) $((load_file_offset + load_filesz))
write_u64_le "$shared_binary" $((tls_header_offset + 16)) $((load_virtual_address + load_filesz))
write_u64_le "$shared_binary" $((tls_header_offset + 32)) 1
write_u64_le "$shared_binary" $((tls_header_offset + 40)) 1
expect_candidate_rejection_before_fs graph unreadable-initialized-prefix
mv "$shared_binary.valid" "$shared_binary"

cp "$shared_binary" "$shared_binary.valid"
write_u32_le "$shared_binary" "$stack_header_offset" 7
expect_candidate_rejection_before_fs graph duplicate-pt-tls
mv "$shared_binary.valid" "$shared_binary"

cp "$shared_binary" "$shared_binary.valid"
printf '\377\377\377\377\377\377\377\177' | dd of="$shared_binary" bs=1 seek=$((tls_header_offset + 40)) conv=notrunc status=none
expect_candidate_rejection_before_fs graph tls-overflow
mv "$shared_binary.valid" "$shared_binary"

rela_info_offset="$(rela_info_offset_for_type "$shared_binary" 16)" || fail 'fixture has no DTPMOD64 relocation to mutate'
for mutation in unsupported:65535 tpoff32:23 tlsdesc:36; do
    label="${mutation%%:*}"
    kind="${mutation##*:}"
    cp "$shared_binary" "$shared_binary.valid"
    write_u32_le "$shared_binary" "$rela_info_offset" "$kind"
    expect_candidate_rejection_before_fs reloc "$label-relocation"
    mv "$shared_binary.valid" "$shared_binary"
done

build_capacity_chain() {
    local capacity_dir="$work/capacity"
    mkdir "$capacity_dir"
    for ((index = 32; index >= 1; index--)); do
        current="cap$(printf '%02d' "$index")"
        if [ "$index" -eq 32 ]; then
            cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
                -Wl,-soname,"lib${current}.so" -DCRABC_CURRENT_SYMBOL="$current" \
                "$CAPACITY" -o "$capacity_dir/lib${current}.so"
            continue
        fi
        next="cap$(printf '%02d' $((index + 1)))"
        cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
            -Wl,-soname,"lib${current}.so" -Wl,-rpath,"$capacity_dir" \
            -DCRABC_CURRENT_SYMBOL="$current" -DCRABC_NEXT_SYMBOL="$next" "$CAPACITY" \
            -L"$capacity_dir" -Wl,--no-as-needed -l:"lib${next}.so" \
            -o "$capacity_dir/lib${current}.so"
    done
    cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,-soname,libleft.so -Wl,-rpath,"$capacity_dir" \
        -DCRABC_CURRENT_SYMBOL=left_value -DCRABC_NEXT_SYMBOL=cap01 "$CAPACITY" \
        -L"$capacity_dir" -Wl,--no-as-needed -l:libcap01.so \
        -o "$capacity_dir/libleft.so"
}

build_capacity_chain
cp "$left_dir/libleft.so" "$left_dir/libleft.so.valid"
cp "$work/capacity/libleft.so" "$left_dir/libleft.so"
expect_candidate_rejection_before_fs graph object-capacity
mv "$left_dir/libleft.so.valid" "$left_dir/libleft.so"

printf '%s\n' 'installed initial GNU-dynamic TLS: PASS (product TLS diamond, pinned musl value oracle, pre-FS malformed rejection)'
