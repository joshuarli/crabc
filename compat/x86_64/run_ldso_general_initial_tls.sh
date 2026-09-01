#!/usr/bin/env bash
# Native evidence for private x86 general-initial TLS materialization.
#
# This is not a dynamic-loader product test. It proves one bounded arbitrary
# initial DT_NEEDED graph can retain loader-owned generation-one TLS state,
# materialize the main thread before TLS relocations are observed by code, and
# reject malformed/runtime-growth-shaped inputs before ARCH_SET_FS. The
# positive diamond has duplicate shared dependencies plus distinct template,
# tbss, alignment, and candidate-only dependency DT_INIT_ARRAY constructor
# witnesses. The naked pinned-musl reference intentionally bypasses CRT
# dispatch, so it remains the initial-TLS value/layout oracle rather than a
# constructor-order differential. The candidate exercises only
# dependency-first startup callbacks after initial TLS materialization; it
# does not exercise pthread workers, main/CRT lifecycle, dynamic CRT handoff,
# dlopen/dlclose, DTV replacement, or public RuntimeV1 publication.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE_ROOT="$ROOT_DIR/ldso/src/x86_64_general_initial_tls_source_root.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_main.c"
readonly LEFT="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_left.c"
readonly RIGHT="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_right.c"
readonly SHARED="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_shared.c"
readonly CAPACITY="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_capacity.c"
readonly TRACE="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_trace.c"
readonly MUSL_LOADER="/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
readonly MUSL_LIBC_ARCHIVE="/opt/musl-1.2.6/lib/libc.a"

fail() {
    printf 'ERROR: x86 general initial TLS: %s\n' "$*" >&2
    exit 1
}

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: general initial-TLS evidence requires native Linux/x86-64' >&2
    exit 2
fi
[ -x "$MUSL_LOADER" ] || fail 'pinned musl loader is missing'
[ -f "$MUSL_LIBC_ARCHIVE" ] || fail 'pinned musl archive is missing'
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"

work_dir="$(mktemp -d /tmp/crabc-x86-general-initial-tls.XXXXXX)"
if [ "${CRABC_LDSO_GENERAL_INITIAL_TLS_KEEP_WORK:-0}" = 1 ]; then
    printf '%s\n' "retained general initial-TLS work directory: $work_dir" >&2
else
    trap 'rm -rf -- "$work_dir"' EXIT
fi

# Run the typed state-machine regressions through the same isolated root.  The
# test cfg removes only the freestanding entry/panic glue; it leaves the
# general graph, identity, registry, layout, and rollback types unchanged.
rustc --edition=2021 --test \
    --cfg crabc_general_initial_graph --cfg crabc_general_initial_tls_materialization_v1 \
    "$SOURCE_ROOT" -o "$work_dir/general-initial-tls-state-tests"
env -i PATH=/usr/bin:/bin "$work_dir/general-initial-tls-state-tests"

case "${CRABC_LDSO_GENERAL_INITIAL_TLS_ROOT:-source}" in
    source)
        rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
            --cfg crabc_general_initial_graph --cfg crabc_general_initial_tls_materialization_v1 \
            "$SOURCE_ROOT" -o "$work_dir/libgeneral_initial_tls.a"
        cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
            -Wl,--whole-archive "$work_dir/libgeneral_initial_tls.a" -Wl,--no-whole-archive \
            -o "$work_dir/ld-crabc-x86_64-general-initial-tls.so"
        ;;
    crabc-target)
        target_dir="$work_dir/ldso-target"
        CARGO_TARGET_DIR="$target_dir" \
        RUSTFLAGS='-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic' \
            cargo build --locked --target x86_64-unknown-linux-musl -p crabc-ldso \
                --no-default-features --features x86_64-general-initial-tls-interpreter
        cp "$target_dir/x86_64-unknown-linux-musl/debug/libldso.so" \
            "$work_dir/ld-crabc-x86_64-general-initial-tls.so"
        ;;
    *)
        printf '%s\n' 'ERROR: unsupported general initial-TLS root selection' >&2
        exit 2
        ;;
esac

interpreter="$work_dir/ld-crabc-x86_64-general-initial-tls.so"
test "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN
if readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)|\((RELR|RELRSZ|RELRENT)\)'; then
    fail 'general initial-TLS interpreter selected an external bootstrap runtime'
fi
if readelf -lW "$interpreter" | grep -q ' TLS '; then
    fail 'general initial-TLS interpreter selected interpreter TLS'
fi
if ! readelf --dyn-syms -W "$interpreter" | awk '$8 == "__tls_get_addr" && $7 != "UND" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'candidate interpreter did not own __tls_get_addr'
fi

left_dir="$work_dir/left"
right_dir="$work_dir/right"
shared_dir="$work_dir/shared"
mkdir "$left_dir" "$right_dir" "$shared_dir"

cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libshared.so \
    "$SHARED" -o "$shared_dir/libshared.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libleft.so -Wl,-rpath,"$shared_dir" \
    "$LEFT" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$left_dir/libleft.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libright.so -Wl,-rpath,"$shared_dir" \
    "$RIGHT" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$right_dir/libright.so"

build_main() {
    local selected_interpreter="$1"
    local output="$2"
    local mode="$3"
    local -a main_cppflags=()
    local -a main_linker_inputs=()
    case "$mode" in
        musl-reference)
            # The bare graph has no libc DT_NEEDED edge. Retain musl's pinned
            # resolver object only in the oracle executable, never candidate.
            main_linker_inputs=(-Wl,-u,__tls_get_addr "$MUSL_LIBC_ARCHIVE")
            ;;
        candidate)
            main_cppflags=(-DCRABC_GENERAL_INITIAL_TLS_CANDIDATE)
            main_linker_inputs=(-Wl,--unresolved-symbols=ignore-all)
            ;;
        *) fail "unknown main mode: $mode" ;;
    esac
    cc -nostdlib -fPIE -pie -ftls-model=global-dynamic -mtls-dialect=gnu \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
        -Wl,--dynamic-linker,"$selected_interpreter" -Wl,-rpath,"$left_dir:$right_dir:$shared_dir" \
        "${main_cppflags[@]}" "$START" "$MAIN" -L"$left_dir" -L"$right_dir" \
        -L"$shared_dir" -Wl,--no-as-needed -l:libleft.so -l:libright.so -l:libshared.so \
        "${main_linker_inputs[@]}" \
        -o "$output"
}

build_main "$MUSL_LOADER" "$work_dir/main-musl" musl-reference
build_main "$interpreter" "$work_dir/main-crabc" candidate

require_needed_names() {
    local binary="$1"
    shift
    local actual expected=''
    actual="$(readelf -dW "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    for name in "$@"; do
        if [ -n "$expected" ]; then
            expected+=$'\n'
        fi
        expected+="$name"
    done
    [ "$actual" = "$expected" ] || fail "unexpected DT_NEEDED graph in $binary"
}

require_needed_names "$work_dir/main-crabc" libleft.so libright.so libshared.so
require_needed_names "$left_dir/libleft.so" libshared.so
require_needed_names "$right_dir/libright.so" libshared.so
require_needed_names "$shared_dir/libshared.so"

require_dependency_init_array() {
    local binary="$1"
    local dynamic
    dynamic="$(readelf -dW "$binary")"
    if ! grep -Fq '(INIT_ARRAY)' <<<"$dynamic" \
        || ! grep -Fq '(INIT_ARRAYSZ)' <<<"$dynamic"; then
        fail "dependency fixture did not retain its DT_INIT_ARRAY pair: $binary"
    fi
    # The bounded loader lifecycle admits only dependency init arrays. Keep
    # legacy/finalization tags out of this positive TLS differential rather
    # than accidentally making it exercise an unselected lifecycle owner.
    if grep -Eq '\((INIT|FINI|FINI_ARRAY|FINI_ARRAYSZ|PREINIT_ARRAY|PREINIT_ARRAYSZ)\)' <<<"$dynamic"; then
        fail "dependency fixture selected an out-of-scope lifecycle tag: $binary"
    fi
}

# Each DSO has one priority-101 dependency callback. The pinned-musl raw-main
# route intentionally bypasses all constructors; the candidate-only main
# validation proves its loader calls shared once before both branches observe
# their own ready TLS. It intentionally leaves sibling order to each loader's
# valid graph traversal.
for binary in "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so"; do
    require_dependency_init_array "$binary"
done
if readelf -dW "$work_dir/main-crabc" | grep -Eq '\((INIT_ARRAY|INIT_ARRAYSZ|INIT|FINI|FINI_ARRAY|FINI_ARRAYSZ|PREINIT_ARRAY|PREINIT_ARRAYSZ)\)'; then
    fail 'main fixture selected lifecycle metadata outside the dependency-only boundary'
fi

for binary in "$work_dir/main-crabc" "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so"; do
    readelf -lW "$binary" | grep -q ' TLS ' || fail "fixture lacks PT_TLS: $binary"
    if readelf -rW "$binary" | awk '/R_X86_64_/ { if ($3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" && $3 != "R_X86_64_JUMP_SLOT" && $3 != "R_X86_64_DTPMOD64" && $3 != "R_X86_64_DTPOFF64") exit 1 }'; then :; else
        fail "fixture escaped the initial GNU-Dynamic relocation profile: $binary"
    fi
done

relocations="$(readelf -rW "$work_dir/main-crabc" "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so")"
for relocation in R_X86_64_DTPMOD64 R_X86_64_DTPOFF64; do
    grep -q "$relocation" <<<"$relocations" || fail "fixture did not exercise $relocation"
done
grep -q '__tls_get_addr' <<<"$relocations" || fail 'fixture did not call __tls_get_addr'
if grep -Eq 'R_X86_64_(TPOFF64|TPOFF32|GOTTPOFF|TLSDESC|GOTPC32_TLSDESC|TLSDESC_CALL)' <<<"$relocations"; then
    fail 'fixture escaped the explicit DTPMOD64/DTPOFF64-only TLS boundary'
fi
require_zero_offset_tls_symbol() {
    local binary="$1"
    local symbol="$2"
    if ! readelf -Ws "$binary" | awk -v symbol="$symbol" '$4 == "TLS" && $8 == symbol && $2 == "0000000000000000" { found = 1 } END { exit found ? 0 : 1 }'; then
        fail "direct __tls_get_addr witness no longer has module offset zero: $symbol"
    fi
}

# The candidate calls the standard two-word GNU TLS index ABI directly for
# each loader-order ID.  These symbols must remain the base of their image so
# index offset zero independently witnesses main=1, left=2, shared=3, and
# right=4 through both the DTV and the resolver.
require_zero_offset_tls_symbol "$work_dir/main-crabc" general_main_tls
require_zero_offset_tls_symbol "$left_dir/libleft.so" general_left_tls
require_zero_offset_tls_symbol "$shared_dir/libshared.so" general_shared_tls
require_zero_offset_tls_symbol "$right_dir/libright.so" general_right_tls

main_crabc_interpreter="$(readelf -lW "$work_dir/main-crabc" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
main_musl_interpreter="$(readelf -lW "$work_dir/main-musl" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
[ "$main_crabc_interpreter" = "$interpreter" ] || fail 'candidate PT_INTERP drifted'
[ "$main_musl_interpreter" = "$MUSL_LOADER" ] || fail 'musl reference PT_INTERP drifted'

(cd "$work_dir" && env -i PATH=/usr/bin:/bin "$work_dir/main-musl")
(cd "$work_dir" && env -i PATH=/usr/bin:/bin "$work_dir/main-crabc")

# Trace expected failures to prove malformed input does not get as far as the
# private ARCH_SET_FS transition. The tracer itself is ordinary harness code,
# never a candidate dependency.
cc -D_GNU_SOURCE -std=c11 "$TRACE" -o "$work_dir/no-arch-set-fs-trace"

expect_candidate_rejection_before_fs() {
    local expected_message="$1"
    local case_name="$2"
    local output status
    set +e
    output="$(cd "$work_dir" && env -i PATH=/usr/bin:/bin "$work_dir/no-arch-set-fs-trace" "$work_dir/main-crabc" 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 0 ] || ! grep -Fxq "$expected_message" <<<"$output"; then
        printf 'ERROR: candidate did not reject before ARCH_SET_FS (%s)\n' "$case_name" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

program_header_offset_for_type() {
    local binary="$1"
    local wanted_type="$2"
    local count index offset kind
    count="$(od -An -tu2 -j56 -N2 "$binary" | tr -d '[:space:]')"
    for ((index = 0; index < count; index++)); do
        offset=$((64 + index * 56))
        kind="$(od -An -tx4 -j"$offset" -N4 "$binary" | tr -d '[:space:]')"
        if [ "$kind" = "$wanted_type" ]; then
            printf '%s\n' "$offset"
            return 0
        fi
    done
    return 1
}

# Return the readable PT_LOAD whose zero-fill extension contains the first
# byte past its file-backed prefix.  Repointing PT_TLS at that address keeps
# the ELF vaddr/file-offset phase valid while making a nonempty initialized
# prefix cross the exact file-backed boundary the loader must reject.
readable_load_header_with_bss() {
    local binary="$1"
    local count index offset kind flags filesz memsz
    count="$(od -An -tu2 -j56 -N2 "$binary" | tr -d '[:space:]')"
    for ((index = 0; index < count; index++)); do
        offset=$((64 + index * 56))
        kind="$(od -An -tx4 -j"$offset" -N4 "$binary" | tr -d '[:space:]')"
        [ "$kind" = 00000001 ] || continue
        flags="$(od -An -tu4 -j$((offset + 4)) -N4 "$binary" | tr -d '[:space:]')"
        filesz="$(od -An -tu8 -j$((offset + 32)) -N8 "$binary" | tr -d '[:space:]')"
        memsz="$(od -An -tu8 -j$((offset + 40)) -N8 "$binary" | tr -d '[:space:]')"
        if (( (flags & 4) != 0 && memsz > filesz )); then
            printf '%s\n' "$offset"
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
    [ -n "$rela_offset" ] && [ -n "$rela_size" ] || return 1
    (( rela_size % 24 == 0 )) || return 1
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

write_u32_le() {
    local binary="$1"
    local offset="$2"
    local value="$3"
    local byte escape
    {
        for ((index = 0; index < 4; index++)); do
            byte=$((value & 255))
            printf -v escape '\\%03o' "$byte"
            printf '%b' "$escape"
            value=$((value >> 8))
        done
    } | dd of="$binary" bs=1 seek="$offset" conv=notrunc status=none
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
[ -n "$tls_filesz" ] && [ -n "$tls_memsz" ] && [ -n "$tls_file_offset" ] && [ -n "$tls_align" ] && [ -n "$load_file_offset" ] && [ -n "$load_virtual_address" ] && [ -n "$load_filesz" ] && [ -n "$load_memsz" ] || fail 'fixture TLS or PT_LOAD header is unreadable'
(( tls_filesz < tls_memsz )) || fail 'fixture lacks a tbss range for unreadable-prefix testing'
(( tls_align > 1 && (tls_align & (tls_align - 1)) == 0 )) || fail 'fixture lacks a phase-sensitive TLS alignment'
(( load_memsz > load_filesz )) || fail 'fixture PT_LOAD has no BSS boundary'

# p_filesz > p_memsz, non-power-of-two p_align, phase mismatch, a second TLS
# record, a prefix stretching into tbss, and arithmetic-overflow-shaped memsz
# are all rejected during graph admission. No negative may install FS.
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
# The first BSS byte is valid virtual memory but lies immediately past the
# file-backed PT_LOAD prefix.  Claiming one initialized PT_TLS byte there must
# fail `virtual_range_in_readable_file_load`, not merely rely on a short file.
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
for mutation in unsupported:0 tpoff:18 tlsdesc:36; do
    label="${mutation%%:*}"
    kind="${mutation##*:}"
    cp "$shared_binary" "$shared_binary.valid"
    write_u32_le "$shared_binary" "$rela_info_offset" "$kind"
    expect_candidate_rejection_before_fs reloc "$label-relocation"
    mv "$shared_binary.valid" "$shared_binary"
done

build_capacity_chain() {
    local capacity_dir="$work_dir/capacity"
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
cp "$work_dir/capacity/libleft.so" "$left_dir/libleft.so"
expect_candidate_rejection_before_fs graph object-capacity
mv "$left_dir/libleft.so.valid" "$left_dir/libleft.so"

printf '%s\n' 'x86 general initial TLS materialization: PASS (dependency-first DT_INIT_ARRAY TLS callbacks; initial-only DTPMOD64/DTPOFF64 diamond; generation-one state; pre-FS rejection)'
