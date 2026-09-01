#!/usr/bin/env bash
# Native x86-64 evidence for the first loader-owned general initial graph.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE_ROOT="$ROOT_DIR/ldso/src/x86_64_general_initial_graph_source_root.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_general_initial_graph_main.c"
readonly LEFT="$ROOT_DIR/compat/x86_64/ldso_general_initial_graph_left.c"
readonly RIGHT="$ROOT_DIR/compat/x86_64/ldso_general_initial_graph_right.c"
readonly SHARED="$ROOT_DIR/compat/x86_64/ldso_general_initial_graph_shared.c"

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: general initial-graph evidence requires native Linux/x86-64' >&2
    exit 2
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# Exercise the graph-only lifecycle planner through the same isolated source
# root. These tests prove the declared-needed diamond postorder and explicit
# cycle rejection without making either condition depend on fixture layout.
rustc --edition=2021 --test --cfg crabc_general_initial_graph \
    "$SOURCE_ROOT" -o "$work_dir/general-initial-graph-state-tests"
env -i PATH=/usr/bin:/bin "$work_dir/general-initial-graph-state-tests"

case "${CRABC_LDSO_GENERAL_INITIAL_GRAPH_ROOT:-source}" in
    source)
        rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
            --cfg crabc_general_initial_graph "$SOURCE_ROOT" -o "$work_dir/libgeneral_initial_graph.a"
        cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
            -Wl,--whole-archive "$work_dir/libgeneral_initial_graph.a" -Wl,--no-whole-archive \
            -o "$work_dir/ld-crabc-x86_64-general-initial-graph.so"
        ;;
    crabc-target)
        target_dir="$work_dir/ldso-target"
        CARGO_TARGET_DIR="$target_dir" \
        RUSTFLAGS='-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic' \
            cargo build --locked --target x86_64-unknown-linux-musl -p crabc-ldso \
                --no-default-features --features x86_64-general-initial-interpreter
        cp "$target_dir/x86_64-unknown-linux-musl/debug/libldso.so" \
            "$work_dir/ld-crabc-x86_64-general-initial-graph.so"
        ;;
    *)
        printf '%s\n' 'ERROR: unsupported general initial-graph root selection' >&2
        exit 2
        ;;
esac

interpreter="$work_dir/ld-crabc-x86_64-general-initial-graph.so"
test "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN
if readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)|\((RELR|RELRSZ|RELRENT)\)'; then
    printf '%s\n' 'ERROR: general interpreter selected an external or unsupported bootstrap runtime' >&2
    exit 1
fi
if readelf -lW "$interpreter" | grep -q ' TLS '; then
    printf '%s\n' 'ERROR: general initial graph selected interpreter TLS' >&2
    exit 1
fi

left_dir="$work_dir/left"
right_dir="$work_dir/right"
shared_dir="$work_dir/shared"
mkdir "$left_dir" "$right_dir" "$shared_dir"

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libshared.so \
    "$SHARED" -o "$shared_dir/libshared.so"
for side in left right; do
    source="$LEFT"
    output_dir="$left_dir"
    [ "$side" = right ] && source="$RIGHT"
    [ "$side" = right ] && output_dir="$right_dir"
    cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,"lib${side}.so" \
        -Wl,-rpath,"$shared_dir" "$source" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
        -o "$output_dir/lib${side}.so"
done
build_main() {
    local selected_interpreter="$1"
    local output="$2"
    shift 2
    cc -nostdlib -fPIE -pie -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,--dynamic-linker,"$selected_interpreter" -Wl,-rpath,"$left_dir:$right_dir" \
        "$START" "$@" "$MAIN" -L"$left_dir" -L"$right_dir" \
        -Wl,--no-as-needed -l:libleft.so -l:libright.so \
        -o "$output"
}

build_main "$interpreter" "$work_dir/main"

if ! readelf -dW "$work_dir/main" | grep -Fq "Library runpath: [$left_dir:$right_dir]"; then
    printf '%s\n' 'ERROR: main lost its ordered two-directory absolute RUNPATH' >&2
    exit 1
fi
for binary in "$left_dir/libleft.so" "$right_dir/libright.so"; do
    if ! readelf -dW "$binary" | grep -Fq "Library runpath: [$shared_dir]"; then
        printf '%s\n' "ERROR: dependency lost its selected absolute RUNPATH: $binary" >&2
        exit 1
    fi
done
for binary in "$work_dir/main" "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so"; do
    if readelf -lW "$binary" | grep -q ' TLS '; then
        printf '%s\n' "ERROR: initial graph fixture selected TLS: $binary" >&2
        exit 1
    fi
    if readelf -rW "$binary" | awk '/R_X86_64_/ { if ($3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" && $3 != "R_X86_64_JUMP_SLOT") exit 1 }'; then :; else
        printf '%s\n' "ERROR: fixture escaped the non-TLS relocation profile: $binary" >&2
        exit 1
    fi
done

needed_main="$(readelf -dW "$work_dir/main")"
needed_left="$(readelf -dW "$left_dir/libleft.so")"
needed_right="$(readelf -dW "$right_dir/libright.so")"
grep -Fq 'Shared library: [libleft.so]' <<<"$needed_main"
grep -Fq 'Shared library: [libright.so]' <<<"$needed_main"
grep -Fq 'Shared library: [libshared.so]' <<<"$needed_left"
grep -Fq 'Shared library: [libshared.so]' <<<"$needed_right"

CRABC_EXECUTION_MODE=native "$work_dir/main"

expect_candidate_rejection() {
    local expected_message="$1"
    local case_name="$2"
    local output status
    set +e
    output="$(CRABC_EXECUTION_MODE=native "$work_dir/main" 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 127 ] || ! grep -Fxq "$expected_message" <<<"$output"; then
        printf 'ERROR: general graph did not fail closed (%s)\n' "$case_name" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

replace_left_and_expect_rejection() {
    local replacement="$1"
    local expected_message="$2"
    local case_name="$3"
    cp "$left_dir/libleft.so" "$left_dir/libleft-valid.so"
    cp "$replacement" "$left_dir/libleft.so"
    expect_candidate_rejection "$expected_message" "$case_name"
    mv "$left_dir/libleft-valid.so" "$left_dir/libleft.so"
}

# The graph-state test above fixes declared-needed postorder as shared, left,
# then right; this native diamond proves the shared initializer executes only
# once before both direct dependencies. These malformed dependency arrays
# retain the same identity/search/relocation shape. The loader must preflight
# the entire post-relocation plan, so the valid priority-101 callback never
# runs before a null or non-executable later entry is rejected.
for malformed in zero nonexecutable; do
    macro=CRABC_GENERAL_INIT_ARRAY_ZERO
    [ "$malformed" = nonexecutable ] && macro=CRABC_GENERAL_INIT_ARRAY_NONEXECUTABLE
    cc -D"$macro" -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,-soname,libleft.so -Wl,-rpath,"$shared_dir" "$LEFT" -L"$shared_dir" \
        -Wl,--no-as-needed -l:libshared.so -o "$left_dir/libleft-$malformed.so"
    readelf -dW "$left_dir/libleft-$malformed.so" | grep -Eq '\((INIT_ARRAY|INIT_ARRAYSZ)\)' || {
        printf 'ERROR: %s fixture did not emit DT_INIT_ARRAY metadata\n' "$malformed" >&2
        exit 1
    }
    replace_left_and_expect_rejection "$left_dir/libleft-$malformed.so" ctorplan "$malformed DT_INIT_ARRAY entry"
done

# A real two-DSO cycle must be retained by identity discovery, then rejected
# while the complete dependency-first initializer plan is still preflighted.
# A SONAME-bearing left seed gives the replacement right its conventional
# `DT_NEEDED [libleft.so]`, but the seed directory remains outside every
# runtime RUNPATH. The replacement right instead resolves that name through
# its own absolute RUNPATH to `$left_dir/libleft.so`, the already mapped,
# still-discovering replacement left. Thus the transaction observes
# main -> left -> right -> left by opened identity, not a shallow missing-name
# failure or a SONAME-only shortcut.
#
# Every dependency constructor in the temporary graph has a raw stderr marker.
# A successful `ctorplan` rejection with no marker therefore proves dispatch
# has not started, rather than merely proving the application did not reach
# `main`.
cycle_dir="$work_dir/cycle"
mkdir "$cycle_dir"

cc -DCRABC_GENERAL_CYCLE_CALLBACK_MARKER -fPIC -shared -nostdlib \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libshared.so "$SHARED" \
    -o "$cycle_dir/libshared-cycle.so"
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libleft.so -Wl,-rpath,"$shared_dir" "$LEFT" \
    -L"$cycle_dir" -Wl,--no-as-needed -l:libshared-cycle.so \
    -o "$cycle_dir/libleft-cycle-seed.so"
cc -DCRABC_GENERAL_CYCLE_CALLBACK_MARKER -fPIC -shared -nostdlib \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libright.so \
    -Wl,-rpath,"$left_dir:$shared_dir" "$RIGHT" -L"$cycle_dir" \
    -Wl,--no-as-needed -l:libleft-cycle-seed.so -l:libshared-cycle.so \
    -o "$cycle_dir/libright-cycle.so"
cc -DCRABC_GENERAL_CYCLE_CALLBACK_MARKER -fPIC -shared -nostdlib \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libleft.so \
    -Wl,-rpath,"$right_dir:$shared_dir" "$LEFT" -L"$cycle_dir" \
    -Wl,--no-as-needed -l:libright-cycle.so -l:libshared-cycle.so \
    -o "$cycle_dir/libleft-cycle.so"

for binary in "$cycle_dir/libshared-cycle.so" \
    "$cycle_dir/libleft-cycle-seed.so" "$cycle_dir/libright-cycle.so" \
    "$cycle_dir/libleft-cycle.so"; do
    if readelf -lW "$binary" | grep -q ' TLS '; then
        printf '%s\n' "ERROR: cycle fixture selected TLS: $binary" >&2
        exit 1
    fi
    if readelf -rW "$binary" | awk '/R_X86_64_/ { if ($3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" && $3 != "R_X86_64_JUMP_SLOT") exit 1 }'; then :; else
        printf '%s\n' "ERROR: cycle fixture escaped the non-TLS relocation profile: $binary" >&2
        exit 1
    fi
done
for binary in "$cycle_dir/libshared-cycle.so" "$cycle_dir/libright-cycle.so" \
    "$cycle_dir/libleft-cycle.so"; do
    cycle_dynamic="$(readelf -dW "$binary")"
    if ! grep -Fq '(INIT_ARRAY)' <<<"$cycle_dynamic" \
        || ! grep -Fq '(INIT_ARRAYSZ)' <<<"$cycle_dynamic"; then
        printf '%s\n' "ERROR: cycle callback marker fixture lost DT_INIT_ARRAY metadata: $binary" >&2
        exit 1
    fi
done

needed_cycle_right="$(readelf -dW "$cycle_dir/libright-cycle.so")"
needed_cycle_left="$(readelf -dW "$cycle_dir/libleft-cycle.so")"
if [ "$(awk '/\(NEEDED\)/ { sub(/^.*\[/, ""); sub(/\].*$/, ""); print }' <<<"$needed_cycle_right")" \
    != $'libleft.so\nlibshared.so' ]; then
    printf '%s\n' 'ERROR: cycle right lost its ordered libleft then shared DT_NEEDED edges' >&2
    exit 1
fi
if [ "$(awk '/\(NEEDED\)/ { sub(/^.*\[/, ""); sub(/\].*$/, ""); print }' <<<"$needed_cycle_left")" \
    != $'libright.so\nlibshared.so' ]; then
    printf '%s\n' 'ERROR: cycle left lost its ordered libright then shared DT_NEEDED edges' >&2
    exit 1
fi
if ! grep -Fq "Library runpath: [$left_dir:$shared_dir]" <<<"$needed_cycle_right"; then
    printf '%s\n' 'ERROR: cycle right lost the RUNPATH that closes its libleft identity edge' >&2
    exit 1
fi
if ! grep -Fq "Library runpath: [$right_dir:$shared_dir]" <<<"$needed_cycle_left"; then
    printf '%s\n' 'ERROR: cycle left lost the RUNPATH that reaches the right fixture' >&2
    exit 1
fi

expect_cycle_ctorplan_rejection() {
    local output status
    cp "$left_dir/libleft.so" "$left_dir/libleft-valid.so"
    cp "$right_dir/libright.so" "$right_dir/libright-valid.so"
    cp "$shared_dir/libshared.so" "$shared_dir/libshared-valid.so"
    cp "$cycle_dir/libleft-cycle.so" "$left_dir/libleft.so"
    cp "$cycle_dir/libright-cycle.so" "$right_dir/libright.so"
    cp "$cycle_dir/libshared-cycle.so" "$shared_dir/libshared.so"
    set +e
    output="$(CRABC_EXECUTION_MODE=native "$work_dir/main" 2>&1)"
    status=$?
    set -e
    mv "$left_dir/libleft-valid.so" "$left_dir/libleft.so"
    mv "$right_dir/libright-valid.so" "$right_dir/libright.so"
    mv "$shared_dir/libshared-valid.so" "$shared_dir/libshared.so"
    if [ "$status" -ne 127 ] || [ "$output" != ctorplan ] \
        || grep -Fq cycle-constructor-ran <<<"$output"; then
        printf '%s\n' 'ERROR: ready DT_NEEDED cycle did not fail before dependency constructor dispatch' >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

expect_cycle_ctorplan_rejection

# DT_INIT and every fini-shaped tag remain outside this startup-only slice.
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-init,left_value \
    -Wl,-soname,libleft.so -Wl,-rpath,"$shared_dir" "$LEFT" -L"$shared_dir" \
    -Wl,--no-as-needed -l:libshared.so -o "$left_dir/libleft-legacy-init.so"
readelf -dW "$left_dir/libleft-legacy-init.so" | grep -Fq '(INIT)' || {
    printf '%s\n' 'ERROR: legacy-init fixture did not emit DT_INIT metadata' >&2
    exit 1
}
replace_left_and_expect_rejection "$left_dir/libleft-legacy-init.so" graph 'legacy DT_INIT'

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libleft.so -Wl,-rpath,"$shared_dir" "$LEFT" -L"$shared_dir" \
    -Wl,--no-as-needed -l:libshared.so -Wl,-fini,left_value \
    -o "$left_dir/libleft-legacy-fini.so"
readelf -dW "$left_dir/libleft-legacy-fini.so" | grep -Fq '(FINI)' || {
    printf '%s\n' 'ERROR: legacy-fini fixture did not emit DT_FINI metadata' >&2
    exit 1
}
replace_left_and_expect_rejection "$left_dir/libleft-legacy-fini.so" graph 'legacy DT_FINI'

cc -DCRABC_GENERAL_FINI_ARRAY -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libleft.so -Wl,-rpath,"$shared_dir" "$LEFT" -L"$shared_dir" \
    -Wl,--no-as-needed -l:libshared.so -o "$left_dir/libleft-fini-array.so"
readelf -dW "$left_dir/libleft-fini-array.so" | grep -Eq '\((FINI_ARRAY|FINI_ARRAYSZ)\)' || {
    printf '%s\n' 'ERROR: fini-array fixture did not emit DT_FINI_ARRAY metadata' >&2
    exit 1
}
replace_left_and_expect_rejection "$left_dir/libleft-fini-array.so" graph 'DT_FINI_ARRAY'

# Main-image arrays are still explicitly rejected rather than becoming a
# second spelling for CRT startup ownership.
build_main "$interpreter" "$work_dir/main-main-init-array" -DCRABC_GENERAL_MAIN_INIT_ARRAY
set +e
main_output="$(CRABC_EXECUTION_MODE=native "$work_dir/main-main-init-array" 2>&1)"
main_status=$?
set -e
if [ "$main_status" -ne 127 ] || ! grep -Fxq mainelf <<<"$main_output"; then
    printf '%s\n' 'ERROR: general graph admitted a main-image DT_INIT_ARRAY' >&2
    printf '%s\n' "$main_output" >&2
    exit 1
fi

build_main "$interpreter" "$work_dir/main-main-preinit-array" -DCRABC_GENERAL_MAIN_PREINIT_ARRAY
set +e
preinit_output="$(CRABC_EXECUTION_MODE=native "$work_dir/main-main-preinit-array" 2>&1)"
preinit_status=$?
set -e
if [ "$preinit_status" -ne 127 ] || ! grep -Fxq mainelf <<<"$preinit_output"; then
    printf '%s\n' 'ERROR: general graph admitted a main-image DT_PREINIT_ARRAY' >&2
    printf '%s\n' "$preinit_output" >&2
    exit 1
fi

printf '%s\n' 'x86 general initial DT_NEEDED diamond: PASS (once-only dependency DT_INIT_ARRAY lifecycle)'
