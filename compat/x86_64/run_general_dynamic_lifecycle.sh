#!/usr/bin/env bash
# Owned CRT/libc process lifecycle over the general loader, in pinned native Docker.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly FIXTURES="$ROOT/compat/x86_64"
[ "$(uname -sm)" = 'Linux x86_64' ]
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
try:
    valid = (temporary.is_dir() and temporary.resolve(strict=True) == temporary
             and temporary.is_relative_to(root / ".work"))
except OSError:
    valid = False
if not valid:
    raise SystemExit("dynamic lifecycle TMPDIR must be a physical checkout .work directory")
PY
bash "$FIXTURES/run_musl_oracle.sh"
work="$(mktemp -d "$TMPDIR/general-dynamic-lifecycle.XXXXXX")"
readonly work
pie_model="${CRABC_GENERAL_DYNAMIC_LIFECYCLE_PIE_MODEL:-pie}"
tls_model="${CRABC_GENERAL_DYNAMIC_LIFECYCLE_TLS_MODEL:-global-dynamic}"
case "$pie_model" in pic) pie_flag=-fPIC ;; pie) pie_flag=-fPIE ;; *) exit 2 ;; esac
case "$tls_model" in global-dynamic|initial-exec) ;; *) exit 2 ;; esac
CARGO_TARGET_DIR="$work/loader-target" \
RUSTFLAGS='-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic' \
    cargo build --locked --target x86_64-unknown-linux-musl -p crabc-ldso \
        --no-default-features \
        --features x86_64-general-initial-lifecycle,x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter
cp "$work/loader-target/x86_64-unknown-linux-musl/debug/libldso.so" "$work/loader.so"
rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
    "$ROOT/libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs" -o "$work/consumer.a"
rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
    --cfg crabc_general_dynamic_lifecycle \
    "$ROOT/libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_source_root.rs" -o "$work/owned-dynamic-libc.a"
cc -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
    -Wl,--version-script,"$FIXTURES/general_dynamic_lifecycle.map" -Wl,-soname,libcrabc-dynamic.so \
    -Wl,--whole-archive "$work/owned-dynamic-libc.a" -Wl,--no-whole-archive -o "$work/libcrabc-dynamic.so"
rust_sysroot="$(rustup run nightly-2026-07-24 rustc --print sysroot)"
python3 -B "$ROOT/crt/build_x86_64.py" --general-dynamic-lifecycle \
    --out-dir "$work/crt" --llvm-objdump "$rust_sysroot/lib/rustlib/x86_64-unknown-linux-musl/bin/llvm-objdump" \
    >"$work/crt.json"
build_node() {
    local name="$1" anchor="$2" init="$3" fini="$4"
    shift 4
    cc -fPIC -shared -nostdlib -fstack-protector-all -ftls-model="$tls_model" \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,"$name.so" -Wl,-rpath,"$work" \
        -DANCHOR="$anchor" -DINIT_MARKER="$init" -DFINI_MARKER="$fini" \
        "$FIXTURES/general_dynamic_lifecycle_dso.c" "$@" -o "$work/$name.so"
}
build_node shared dependency_anchor 83 115
build_node left left_anchor 76 108 -DHAS_DEPENDENCY -L"$work" -Wl,--no-as-needed -l:shared.so
build_node right right_anchor 82 114 -DHAS_DEPENDENCY -L"$work" -Wl,--no-as-needed -l:shared.so
build_applications() {
    local first="$1" second="$2" mode="$3"
    local -a mode_flags=()
    local -a entry_flags=()
    [ -n "${REJECT_ENTRY:-}" ] && entry_flags=(-Wl,-e,"$REJECT_ENTRY")
    [ "$mode" = explicit ] && mode_flags=(-DEXPLICIT_EXIT)
    [ "$mode" = immediate ] && mode_flags=(-DIMMEDIATE_EXIT)
    # The executable's initial TLS is owned from process entry. PIE mode
    # exercises real COPY relocations; PIC mode remains its GOT regression.
    cc -nostdlib "$pie_flag" -pie -fstack-protector-all -ftls-model=initial-exec \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,-E -Wl,--allow-shlib-undefined \
        -Wl,--dynamic-linker,"$work/loader.so" \
        -Wl,-rpath,"$work" "$work/crt/Scrt1.o" "$work/crt/crti.o" \
        "${mode_flags[@]}" "${entry_flags[@]}" "$FIXTURES/general_dynamic_lifecycle_main.c" \
        "$FIXTURES/general_dynamic_lifecycle_reject.S" \
        -Wl,--whole-archive "$work/consumer.a" -Wl,--no-whole-archive \
        -L"$work" -Wl,--no-as-needed -l:"$first.so" -l:"$second.so" \
        -l:libcrabc-dynamic.so "$work/crt/crtn.o" -o "$work/candidate"
    /usr/local/bin/crabc-x86_64-musl-gcc -DMUSL_ORACLE "$pie_flag" -pie -fstack-protector-all \
        -Wl,-E -Wl,-rpath,"$work" "${mode_flags[@]}" "$FIXTURES/general_dynamic_lifecycle_main.c" \
        -L"$work" -Wl,--no-as-needed -l:"$first.so" -l:"$second.so" -o "$work/oracle"
    readelf -dW "$work/oracle" >"$work/oracle.dynamic.txt"
    readelf --dyn-syms -W "$work/oracle" >"$work/oracle.symbols.txt"
    readelf -lW "$work/oracle" >"$work/oracle.segments.txt"
    grep -Fq 'Shared library: [libc.so]' "$work/oracle.dynamic.txt"
    awk '$7 == "UND" && $8 == "__libc_start_main" { found = 1 } END { exit found ? 0 : 1 }' "$work/oracle.symbols.txt"
    grep -Fq '/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1' "$work/oracle.segments.txt"
}
for order in left right; do
    first=left second=right expected='PSLRIMbaFrls' immediate='PSLRIM'
    if [ "$order" = right ]; then
        first=right second=left expected='PSRLIMbaFlrs' immediate='PSRLIM'
    fi
    for mode in return explicit immediate; do
        build_applications "$first" "$second" "$mode"
        candidate_status=0 oracle_status=0
        env -i PATH=/usr/bin:/bin CRABC_LIFECYCLE_VALUE=yes \
            timeout 10 "$work/candidate" >"$work/candidate-$order-$mode.txt" || candidate_status=$?
        env -i PATH=/usr/bin:/bin CRABC_LIFECYCLE_VALUE=yes \
            timeout 10 "$work/oracle" >"$work/musl-$order-$mode.txt" || oracle_status=$?
        expected_status=19 expected_output="$expected"
        [ "$mode" = explicit ] && expected_status=23
        [ "$mode" = immediate ] && expected_status=29 && expected_output="$immediate"
        [ "$candidate_status" -eq "$expected_status" ]
        [ "$oracle_status" -eq "$expected_status" ]
        [ "$(<"$work/candidate-$order-$mode.txt")" = "$expected_output" ]
        # The owned preinit contract is checked above. Musl 1.2.6 dynlink.c
        # do_init_fini dispatches INIT/INIT_ARRAY only, not PREINIT_ARRAY.
        [ "$(<"$work/musl-$order-$mode.txt")" = "${expected_output#P}" ]
    done
done
for entry in lifecycle_null_finalizer lifecycle_wrong_finalizer lifecycle_missing_random; do
    REJECT_ENTRY="$entry" build_applications left right return
    status=0
    env -i PATH=/usr/bin:/bin CRABC_LIFECYCLE_VALUE=yes \
        timeout 10 "$work/candidate" >"$work/$entry.txt" 2>"$work/$entry.stderr" || status=$?
    [ "$status" -eq 127 ]
    [ ! -s "$work/$entry.txt" ]
done
build_applications left right return
/usr/local/bin/crabc-x86_64-musl-gcc "$FIXTURES/general_dynamic_lifecycle_trace.c" -o "$work/trace"
env -i PATH=/usr/bin:/bin CRABC_LIFECYCLE_VALUE=yes \
    timeout 10 "$work/trace" "$work/candidate" >"$work/single-fs-install.txt"
[ "$(<"$work/single-fs-install.txt")" = PSLRIMbaFrls ]
for binary in loader.so libcrabc-dynamic.so candidate shared.so left.so right.so; do
    readelf -dW "$work/$binary" >"$work/$binary.dynamic.txt"
    readelf -lW "$work/$binary" >"$work/$binary.segments.txt"
done
! grep -q '(NEEDED)' "$work/loader.so.dynamic.txt"
! grep -q '(NEEDED)' "$work/libcrabc-dynamic.so.dynamic.txt"
readelf --dyn-syms -W "$work/libcrabc-dynamic.so" >"$work/libcrabc-dynamic.so.symbols.txt"
! grep -q '__crabc_dynamic_main_thread_runtime_v1_fini_state' "$work/libcrabc-dynamic.so.symbols.txt"
printf 'general dynamic lifecycle: PASS (owned Scrt1/libc, return/exit/_Exit, musl order, guard/TLS/env/auxv); evidence: %s\n' "$work"
