#!/usr/bin/env bash
# Cold native general-loader relocation, ownership, and musl differential gate.
set -euo pipefail
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH COMPILER_PATH \
    GCC_EXEC_PREFIX LD_LIBRARY_PATH LD_PRELOAD || true
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly FIXTURES="$ROOT/compat/x86_64"
ulimit -c 0
for pie_model in pic pie; do
    for tls_model in global-dynamic initial-exec; do
        evidence="$(CRABC_GENERAL_DYNAMIC_LIFECYCLE_PIE_MODEL="$pie_model" \
            CRABC_GENERAL_DYNAMIC_LIFECYCLE_TLS_MODEL="$tls_model" \
            bash "$FIXTURES/run_general_dynamic_lifecycle.sh")"
        printf '%s\n' "$evidence"
    done
done
# Reuse only the just-built owned loader/CRT/libc, never ambient target inputs.
work="${evidence##*evidence: }"
case "$work" in "$TMPDIR"/general-dynamic-lifecycle.*) ;; *) exit 2 ;; esac
readonly work
rustc --edition=2021 --test --cfg crabc_general_initial_graph \
    --cfg crabc_general_initial_tls_materialization_v1 --cfg crabc_general_initial_lifecycle \
    "$ROOT/ldso/src/x86_64_general_initial_graph_source_root.rs" -o "$work/relocation-tests"
timeout 30 "$work/relocation-tests"
build_consumers() {
    local first="$1" second="$2" expected="$3" weak="$4"
    local -a scope_flags=(-DEXPECTED_SCOPE="$expected")
    [ "$weak" = 1 ] && scope_flags+=(-DEARLY_WEAK_SCOPE)
    [ "${5:-0}" = 1 ] && scope_flags+=(-DPROTECTED_COLLISION)
    cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -fstack-protector-all \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libprovider.so \
        "${scope_flags[@]}" "$FIXTURES/general_relocation_provider.c" -o "$work/libprovider.so"
    cc -fPIC -shared -nostdlib -ftls-model=initial-exec -fstack-protector-all \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libconsumer.so -Wl,-rpath,"$work" \
        "${scope_flags[@]}" "$FIXTURES/general_relocation_consumer.c" \
        -L"$work" -Wl,--no-as-needed -lprovider -o "$work/libconsumer.so"
    cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libright.so \
        "$FIXTURES/general_relocation_right.c" -o "$work/libright.so"
    cc -fPIE -pie -nostdlib -fstack-protector-all -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,-E -Wl,--allow-shlib-undefined -Wl,--dynamic-linker,"$work/loader.so" \
        -Wl,-rpath,"$work" "$work/crt/Scrt1.o" "$work/crt/crti.o" \
        "${scope_flags[@]}" "$FIXTURES/general_relocation_main.c" \
        -Wl,--whole-archive "$work/consumer.a" -Wl,--no-whole-archive \
        -L"$work" -Wl,--no-as-needed -l"$first" -l"$second" -lprovider -l:libcrabc-dynamic.so \
        "$work/crt/crtn.o" -o "$work/relocation-candidate"
    /usr/local/bin/crabc-x86_64-musl-gcc -fPIE -pie -fstack-protector-all -Wl,-E \
        -Wl,-rpath,"$work" "${scope_flags[@]}" "$FIXTURES/general_relocation_main.c" \
        -L"$work" -Wl,--no-as-needed -l"$first" -l"$second" -lprovider -o "$work/relocation-oracle"
}
compare_consumers() {
    local label="$1" candidate_status=0 oracle_status=0
    env -i PATH=/usr/bin:/bin timeout 10 "$work/relocation-candidate" >"$work/$label.candidate.txt" || candidate_status=$?
    env -i PATH=/usr/bin:/bin timeout 10 "$work/relocation-oracle" >"$work/$label.musl.txt" || oracle_status=$?
    [ "$candidate_status" -eq 33 ] && [ "$oracle_status" -eq 33 ]
    [ "$(<"$work/$label.candidate.txt")" = 'general relocation pass' ]
    cmp "$work/$label.candidate.txt" "$work/$label.musl.txt"
}
build_consumers consumer right 11 0
compare_consumers bfs-direct-before-grandchild
build_consumers consumer right 5 1
compare_consumers first-weak-before-later-strong
build_consumers right consumer 11 1
compare_consumers reversed-strong-before-weak
# ELF protected visibility requires own-definition binding. Musl's named GD
# TLS path does not enforce it when main exports the same name; record this
# separately from the ordinary differential cases, not as parity.
build_consumers right consumer 11 1 1
candidate_status=0 oracle_status=0
env -i PATH=/usr/bin:/bin timeout 10 "$work/relocation-candidate" >"$work/protected-collision.candidate.txt" || candidate_status=$?
env -i PATH=/usr/bin:/bin timeout 10 "$work/relocation-oracle" >"$work/protected-collision.musl.txt" || oracle_status=$?
[ "$candidate_status" -eq 33 ] && [ "$oracle_status" -eq 81 ]
[ "$(<"$work/protected-collision.candidate.txt")" = 'general relocation pass' ]
[ ! -s "$work/protected-collision.musl.txt" ]
readelf --dyn-syms -W "$work/libprovider.so" >"$work/protected-collision.provider-symbols.txt"
readelf --dyn-syms -W "$work/relocation-oracle" >"$work/protected-collision.main-symbols.txt"
readelf -rW "$work/libprovider.so" >"$work/protected-collision.provider-relocations.txt"
grep -Eq 'TLS[[:space:]]+GLOBAL[[:space:]]+PROTECTED.*protected_tls' "$work/protected-collision.provider-symbols.txt"
grep -Eq 'TLS[[:space:]]+GLOBAL[[:space:]]+DEFAULT.*protected_tls' "$work/protected-collision.main-symbols.txt"
grep -Eq 'R_X86_64_DTPMOD64.*protected_tls' "$work/protected-collision.provider-relocations.txt"
build_consumers right consumer 11 1
for binary in relocation-candidate relocation-oracle libprovider.so libconsumer.so; do
    readelf -rW "$work/$binary" >"$work/$binary.relocations.txt"
    readelf -lW "$work/$binary" >"$work/$binary.segments.txt"
    readelf -dW "$work/$binary" >"$work/$binary.dynamic.txt"
done
grep -q R_X86_64_COPY "$work/relocation-candidate.relocations.txt"
grep -q R_X86_64_64 "$work/libprovider.so.relocations.txt"
grep -q R_X86_64_DTPMOD64 "$work/libprovider.so.relocations.txt"
grep -q R_X86_64_DTPOFF64 "$work/libprovider.so.relocations.txt"
grep -q R_X86_64_TPOFF64 "$work/libconsumer.so.relocations.txt"
grep -q STATIC_TLS "$work/libconsumer.so.dynamic.txt"
! grep -q ' TLS ' "$work/libconsumer.so.segments.txt"
! grep -q STATIC_TLS "$work/libprovider.so.dynamic.txt"
grep -Fq '/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1' "$work/relocation-oracle.segments.txt"
grep -Fq 'Shared library: [libc.so]' "$work/relocation-oracle.dynamic.txt"
readelf --dyn-syms -W "$work/relocation-oracle" >"$work/relocation-oracle.symbols.txt"
awk '$7 == "UND" && $8 == "__libc_start_main" { found = 1 } END { exit found ? 0 : 1 }' "$work/relocation-oracle.symbols.txt"
for binary in relocation-candidate libprovider.so libconsumer.so; do
    cp "$work/$binary" "$work/$binary.original"
done
for case in provider-size-small provider-size-large; do
    python3 -B "$FIXTURES/general_relocation_mutate.py" \
        "$work/libprovider.so.original" "$work/libprovider.so" "$case"
    compare_consumers "$case"
done
cp "$work/libprovider.so.original" "$work/libprovider.so"
python3 -B "$FIXTURES/general_relocation_mutate.py" \
    "$work/libconsumer.so.original" "$work/libconsumer.so" consumer-clear-static-tls
compare_consumers consumer-clear-static-tls
cp "$work/libconsumer.so.original" "$work/libconsumer.so"
/usr/local/bin/crabc-x86_64-musl-gcc "$FIXTURES/ldso_general_initial_tls_trace.c" -o "$work/reject-trace"
/usr/local/bin/crabc-x86_64-musl-gcc "$FIXTURES/general_relocation_trap.c" -o "$work/trap"
status=0
timeout 10 "$work/reject-trace" "$work/trap" >"$work/trace-fatal.txt" 2>&1 || status=$?
[ "$status" -eq 73 ]
grep -q 'candidate stopped by signal' "$work/trace-fatal.txt"
for entry in \
    relocation-candidate:main-array-half \
    relocation-candidate:copy-offset relocation-candidate:copy-size \
    relocation-candidate:copy-addend relocation-candidate:copy-overlap relocation-candidate:copy-readonly \
    libprovider.so:copy-in-dso libprovider.so:copy-source-size libprovider.so:copy-source-extent \
    libprovider.so:copy-source-hidden libprovider.so:copy-source-protected \
    libprovider.so:copy-source-local libprovider.so:copy-source-tls \
    libprovider.so:tls-offset libprovider.so:tls-size libprovider.so:tls-kind libprovider.so:tls-no-module \
    libconsumer.so:tls-addend-positive libconsumer.so:tls-addend-negative \
    libconsumer.so:tls-unaligned libconsumer.so:tls-invalid-index; do
    binary="${entry%%:*}" case="${entry#*:}"
    python3 -B "$FIXTURES/general_relocation_mutate.py" "$work/$binary.original" "$work/$binary" "$case"
    timeout 10 "$work/reject-trace" "$work/relocation-candidate" >"$work/$case.txt" 2>"$work/$case.stderr"
    [ ! -s "$work/$case.txt" ]
    cp "$work/$binary.original" "$work/$binary"
done
compare_consumers restored-after-negative-matrix
printf 'general relocations: PASS (COPY/scope/IE/GD, musl, 21 pre-FS failures); evidence: %s\n' "$work"
