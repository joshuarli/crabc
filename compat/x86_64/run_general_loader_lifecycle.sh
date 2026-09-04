#!/usr/bin/env bash
# Run inside the pinned native x86 image; all evidence stays in TMPDIR.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly FIXTURES="$ROOT/compat/x86_64"
[ "$(uname -sm)" = 'Linux x86_64' ]
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) exit 2 ;; esac
bash "$FIXTURES/run_musl_oracle.sh"
work="$(mktemp -d "$TMPDIR/general-loader-lifecycle.XXXXXX")"
readonly work
cfgs=(--cfg crabc_general_initial_graph --cfg crabc_general_initial_lifecycle)
features=x86_64-general-initial-lifecycle
tls_cflags=()
tls_ldflags=()
if [ "${CRABC_GENERAL_LOADER_LIFECYCLE_TLS:-0}" = 1 ]; then
    cfgs+=(--cfg crabc_general_initial_tls_materialization_v1)
    features+=,x86_64-general-initial-tls-interpreter
    tls_cflags=(-DUSE_TLS -ftls-model=global-dynamic)
    # The interpreter supplies __tls_get_addr at runtime; no libc is linked
    # into the freestanding candidate just to satisfy its DSO's reference.
    tls_ldflags=(-Wl,--allow-shlib-undefined)
fi
rustc --edition=2021 --test "${cfgs[@]}" \
    "$ROOT/ldso/src/x86_64_general_initial_graph_source_root.rs" -o "$work/lifecycle-tests"
timeout 30 "$work/lifecycle-tests"
case "${CRABC_GENERAL_LOADER_LIFECYCLE_ROOT:-source}" in
source)
rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
    "${cfgs[@]}" \
    "$ROOT/ldso/src/x86_64_general_initial_graph_source_root.rs" -o "$work/loader.a"
cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
    -Wl,--whole-archive "$work/loader.a" -Wl,--no-whole-archive -o "$work/loader.so"
    ;;
crabc-target)
    CARGO_TARGET_DIR="$work/target" \
    RUSTFLAGS='-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic' \
        cargo build --locked --target x86_64-unknown-linux-musl -p crabc-ldso \
            --no-default-features --features "$features"
    cp "$work/target/x86_64-unknown-linux-musl/debug/libldso.so" "$work/loader.so"
    ;;
*) exit 2 ;;
esac
readelf -hW "$work/loader.so" >"$work/loader-header.txt"
readelf -lW "$work/loader.so" >"$work/loader-program-headers.txt"
readelf -dW "$work/loader.so" >"$work/loader-dynamic.txt"
readelf --dyn-syms -W "$work/loader.so" >"$work/loader-symbols.txt"
grep -q 'DYN' "$work/loader-header.txt"
if grep -Eq '\(NEEDED\)|\(INTERP\)' "$work/loader-dynamic.txt" \
    || grep -Eq ' TLS | INTERP ' "$work/loader-program-headers.txt" \
    || grep -q 'process_finalizer' "$work/loader-symbols.txt"; then
    printf '%s\n' 'ERROR: lifecycle loader escaped owned bootstrap/private callback boundary' >&2
    exit 1
fi
build_node() {
    local node="$1" base="$2" anchor="$3"
    shift 3
    cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,-soname,"$node.so" -Wl,-init,legacy_init -Wl,-fini,legacy_fini \
        -Wl,-rpath,"$work" -DTAG_BASE="$base" -DANCHOR="$anchor" \
        "$FIXTURES/general_loader_lifecycle_dso.c" "$@" -o "$work/$node.so"
}
build_node shared 65 dependency_anchor "${tls_cflags[@]}"
build_node left 71 left_anchor -DHAS_DEPENDENCY -L"$work" -Wl,--no-as-needed -l:shared.so
build_node right 77 right_anchor -DHAS_DEPENDENCY -L"$work" -Wl,--no-as-needed -l:shared.so
build_applications() {
    local first="$1" second="$2"
    cc -nostdlib -fPIE -pie -Wl,--hash-style=sysv -Wl,-z,now -Wl,-E \
    "${tls_ldflags[@]}" \
    -Wl,--dynamic-linker,"$work/loader.so" -Wl,-rpath,"$work" -DCANDIDATE \
    "$FIXTURES/general_loader_lifecycle_start.S" "$FIXTURES/general_loader_lifecycle_main.c" \
    -L"$work" -Wl,--no-as-needed -l:"$first.so" -l:"$second.so" -o "$work/candidate"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIE -pie -Wl,-E -Wl,-rpath,"$work" \
    "$FIXTURES/general_loader_lifecycle_main.c" -L"$work" \
    -Wl,--no-as-needed -l:"$first.so" -l:"$second.so" -o "$work/oracle"
}
build_applications left right
expected='ABCGHIMNO!QPRKJLEDF'
actual="$(env -i PATH=/usr/bin:/bin "$work/candidate")"
oracle="$(env -i PATH=/usr/bin:/bin "$work/oracle")"
[ "$actual" = "$expected" ]
[ "$actual" = "$oracle" ]
printf '%s\n' "$actual" >"$work/candidate-left-first.txt"
printf '%s\n' "$oracle" >"$work/musl-left-first.txt"
build_applications right left
actual="$(env -i PATH=/usr/bin:/bin "$work/candidate")"
oracle="$(env -i PATH=/usr/bin:/bin "$work/oracle")"
[ "$actual" = 'ABCMNOGHI!KJLQPREDF' ]
[ "$actual" = "$oracle" ]
printf '%s\n' "$actual" >"$work/candidate-right-first.txt"
printf '%s\n' "$oracle" >"$work/musl-right-first.txt"
for malformed in ZERO DATA; do
    build_node left 71 left_anchor -DHAS_DEPENDENCY -D"BAD_FINI_$malformed" \
        -L"$work" -Wl,--no-as-needed -l:shared.so
    status=0
    "$work/candidate" >"$work/rejected.stdout" 2>"$work/rejected.stderr" || status=$?
    [ "$status" -eq 127 ]
    [ ! -s "$work/rejected.stdout" ]
    [ "$(<"$work/rejected.stderr")" = ctorplan ]
    cp "$work/rejected.stderr" "$work/rejected-fini-$malformed.txt"
done
build_node left 71 left_anchor -DHAS_DEPENDENCY -DBAD_LEGACY_FINI \
    -L"$work" -Wl,--no-as-needed -l:shared.so
status=0
"$work/candidate" >"$work/rejected.stdout" 2>"$work/rejected.stderr" || status=$?
[ "$status" -eq 127 ]
[ ! -s "$work/rejected.stdout" ]
[ "$(<"$work/rejected.stderr")" = graph ]
build_node left 71 left_anchor -DHAS_DEPENDENCY -L"$work" -Wl,--no-as-needed -l:shared.so
cp "$work/left.so" "$work/left-valid.so"
for malformed in unpaired zero-size oversized unaligned outside-load unreadable; do
    python3 "$FIXTURES/general_loader_lifecycle_malformed.py" \
        "$work/left-valid.so" "$work/left.so" "$malformed"
    status=0
    "$work/candidate" >"$work/rejected.stdout" 2>"$work/rejected.stderr" || status=$?
    [ "$status" -eq 127 ]
    [ ! -s "$work/rejected.stdout" ]
    [ "$(<"$work/rejected.stderr")" = graph ]
    cp "$work/rejected.stderr" "$work/rejected-metadata-$malformed.txt"
done
sha256sum "$ROOT"/ldso/src/x86_64*.rs "$ROOT/ldso/src/lib.rs" \
    "$ROOT/ldso/Cargo.toml" "$ROOT/ldso/build.rs" \
    "$FIXTURES/run_general_loader_lifecycle.sh" \
    "$FIXTURES/general_loader_lifecycle_dso.c" \
    "$FIXTURES/general_loader_lifecycle_main.c" \
    "$FIXTURES/general_loader_lifecycle_start.S" \
    "$FIXTURES/general_loader_lifecycle_malformed.py" >"$work/source-sha256.txt"
printf 'general loader dependency lifecycle: PASS (musl differential, recursive/repeated fini, atomic preflight); evidence: %s\n' "$work"
