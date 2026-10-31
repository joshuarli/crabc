#!/usr/bin/env bash
# Installed-product evidence for dependency lifecycle ordering.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$(dirname "${BASH_SOURCE[0]}")/native_build_environment.sh"
readonly PRODUCT="${1:?usage: $0 DYNAMIC-SYSROOT}"
readonly FIXTURES="$ROOT/compat/x86_64"
readonly MUSL_LOADER="/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
readonly MUSL_LIBC="/opt/musl-1.2.6/lib/libc.so"
readonly ORACLE_CC="/usr/local/bin/crabc-x86_64-musl-gcc"

[ "$(uname -sm)" = 'Linux x86_64' ]
[ -d "$PRODUCT" ] || { printf 'ERROR: installed product missing: %s\n' "$PRODUCT" >&2; exit 2; }
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) exit 2 ;; esac
bash "$FIXTURES/run_musl_oracle.sh" >/dev/null
work="$(mktemp -d "$TMPDIR/general-loader-lifecycle-product.XXXXXX")"
printf 'evidence: %s\n' "$work"

root="$work/root"
oracle_root="$work/oracle-root"
fixtures="$root/fixtures"
oracle_fixtures="$oracle_root/fixtures"
cp -a "$PRODUCT" "$root"
mkdir -p "$fixtures" "$oracle_root/lib" "$oracle_root/usr/lib" "$oracle_fixtures"
cp "$MUSL_LOADER" "$oracle_root/lib/ld-musl-x86_64.so.1"
cp "$MUSL_LIBC" "$oracle_root/usr/lib/libc.so"
mkdir -p "$oracle_root/opt/musl-1.2.6/lib"
cp "$MUSL_LOADER" "$oracle_root/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
chmod 0755 "$oracle_root/lib/ld-musl-x86_64.so.1" "$oracle_root/usr/lib/libc.so" \
    "$oracle_root/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"

loader="$root/lib/ld-crabc-x86_64.so.1"
readelf -hW "$loader" | grep -F 'DYN' >/dev/null
if readelf -dW "$loader" | grep -E '\(NEEDED\)|\(INTERP\)' >/dev/null \
    || readelf -lW "$loader" | grep ' INTERP ' >/dev/null \
    || readelf --dyn-syms -W "$loader" | grep 'process_finalizer' >/dev/null; then
    printf '%s\n' 'ERROR: installed loader escaped the owned bootstrap boundary' >&2
    exit 1
fi

build_node() {
    local node="$1" base="$2" anchor="$3"
    shift 3
    cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,-soname,"$node.so" -Wl,-init,legacy_init -Wl,-fini,legacy_fini \
        -Wl,-rpath,/fixtures -DTAG_BASE="$base" -DANCHOR="$anchor" \
        "$FIXTURES/general_loader_lifecycle_dso.c" "$@" -o "$fixtures/$node.so"
}
build_node shared 65 dependency_anchor
build_node left 71 left_anchor -DHAS_DEPENDENCY -L"$fixtures" -Wl,--no-as-needed -l:shared.so
build_node right 77 right_anchor -DHAS_DEPENDENCY -L"$fixtures" -Wl,--no-as-needed -l:shared.so

cc -O2 -fPIE -c "$FIXTURES/general_loader_lifecycle_main.c" -o "$work/main.o"
build_applications() {
    local first="$1" second="$2"
    cp -a "$fixtures/." "$oracle_fixtures/"
    cc -nostdlib -fPIE -pie -Wl,--hash-style=sysv -Wl,-z,now -Wl,-E \
        -Wl,--dynamic-linker,/lib/ld-crabc-x86_64.so.1 -Wl,-rpath,/fixtures \
        -Wl,-rpath-link,"$fixtures" \
        "$PRODUCT/usr/lib/Scrt1.o" "$PRODUCT/usr/lib/crti.o" "$work/main.o" \
        "$PRODUCT/usr/lib/crabc-dynamic-attach.o" -L"$PRODUCT/usr/lib" -lc \
        "$PRODUCT/usr/lib/libcrabc-builtins.a" "$PRODUCT/usr/lib/crtn.o" \
        -L"$fixtures" -Wl,--no-as-needed -l:"$first.so" -l:"$second.so" \
        -o "$fixtures/candidate"
    "$ORACLE_CC" -fPIE -pie -Wl,-E -Wl,-rpath,/fixtures "$work/main.o" -L"$fixtures" \
        -Wl,--no-as-needed -l:"$first.so" -l:"$second.so" -o "$work/oracle"
    cp "$fixtures/candidate" "$oracle_fixtures/candidate"
    cp "$work/oracle" "$oracle_fixtures/oracle"
}
run_case() {
    local expected="$1" first="$2" second="$3"
    build_applications "$first" "$second"
    local actual oracle
    actual="$(chroot "$root" /fixtures/candidate)"
    oracle="$(chroot "$oracle_root" /fixtures/oracle)"
    [ "$actual" = "$expected" ] || {
        printf 'ERROR: candidate lifecycle order drifted: %s\n' "$actual" >&2
        exit 1
    }
    [ "$actual" = "$oracle" ] || {
        printf 'ERROR: candidate lifecycle order differs from musl: candidate=%s musl=%s\n' \
            "$actual" "$oracle" >&2
        exit 1
    }
    printf '%s\n' "$actual" >"$work/lifecycle-$(basename "$first")-first.txt"
}
run_case 'ABCGHIMNO!QPRKJLEDF' left right
run_case 'ABCMNOGHI!KJLQPREDF' right left

expect_rejected() {
    local status output expected matched=0
    set +e
    output="$(chroot "$root" /fixtures/candidate 2>&1)"
    status=$?
    set -e
    for expected in "$@"; do
        if grep -Fx "$expected" <<<"$output" >/dev/null; then matched=1; break; fi
    done
    [ "$status" -eq 127 ] && [ "$matched" -eq 1 ] || {
        printf 'ERROR: malformed lifecycle input did not fail closed: status=%s output=%q expected=%s\n' \
            "$status" "$output" "$*" >&2
        exit 1
    }
}
for malformed in ZERO DATA; do
    build_node left 71 left_anchor -DHAS_DEPENDENCY -D"BAD_FINI_$malformed" \
        -L"$fixtures" -Wl,--no-as-needed -l:shared.so
    build_applications left right
    expect_rejected ctorplan
done
build_node left 71 left_anchor -DHAS_DEPENDENCY -DBAD_LEGACY_FINI \
    -L"$fixtures" -Wl,--no-as-needed -l:shared.so
build_applications left right
expect_rejected graph ctorplan
build_node left 71 left_anchor -DHAS_DEPENDENCY -L"$fixtures" -Wl,--no-as-needed -l:shared.so
cp "$fixtures/left.so" "$work/left-valid.so"
for malformed in unpaired zero-size oversized unaligned outside-load unreadable; do
    python3 "$FIXTURES/general_loader_lifecycle_malformed.py" \
        "$work/left-valid.so" "$fixtures/left.so" "$malformed"
    expect_rejected graph ctorplan
done
printf '%s\n' 'installed dependency lifecycle: PASS (musl differential order, malformed metadata rejection)'
