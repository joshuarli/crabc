#!/usr/bin/env bash
# Installed search decisions, with the same graph in a separate pinned-musl root.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
readonly mode="${CRABC_GENERAL_DYNAMIC_ENTRY_MODE:---dynamic-pie}"
case "$mode" in --dynamic-pie) oracle_mode=-pie;; --dynamic-non-pie) oracle_mode=-no-pie;; *) exit 2;; esac
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PYTHON'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('general dynamic search TMPDIR must be a physical checkout .work directory')
PYTHON
readonly work="$(mktemp -d "$TMPDIR/general-dynamic-search.XXXXXX")"
trap 'printf "general dynamic search: FAIL arm=%s case=%s; evidence: %s\n" "${arm:-setup}" "${test:-build}" "$work" >&2' ERR
readonly source="$ROOT/compat/x86_64/general_dynamic_search.c"
bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >"$work/oracle-toolchain.log"
for arm in candidate oracle; do
    mkdir -p "$work/$arm" "$work/$arm-root/search" "$work/$arm-root/plugins/sub" "$work/$arm-root/environment" "$work/$arm-root/caller" "$work/$arm-root/loop"
    build="$work/$arm"
    root="$work/$arm-root"
    if [ "$arm" = candidate ]; then
        cp -a "$installed/." "$root/"
        cc=("$installed/bin/crabc-cc-dynamic")
        "${cc[@]}" --dynamic-shared-object -DSEARCH_LEAF=7 "$source" -o "$build/libsearch_leaf.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_LEAF=8 "$source" -o "$build/environment.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_MIDDLE --application-runpath /missing "$source" --application-dso "$build/libsearch_leaf.so" -o "$build/libsearch_mid.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_MIDDLE --application-runpath '${ORIGIN}/sub' "$source" --application-dso "$build/libsearch_leaf.so" -o "$build/liborigin.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_CALLER --application-runpath /caller "$source" -o "$build/libcaller.so"
        "${cc[@]}" "$mode" --application-runpath /search:/usr/lib "$source" -o "$build/consumer"
        "${cc[@]}" "$mode" -DSEARCH_INITIAL --application-runpath /search:/usr/lib "$source" --application-dso "$build/libsearch_mid.so" --application-dso "$build/libsearch_leaf.so" -o "$build/initial"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_MIDDLE --application-runpath /environment "$source" --application-dso "$build/libsearch_leaf.so" -o "$build/libbreadth.so"
        "${cc[@]}" "$mode" -DSEARCH_INITIAL --application-runpath /search:/usr/lib "$source" --application-dso "$build/libbreadth.so" --application-dso "$build/libsearch_leaf.so" -o "$build/breadth"
    else
        cc=(/usr/local/bin/crabc-x86_64-musl-gcc)
        mkdir -p "$root/opt/musl-1.2.6/lib" "$root/usr/lib"
        cp /opt/musl-1.2.6/lib/libc.so "$root/usr/lib/libc.so"
        cp /opt/musl-1.2.6/lib/libc.so "$root/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
        "${cc[@]}" -fPIC -shared -Wl,-soname,libsearch_leaf.so -DSEARCH_LEAF=7 "$source" -o "$build/libsearch_leaf.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_LEAF=8 "$source" -o "$build/environment.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_MIDDLE "$source" -L"$build" -lsearch_leaf -Wl,-rpath,/missing -Wl,-soname,libsearch_mid.so -o "$build/libsearch_mid.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_MIDDLE "$source" -L"$build" -lsearch_leaf '-Wl,-rpath,${ORIGIN}/sub' -o "$build/liborigin.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_CALLER "$source" -Wl,-rpath,/caller -o "$build/libcaller.so"
        "${cc[@]}" -fPIE "$oracle_mode" "$source" -Wl,-rpath,/search:/usr/lib -o "$build/consumer"
        "${cc[@]}" -fPIE "$oracle_mode" -DSEARCH_INITIAL "$source" -L"$build" -lsearch_mid -lsearch_leaf -Wl,-rpath,/search:/usr/lib -o "$build/initial"
        "${cc[@]}" -fPIC -shared -DSEARCH_MIDDLE "$source" -L"$build" -lsearch_leaf -Wl,-rpath,/environment -Wl,-soname,libbreadth.so -o "$build/libbreadth.so"
        "${cc[@]}" -fPIE "$oracle_mode" -DSEARCH_INITIAL "$source" -L"$build" -lbreadth -lsearch_leaf -Wl,-rpath,/search:/usr/lib -o "$build/breadth"
    fi
    cp "$build/consumer" "$build/initial" "$build/breadth" "$root/"
    cp "$build/libsearch_leaf.so" "$build/libsearch_mid.so" "$build/libbreadth.so" "$root/search/"
    cp "$build/libsearch_mid.so" "$build/liborigin.so" "$root/plugins/"
    cp "$build/libsearch_leaf.so" "$root/plugins/sub/"
    cp "$build/environment.so" "$root/environment/libsearch_leaf.so"
    cp "$build/libcaller.so" "$root/caller/"
    # A caller-local same-name object is deliberately not chosen by dlopen.
    cp "$build/environment.so" "$root/caller/libsearch_mid.so"
    ln -s libsearch_leaf.so "$root/loop/libsearch_leaf.so"
    for test in ancestor environment origin caller initial initial-environment relative delimiters missing stop-error breadth; do
        command=(/consumer /plugins/libsearch_mid.so 7)
        environment=()
        case "$test" in
            environment) environment=(LD_LIBRARY_PATH=/environment); command[2]=8;;
            origin) command[1]=/plugins/liborigin.so;;
            caller) command[1]=/caller/libcaller.so;;
            initial) command=(/initial unused 7);;
            initial-environment) environment=(LD_LIBRARY_PATH=/environment); command=(/initial unused 8);;
            relative) command[1]=plugins/libsearch_mid.so;;
            breadth) command=(/breadth unused 7);;
            missing) command[1]=/missing/libsearch_mid.so; command[2]=0;;
            stop-error) environment=(LD_LIBRARY_PATH=/loop); command[2]=0;;
            delimiters) environment=(LD_LIBRARY_PATH=$':\n/missing::/environment\n'); command[2]=8;;
        esac
        timeout 20 env -u LD_LIBRARY_PATH "${environment[@]}" chroot "$root" "${command[@]}" >"$work/$arm-$test.stdout"
    done
done
for test in ancestor environment origin caller initial initial-environment relative delimiters missing stop-error breadth; do
    cmp "$work/candidate-$test.stdout" "$work/oracle-$test.stdout"
done
printf 'general dynamic search: PASS (11 installed/musl decisions, %s); evidence: %s\n' "$mode" "$work"
