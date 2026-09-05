#!/usr/bin/env bash
# Initial cyclic DT_NEEDED traversal through ordinary owned applications.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1" source="$ROOT/compat/x86_64/general_dynamic_cycle.c"
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/general-dynamic-cycle.XXXXXX")"
trap 'printf "initial cycle FAIL arm=%s mode=%s order=%s; evidence: %s\n" "${arm:-setup}" "${mode:-build}" "${order:-build}" "$work" >&2' ERR

build_library() {
    local kind="$1" output="$2"
    shift 2
    local dependencies=()
    if [ "$arm" = candidate ]; then
        for dependency in "$@"; do dependencies+=(--application-dso "$dependency"); done
        "$installed/bin/crabc-cc-dynamic" --dynamic-shared-object "-DCYCLE_$kind" "$source" "${dependencies[@]}" -o "$output"
    else
        /usr/local/bin/crabc-x86_64-musl-gcc -fPIC -shared "-DCYCLE_$kind" "$source" \
            -Wl,-soname,"$(basename "$output")",-rpath,/usr/lib,--no-as-needed "$@" -o "$output"
    fi
}

for arm in oracle candidate; do
    root="$work/$arm"
    mkdir -p "$root/lib" "$root/usr/lib" "$work/$arm-seed"
    if [ "$arm" = candidate ]; then
        cp -a "$installed/." "$root/"
        interpreter=/lib/ld-crabc-x86_64.so.1
    else
        cp /opt/musl-1.2.6/lib/libc.so "$root/lib/ld-musl-x86_64.so.1"
        cp /opt/musl-1.2.6/lib/libc.so "$root/usr/lib/libc.so"
        interpreter=/lib/ld-musl-x86_64.so.1
    fi
    # The seed contributes only the future A SONAME during B's link. It is
    # outside the execution root; the final A/B pair closes the real cycle.
    build_library SEED "$work/$arm-seed/libcycle_a.so"
    build_library B "$root/usr/lib/libcycle_b.so" "$work/$arm-seed/libcycle_a.so"
    build_library A "$root/usr/lib/libcycle_a.so" "$root/usr/lib/libcycle_b.so" "$work/$arm-seed/libcycle_a.so"
    for library in a b; do
        readelf -dW "$root/usr/lib/libcycle_$library.so" >"$work/$arm-$library.dynamic"
    done
    grep -Fq 'Shared library: [libcycle_b.so]' "$work/$arm-a.dynamic"
    grep -Fq 'Shared library: [libcycle_a.so]' "$work/$arm-b.dynamic"
    for mode in pie non-pie; do
        for order in a-first b-first; do
            dsos=("$root/usr/lib/libcycle_a.so" "$root/usr/lib/libcycle_b.so")
            [ "$order" = a-first ] || dsos=("${dsos[1]}" "${dsos[0]}")
            name="$mode-$order"
            if [ "$arm" = candidate ]; then
                "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$source" \
                    --application-dso "${dsos[0]}" --application-dso "${dsos[1]}" -o "$root/$name"
            else
                /usr/local/bin/crabc-x86_64-musl-gcc -fPIE "-${mode/non-pie/no-pie}" "$source" \
                    -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1,-rpath,/usr/lib,--no-as-needed "${dsos[@]}" -o "$root/$name"
            fi
            for entry in interp direct; do
                command=("/$name")
                [ "$entry" = interp ] || command=("$interpreter" "/$name")
                timeout 20 chroot "$root" "${command[@]}" >"$work/$arm-$name-$entry.stdout" 2>"$work/$arm-$name-$entry.stderr"
                if [ "$arm" = candidate ]; then
                    cmp "$work/oracle-$name-$entry.stdout" "$work/candidate-$name-$entry.stdout"
                fi
            done
        done
    done
done
printf 'initial dependency cycles: PASS (both entries and traversal roots); evidence: %s\n' "$work"
