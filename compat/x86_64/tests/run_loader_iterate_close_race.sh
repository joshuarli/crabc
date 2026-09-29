#!/usr/bin/env bash
# Run one application and one DSO object through pinned musl and owned products.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [ "$#" -ne 5 ]; then
    printf 'usage: %s WORK ACCEPTED_STATIC ACCEPTED_DYNAMIC NATIVE_STATIC NATIVE_DYNAMIC\n' "$0" >&2
    exit 2
fi
readonly work="$(realpath -m "$1")"
case "$work" in "$ROOT"/.work/*) ;; *) exit 2 ;; esac
[ ! -e "$work" ] || { printf 'work already exists: %s\n' "$work" >&2; exit 2; }
mkdir -p "$work"
readonly accepted_static="$(realpath -e "$2")"
readonly accepted_dynamic="$(realpath -e "$3")"
readonly native_static="$(realpath -e "$4")"
readonly native_dynamic="$(realpath -e "$5")"
readonly probe="$ROOT/compat/x86_64/tests/loader_iterate_close_race_probe.c"
readonly plugin="$ROOT/compat/x86_64/tests/loader_iterate_close_race_plugin.c"
readonly musl=/usr/local/bin/crabc-x86_64-musl-gcc
readonly musl_loader=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

"$accepted_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -O2 -pthread -c "$probe" -o "$work/probe.o"
"$accepted_dynamic/bin/crabc-cc-dynamic" -shared -std=c11 -O2 -c "$plugin" -o "$work/plugin.o"
"$musl" -static -fno-pie -no-pie -pthread "$work/probe.o" -o "$work/oracle-static"
"$musl" -fPIE -pie -pthread "$work/probe.o" -o "$work/oracle-dynamic"
"$musl" -shared "$work/plugin.o" -o "$work/libloader-iterate-close-race.so"
"$accepted_dynamic/bin/crabc-cc-dynamic" -shared "$work/plugin.o" -o "$work/accepted-plugin.so"
"$native_dynamic/bin/crabc-cc-dynamic" -shared "$work/plugin.o" -o "$work/native-plugin.so"
printf 'case\tmode\tstatus\tstdout_sha256\tstderr_sha256\n' >"$work/results.tsv"

run_case() {
    local label="$1" mode="$2" status out err
    shift 2
    out="$work/$label.stdout"; err="$work/$label.stderr"
    set +e
    timeout 20 "$@" >"$out" 2>"$err"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/$label.status"
    printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$mode" "$status" \
        "$(sha256sum "$out" | cut -d' ' -f1)" "$(sha256sum "$err" | cut -d' ' -f1)" \
        >>"$work/results.tsv"
}

run_case oracle-static static "$work/oracle-static" static
run_case oracle-dynamic-kernel dynamic "$work/oracle-dynamic" dynamic "$work/libloader-iterate-close-race.so"
run_case oracle-dynamic-direct dynamic "$musl_loader" "$work/oracle-dynamic" dynamic "$work/libloader-iterate-close-race.so"
for backend in accepted native; do
    if [ "$backend" = accepted ]; then
        static="$accepted_static"; dynamic="$accepted_dynamic"
    else
        static="$native_static"; dynamic="$native_dynamic"
    fi
    for link in static static-pie; do
        root="$work/root/$backend-$link"
        mkdir -p "$root"
        "$static/bin/crabc-cc" "-$link" "$work/probe.o" -o "$root/probe"
        run_case "$backend-$link" static chroot "$root" /probe static
    done
    for link in pie non-pie; do
        root="$work/root/$backend-$link"
        mkdir -p "$root"
        cp -a --reflink=auto "$dynamic/." "$root/"
        "$dynamic/bin/crabc-cc-dynamic" "--dynamic-$link" "$work/probe.o" -o "$root/probe"
        cp "$work/$backend-plugin.so" "$root/libloader-iterate-close-race.so"
        run_case "$backend-$link-kernel" dynamic chroot "$root" /probe dynamic /libloader-iterate-close-race.so
        run_case "$backend-$link-direct" dynamic chroot "$root" /lib/ld-crabc-x86_64.so.1 \
            /probe dynamic /libloader-iterate-close-race.so
    done
done
python3 -B "$ROOT/compat/x86_64/tests/loader_iterate_close_race_evidence.py" collect \
    "$work" "$accepted_static" "$accepted_dynamic" "$native_static" "$native_dynamic"
