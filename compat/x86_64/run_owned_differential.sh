#!/usr/bin/env bash
# Replay the frozen differential sources through supplied owned x86 products.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly HELPER="$ROOT/compat/x86_64/owned_differential_evidence.py"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CASES=(foundational string-memory allocator fd-filesystem stdio-fdopen)

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

provided_static=''
provided_dynamic=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] || usage
            [ -n "$2" ] || usage
            case "$2" in
                -*) usage ;;
            esac
            [ -z "$provided_static" ] || usage
            provided_static="$2"
            shift 2
            ;;
        -*)
            usage
            ;;
        *)
            [ -n "$1" ] || usage
            [ -z "$provided_dynamic" ] || usage
            provided_dynamic="$1"
            shift
            ;;
    esac
done
[ -n "$provided_dynamic" ] || usage

if [ -n "$provided_static" ]; then
    provided_static="$(realpath -e -- "$provided_static")"
fi
provided_dynamic="$(realpath -e -- "$provided_dynamic")"
temporary="$(realpath -e -- "${TMPDIR:-$ROOT/.work/x86_64/tmp}")"
readonly temporary

[ "$(uname -sm)" = 'Linux x86_64' ]
input_arguments=(
    validate-inputs --root "$ROOT" --temporary "$temporary" --dynamic "$provided_dynamic"
)
if [ -n "$provided_static" ]; then
    input_arguments+=(--static "$provided_static")
fi
python3 -B "$HELPER" "${input_arguments[@]}"

readonly work="$(mktemp -d "$temporary/owned-differential.XXXXXX")"
chmod a+rx "$work"
mkdir "$work/oracle" "$work/candidates" "$work/links" "$work/copies" \
    "$work/roots" "$work/executions" "$work/observations"
printf 'owned differential evidence: %s\n' "$work"

# The helper invokes this command exactly once per frozen source through the
# supplied dynamic driver. Later links receive only its retained ET_REL object.
python3 -B "$HELPER" record-compile --dynamic "$provided_dynamic" --work "$work"

run_in_root() {
    local root="$1" prefix="$2" status=0
    shift 2
    if env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C timeout 30 chroot "$root" "$@" \
        < /dev/null >"$prefix.stdout" 2>"$prefix.stderr"; then
        :
    else
        status=$?
    fi
    printf '%s\n' "$status" >"$prefix.status"
}

prepare_file_root() {
    local root="$1" executable="$2" copy_record="$3" root_record="$4"
    mkdir "$root"
    cp -a -- "$executable" "$root/consumer"
    python3 -B "$HELPER" record-file-copy --source "$executable" --copy "$root/consumer" \
        --record "$copy_record"
    mkdir "$root/tmp"
    chmod 1777 "$root/tmp"
    # ``$work`` can inherit its group directory's setgid bit.  The contained
    # workload contract is exactly sticky world-writable 1777, not 3777.
    chmod g-s "$root/tmp"
    python3 -B "$HELPER" attest-file-root --source "$executable" --root "$root" --phase pre \
        --record "$root_record"
}

prepare_dynamic_root() {
    local root="$1" executable="$2" product_record="$3" file_record="$4" root_record="$5"
    mkdir "$root"
    cp -a -- "$provided_dynamic/." "$root/"
    # Validate the copied product before the disposable application is added;
    # its manifest and every payload mode then bind the runtime actually used.
    python3 -B "$HELPER" record-product-copy --kind dynamic --source "$provided_dynamic" \
        --copy "$root" --record "$product_record"
    cp -a -- "$executable" "$root/consumer"
    python3 -B "$HELPER" record-file-copy --source "$executable" --copy "$root/consumer" \
        --record "$file_record"
    mkdir "$root/tmp"
    chmod 1777 "$root/tmp"
    chmod g-s "$root/tmp"
    python3 -B "$HELPER" attest-dynamic-root --source "$provided_dynamic" --root "$root" \
        --executable "$executable" --phase pre --record "$root_record"
}

compare_case() {
    local case="$1" reference_prefix="$2" candidate_label="$3" candidate_prefix="$4"
    python3 -B "$HELPER" compare --case "$case" --reference-label musl \
        --reference-status "$reference_prefix.status" --reference-stdout "$reference_prefix.stdout" \
        --reference-stderr "$reference_prefix.stderr" --candidate-label "$candidate_label" \
        --candidate-status "$candidate_prefix.status" --candidate-stdout "$candidate_prefix.stdout" \
        --candidate-stderr "$candidate_prefix.stderr" \
        --record "$work/observations/$case-$candidate_label.json"
}

run_static_case() {
    local case="$1" mode="$2" reference_prefix="$3"
    local object="$work/objects/$case.o"
    local candidate="$work/candidates/$case-static-$mode"
    local receipt="$work/candidates/$case-static-$mode.receipt.json"
    local root="$work/roots/$case-static-$mode"
    local prefix="$work/executions/$case-static-$mode"
    local root_pre="$work/copies/$case-static-$mode-root-pre.json"
    local root_post="$work/copies/$case-static-$mode-root-post.json"

    (
        cd "$work/candidates"
        TMPDIR="$work" "$provided_static/bin/crabc-cc" "-$mode" \
            --link-receipt "$(basename "$receipt")" "$object" -o "$candidate"
    )
    python3 -B "$HELPER" validate-link --product "$provided_static" --work "$work" \
        --case "$case" --linkage "$mode" --executable "$candidate" --receipt "$receipt" \
        --record "$work/links/$case-static-$mode.json"
    prepare_file_root "$root" "$candidate" "$work/copies/$case-static-$mode-executable.json" "$root_pre"
    run_in_root "$root" "$prefix" /consumer
    python3 -B "$HELPER" attest-file-root --source "$candidate" --root "$root" --phase post \
        --record "$root_post"
    compare_case "$case" "$reference_prefix" "static-$mode" "$prefix"
}

run_dynamic_case() {
    local case="$1" mode="$2" reference_prefix="$3"
    local object="$work/objects/$case.o"
    local candidate="$work/candidates/$case-dynamic-$mode"
    local receipt="$candidate.crabc-link.json"
    local entry root prefix

    TMPDIR="$work" "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        "$object" -o "$candidate"
    python3 -B "$HELPER" validate-link --product "$provided_dynamic" --work "$work" \
        --case "$case" --linkage "$mode" --executable "$candidate" --receipt "$receipt" \
        --record "$work/links/$case-dynamic-$mode.json"
    for entry in kernel direct; do
        root="$work/roots/$case-dynamic-$mode-$entry"
        prefix="$work/executions/$case-dynamic-$mode-$entry"
        prepare_dynamic_root "$root" "$candidate" \
            "$work/copies/$case-dynamic-$mode-$entry-product.json" \
            "$work/copies/$case-dynamic-$mode-$entry-executable.json" \
            "$work/copies/$case-dynamic-$mode-$entry-root-pre.json"
        if [ "$entry" = direct ]; then
            run_in_root "$root" "$prefix" /lib/ld-crabc-x86_64.so.1 /consumer
        else
            run_in_root "$root" "$prefix" /consumer
        fi
        python3 -B "$HELPER" attest-dynamic-root --source "$provided_dynamic" --root "$root" \
            --executable "$candidate" --phase post \
            --record "$work/copies/$case-dynamic-$mode-$entry-root-post.json"
        compare_case "$case" "$reference_prefix" "dynamic-$mode-$entry" "$prefix"
    done
}

for case in "${CASES[@]}"; do
    object="$work/objects/$case.o"
    oracle="$work/oracle/$case"
    reference_root="$work/roots/$case-musl"
    reference_prefix="$work/executions/$case-musl"

    "$ORACLE_CC" -static -fno-pie -no-pie "$object" -o "$oracle"
    python3 -B "$HELPER" record-oracle-link --work "$work" --case "$case" \
        --executable "$oracle" --record "$work/links/$case-musl.json"
    prepare_file_root "$reference_root" "$oracle" "$work/copies/$case-musl-executable.json" \
        "$work/copies/$case-musl-root-pre.json"
    run_in_root "$reference_root" "$reference_prefix" /consumer
    python3 -B "$HELPER" attest-file-root --source "$oracle" --root "$reference_root" --phase post \
        --record "$work/copies/$case-musl-root-post.json"

    if [ -n "$provided_static" ]; then
        run_static_case "$case" static "$reference_prefix"
        run_static_case "$case" static-pie "$reference_prefix"
    fi
    run_dynamic_case "$case" pie "$reference_prefix"
    run_dynamic_case "$case" non-pie "$reference_prefix"
done

summary_arguments=(summarize --work "$work")
if [ -n "$provided_static" ]; then
    summary_arguments+=(--static-replayed)
fi
python3 -B "$HELPER" "${summary_arguments[@]}"

printf 'owned differential: PASS (five frozen sources, one installed-header object per source, pinned musl, supplied static/static-PIE when present, supplied dynamic PIE/non-PIE kernel/direct roots, and raw status/stdout/stderr/errno receipts); report: %s/summary.json; evidence: %s\n' "$work" "$work"
