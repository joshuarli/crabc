#!/usr/bin/env bash
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -ge 1 ] && [ "$#" -le 3 ] || { echo "usage: $0 INSTALLED_DYNAMIC_SYSROOT [EXTRA_ROOTS] [--ordinary-only]" >&2; exit 2; }
readonly installed="$1"
readonly extra="${2:-16}"
readonly ordinary="${3:-}"
[ -z "$ordinary" ] || [ "$ordinary" = --ordinary-only ] || exit 2
consumer_arguments=()
[ -z "$ordinary" ] || consumer_arguments+=("$ordinary")
[[ "$extra" =~ ^[0-9]+$ ]] && [ "$extra" -ge 1 ] && [ "$extra" -le 96 ] || exit 2
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
case "${TMPDIR:-}" in "$root"/.work/*) ;; *) echo 'TMPDIR must be within the checkout .work directory' >&2; exit 2 ;; esac

ulimit -c 0
bash "$root/compat/x86_64/run_musl_oracle.sh"
work="$(mktemp -d "$TMPDIR/owned-loader-scope-graph.XXXXXX")"
readonly work
trap 'echo "scope graph evidence: $work" >&2' EXIT
mkdir "$work/oracle"
readonly source="$root/compat/x86_64/owned_loader_scope_graph"

"$driver" --dynamic-shared-object "$source"_leaf.c -o "$work/libgraph-leaf.so"
"$oracle_cc" -fPIC -shared "$source"_leaf.c -Wl,-z,now,-soname,libgraph-leaf.so \
    -o "$work/oracle/libgraph-leaf.so"
"$driver" --dynamic-shared-object "$source"_leaf.c -o "$work/libgraph-absent.so"
"$oracle_cc" -fPIC -shared "$source"_leaf.c -Wl,-z,now,-soname,libgraph-absent.so \
    -o "$work/oracle/libgraph-absent.so"
for side in left right; do
    define=GRAPH_LEFT
    [ "$side" = left ] || define=GRAPH_RIGHT
    "$driver" --dynamic-shared-object -D"$define" "$source"_node.c \
        --application-dso "$work/libgraph-leaf.so" -o "$work/libgraph-$side.so"
    "$oracle_cc" -fPIC -shared -D"$define" "$source"_node.c \
        -L"$work/oracle" -Wl,--no-as-needed -l:libgraph-leaf.so \
        -Wl,-z,now,-soname,"libgraph-$side.so" -o "$work/oracle/libgraph-$side.so"
done
for variant in ab ba bad; do
    case "$variant" in
        ba) first=right; second=left ;;
        *) first=left; second=right ;;
    esac
    candidate_dependencies=(--application-dso "$work/libgraph-$first.so"
        --application-dso "$work/libgraph-$second.so" --application-dso "$work/libgraph-leaf.so")
    oracle_dependencies=(-l:"libgraph-$first.so" -l:"libgraph-$second.so")
    if [ "$variant" = bad ]; then
        candidate_dependencies+=(--application-dso "$work/libgraph-absent.so")
        oracle_dependencies+=(-l:libgraph-absent.so)
    fi
    "$driver" --dynamic-shared-object "$source"_root.c \
        "${candidate_dependencies[@]}" -o "$work/libgraph-$variant.so"
    "$oracle_cc" -fPIC -shared "$source"_root.c \
        -L"$work/oracle" -Wl,--no-as-needed "${oracle_dependencies[@]}" \
        -Wl,-z,now,-soname,"libgraph-$variant.so" -o "$work/oracle/libgraph-$variant.so"
done
for ((index=0; index<extra; index++)); do
    printf -v name 'libgraph-%02d.so' "$index"
    if ((index % 2)); then first=right; second=left; else first=left; second=right; fi
    "$driver" --dynamic-shared-object "$source"_root.c \
        --application-dso "$work/libgraph-$first.so" \
        --application-dso "$work/libgraph-$second.so" \
        --application-dso "$work/libgraph-leaf.so" -o "$work/$name"
    "$oracle_cc" -fPIC -shared "$source"_root.c \
        -L"$work/oracle" -Wl,--no-as-needed \
        -l:"libgraph-$first.so" -l:"libgraph-$second.so" \
        -Wl,-z,now,-soname,"$name" -o "$work/oracle/$name"
done

# Keep the bad root's declared dependency absent in both execution roots.
rm "$work/oracle/libgraph-absent.so"
cp -a "$installed" "$work/candidate-root"
cp "$work"/libgraph-{leaf,left,right,ab,ba,bad}.so "$work/candidate-root/usr/lib/"
cp "$work"/libgraph-[0-9][0-9].so "$work/candidate-root/usr/lib/"
mkdir -p "$work/candidate-root/opt/plugins" "$work/oracle/aliases"
ln -s ../../usr/lib/libgraph-ab.so "$work/candidate-root/opt/plugins/libgraph-ab.so"
ln -s ../libgraph-ab.so "$work/oracle/aliases/libgraph-ab.so"
if [ -z "$ordinary" ]; then
    cp "$work/libgraph-ab.so" "$work/candidate-root/usr/lib/libgraph-malformed.so"
    cp "$work/oracle/libgraph-ab.so" "$work/oracle/libgraph-malformed.so"
    truncate -s 1 "$work/candidate-root/usr/lib/libgraph-malformed.so" "$work/oracle/libgraph-malformed.so"
fi

for mode in --dynamic-pie --dynamic-non-pie; do
    name="consumer${mode#--dynamic}"
    case "$mode" in --dynamic-pie) oracle_flags=(-fPIE -pie) ;; *) oracle_flags=(-fno-pie -no-pie) ;; esac
    "$driver" "$mode" "$source"_main.c -o "$work/$name"
    "$oracle_cc" "${oracle_flags[@]}" "$source"_main.c -o "$work/oracle/$name"
    cp "$work/$name" "$work/candidate-root/$name"
    LD_LIBRARY_PATH="$work/oracle/aliases:$work/oracle" timeout 30 "$work/oracle/$name" \
        "$extra" "$work/oracle/libgraph-ab.so" "${consumer_arguments[@]}" \
        >"$work/$name.oracle.stdout" 2>"$work/$name.oracle.stderr"
    for entry in kernel direct; do
        command=("/$name")
        [ "$entry" = kernel ] || command=(/lib/ld-crabc-x86_64.so.1 "/$name")
        LD_LIBRARY_PATH=/opt/plugins:/usr/lib timeout 30 chroot "$work/candidate-root" \
            "${command[@]}" "$extra" /usr/lib/libgraph-ab.so "${consumer_arguments[@]}" \
            >"$work/$name.$entry.stdout" 2>"$work/$name.$entry.stderr"
        cmp "$work/$name.$entry.stdout" "$work/$name.oracle.stdout"
        cmp "$work/$name.$entry.stderr" "$work/$name.oracle.stderr"
        [ "$(<"$work/$name.$entry.stdout")" = \
            'scope graph: rollback, breadth-first handles, retained state, promotion' ]
    done
done
printf 'owned loader scope graph: PASS (%s extra roots, PIE/non-PIE, kernel/direct, pinned-musl differential); evidence: %s\n' "$extra" "$work"
trap - EXIT
