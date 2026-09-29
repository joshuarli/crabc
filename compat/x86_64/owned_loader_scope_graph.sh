#!/usr/bin/env bash
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { echo "usage: $0 INSTALLED_DYNAMIC_SYSROOT [EXTRA_ROOTS]" >&2; exit 2; }
readonly installed="$1"
readonly extra="${2:-16}"
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

"$driver" --dynamic-pie "$source"_main.c -o "$work/consumer"
"$oracle_cc" -fPIE -pie "$source"_main.c -o "$work/oracle/consumer"
# Keep the bad root's declared dependency absent in both execution roots.
rm "$work/oracle/libgraph-absent.so"
cp -a "$installed" "$work/candidate-root"
cp "$work/consumer" "$work/candidate-root/consumer"
cp "$work"/libgraph-{leaf,left,right,ab,ba,bad}.so "$work/candidate-root/usr/lib/"
cp "$work"/libgraph-[0-9][0-9].so "$work/candidate-root/usr/lib/"
mkdir -p "$work/candidate-root/opt/plugins" "$work/oracle/aliases"
ln -s ../../usr/lib/libgraph-ab.so "$work/candidate-root/opt/plugins/libgraph-ab.so"
ln -s ../libgraph-ab.so "$work/oracle/aliases/libgraph-ab.so"
cp "$work/libgraph-ab.so" "$work/candidate-root/usr/lib/libgraph-malformed.so"
cp "$work/oracle/libgraph-ab.so" "$work/oracle/libgraph-malformed.so"
truncate -s 1 "$work/candidate-root/usr/lib/libgraph-malformed.so" "$work/oracle/libgraph-malformed.so"

LD_LIBRARY_PATH=/opt/plugins:/usr/lib timeout 30 chroot "$work/candidate-root" \
    /consumer "$extra" /usr/lib/libgraph-ab.so >"$work/candidate.stdout" 2>"$work/candidate.stderr"
LD_LIBRARY_PATH="$work/oracle/aliases:$work/oracle" timeout 30 "$work/oracle/consumer" \
    "$extra" "$work/oracle/libgraph-ab.so" \
    >"$work/oracle.stdout" 2>"$work/oracle.stderr"
cmp "$work/candidate.stdout" "$work/oracle.stdout"
cmp "$work/candidate.stderr" "$work/oracle.stderr"
[ "$(<"$work/candidate.stdout")" = \
    'scope graph: rollback, breadth-first handles, retained state, promotion' ]
printf 'owned loader scope graph: PASS (%s extra roots, pinned-musl differential); evidence: %s\n' "$extra" "$work"
trap - EXIT
