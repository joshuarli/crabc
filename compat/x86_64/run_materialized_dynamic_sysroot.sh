#!/usr/bin/env bash
# Installed initial/runtime graph evidence. Full dynamic campaign stays open.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$(uname -sm)" = 'Linux x86_64' ]
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('materialized dynamic TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/materialized-dynamic.XXXXXX")"
readonly work
# Reuse the normal installed driver for actual ELF interposition. Both the
# parent and exec target are owned binaries inside this run's private root.
check_spawn_interposition() {
    local installed="$1" execution_root="$2" name="$3"
    "$installed/bin/crabc-cc-dynamic" --dynamic-pie -DCRABC_SPAWN_ELF_INTERPOSITION \
        "$ROOT/compat/x86_64/owned_spawn_interposition_probe.c" -o "$work/$name"
    readelf --dyn-syms -W "$work/$name" >"$work/$name.symbols"
    for symbol in memcpy memset; do
        awk -v name="$symbol" '$5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { found = 1 }
            END { exit !found }' "$work/$name.symbols"
    done
    # The installed compiler driver already owns bin/ in this private copy.
    [ -d "$execution_root/bin" ]
    cp "$work/$name" "$execution_root/spawn-interposition"
    cp "$work/$name" "$execution_root/bin/true"
    timeout 20 chroot "$execution_root" /spawn-interposition >"$work/$name.stdout"
    [ ! -s "$work/$name.stdout" ]
}

check_non_pie() {
    local installed_root="$1" execution_root="$2" dependency="$3" name="$4"
    "$installed_root/bin/crabc-cc-dynamic" --dynamic-non-pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
        --application-dso "$dependency" -o "$work/$name"
    readelf -hW "$work/$name" >"$work/$name.header"
    grep -Eq 'Type: +EXEC' "$work/$name.header"
    readelf -lW "$work/$name" >"$work/$name.segments"
    grep -Fq '/lib/ld-crabc-x86_64.so.1' "$work/$name.segments"
    cp "$work/$name" "$execution_root/non-pie"
    timeout 20 chroot "$execution_root" /non-pie >"$work/$name.stdout"
    cmp "$work/expected.stdout" "$work/$name.stdout"
}
python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" prepare --work "$work"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIC -shared "$ROOT/compat/x86_64/owned_dynamic_dependency.c" \
    -Wl,-soname,liboracle-dependency.so -o "$work/liboracle-dependency.so"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIE -pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
    -L"$work" -Wl,-rpath,"$work" -l:liboracle-dependency.so -o "$work/oracle"
timeout 20 "$work/oracle" >"$work/oracle.stdout"
# Each clean build and the extracted package execute the same product matrix.
# Byte equality is a separate prerequisite, not an execution receipt.
check_basic_product() {
    local product="$1" label="$2"
    local driver="$product/bin/crabc-cc-dynamic"
    local dependency="$work/lib$label.so"
    local consumer="$work/$label-consumer"
    local execution_root="$work/$label-execution-root"
    "$driver" --dynamic-shared-object "$ROOT/compat/x86_64/owned_dynamic_dependency.c" -o "$dependency"
    "$driver" --dynamic-pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
        --application-dso "$dependency" -o "$consumer"
    for artifact in "$product/lib/ld-crabc-x86_64.so.1" "$product/usr/lib/libc.so"; do
        readelf -dW "$artifact" >"$work/$label-$(basename "$artifact").dynamic.txt"
        ! grep -E '\(NEEDED\)|\(TEXTREL\)' "$work/$label-$(basename "$artifact").dynamic.txt"
    done
    readelf -lW "$consumer" >"$consumer.segments.txt"
    grep -Fq '/lib/ld-crabc-x86_64.so.1' "$consumer.segments.txt"
    # The complete execution root and its writable scratch remain below .work.
    cp -a "$product" "$execution_root"
    mkdir "$execution_root/tmp"
    cp "$consumer" "$execution_root/consumer"
    cp "$dependency" "$execution_root/usr/lib/$(basename "$dependency")"
    timeout 20 chroot "$execution_root" /consumer >"$consumer.stdout"
    cmp "$work/expected.stdout" "$consumer.stdout"
    cmp "$work/oracle.stdout" "$consumer.stdout"
    check_spawn_interposition "$product" "$execution_root" "spawn-$label"
    check_non_pie "$product" "$execution_root" "$dependency" "non-pie-$label"
}

check_runtime_suites() {
    local label="$1" cases case_name
    # The qualification catalog owns the complete leaf/mode roster. Capture its
    # exit status before the loop so discovery failures cannot omit coverage.
    cases="$(python3 -B - "$ROOT" <<'PYTHON'
import sys
sys.path.insert(0, sys.argv[1] + '/compat/x86_64')
from owned_dynamic_qualification import CASES
print('\n'.join(CASES))
PYTHON
)"
    while IFS= read -r case_name; do
        python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" run \
            --work "$work" --product "$label" --case "$case_name"
    done <<<"$cases"
}

python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/installed"
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/second"
cmp "$work/installed/share/crabc/manifest.json" "$work/second/share/crabc/manifest.json"
python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" package "$work/installed" "$work/runtime.tar"
python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" package "$work/second" "$work/second-runtime.tar"
cmp "$work/runtime.tar" "$work/second-runtime.tar"
python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" extract "$work/runtime.tar" "$work/extracted"
printf 'installed dynamic: allocation errno stdio threads\nordinary exit\n' >"$work/expected.stdout"
for label in installed second extracted; do
    check_basic_product "$work/$label" "$label"
    check_runtime_suites "$label"
    printf 'materialized dynamic product: PASS (%s)\n' "$label"
done
python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" finish --work "$work"
printf 'materialized dynamic sysroot: PASS (two clean builds and extracted initial/runtime graphs); evidence: %s\n' "$work"
