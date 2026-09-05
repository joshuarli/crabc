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
python3 -B -m unittest discover -s "$ROOT/compat/x86_64" -p test_owned_dynamic_driver.py
python3 -B -m unittest discover -s "$ROOT/crt/tests" -p test_x86_64_dynamic_modes.py
rustc --edition=2021 --test --cfg crabc_general_initial_graph \
    --cfg crabc_general_initial_tls_materialization_v1 --cfg crabc_general_loader_libc_tls_runtime_v1 \
    --cfg crabc_general_initial_lifecycle --cfg crabc_dynamic_main_thread_runtime_v1 \
    --cfg 'feature="x86_64-owned-dynamic-runtime"' \
    "$ROOT/ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs" -o "$work/loader-tests"
"$work/loader-tests"
bash "$ROOT/compat/x86_64/run_musl_oracle.sh"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIC -shared "$ROOT/compat/x86_64/owned_dynamic_dependency.c" \
    -Wl,-soname,liboracle-dependency.so -o "$work/liboracle-dependency.so"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIE -pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
    -L"$work" -Wl,-rpath,"$work" -l:liboracle-dependency.so -o "$work/oracle"
timeout 20 "$work/oracle" >"$work/oracle.stdout"
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/installed"
driver="$work/installed/bin/crabc-cc-dynamic"
"$driver" --dynamic-shared-object "$ROOT/compat/x86_64/owned_dynamic_dependency.c" -o "$work/libapplication.so"
"$driver" --dynamic-pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
    --application-dso "$work/libapplication.so" -o "$work/consumer"
for artifact in "$work/installed/lib/ld-crabc-x86_64.so.1" "$work/installed/usr/lib/libc.so"; do
    readelf -dW "$artifact" >"$work/$(basename "$artifact").dynamic.txt"
    ! grep -E '\(NEEDED\)|\(TEXTREL\)' "$work/$(basename "$artifact").dynamic.txt"
done
readelf -lW "$work/consumer" >"$work/consumer.segments.txt"
grep -Fq '/lib/ld-crabc-x86_64.so.1' "$work/consumer.segments.txt"
# Chroot changes only pathname resolution inside this private container. The
# complete runtime image and its writable scratch still live below .work.
cp -a "$work/installed" "$work/execution-root"
mkdir "$work/execution-root/tmp"
cp "$work/consumer" "$work/execution-root/consumer"
cp "$work/libapplication.so" "$work/execution-root/usr/lib/libapplication.so"
timeout 20 chroot "$work/execution-root" /consumer >"$work/consumer.stdout"
printf 'installed dynamic: allocation errno stdio threads\nordinary exit\n' >"$work/expected.stdout"
cmp "$work/expected.stdout" "$work/consumer.stdout"
cmp "$work/oracle.stdout" "$work/consumer.stdout"
check_spawn_interposition "$work/installed" "$work/execution-root" spawn-installed
check_non_pie "$work/installed" "$work/execution-root" "$work/libapplication.so" non-pie-installed
python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" package "$work/installed" "$work/runtime.tar"
python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" extract "$work/runtime.tar" "$work/extracted"
extracted_driver="$work/extracted/bin/crabc-cc-dynamic"
"$extracted_driver" --dynamic-shared-object "$ROOT/compat/x86_64/owned_dynamic_dependency.c" -o "$work/libextracted.so"
"$extracted_driver" --dynamic-pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
    --application-dso "$work/libextracted.so" -o "$work/extracted-consumer"
cp -a "$work/extracted" "$work/extracted-execution-root"
mkdir "$work/extracted-execution-root/tmp"
cp "$work/extracted-consumer" "$work/extracted-execution-root/consumer"
cp "$work/libextracted.so" "$work/extracted-execution-root/usr/lib/libextracted.so"
timeout 20 chroot "$work/extracted-execution-root" /consumer >"$work/extracted-consumer.stdout"
cmp "$work/expected.stdout" "$work/extracted-consumer.stdout"
check_spawn_interposition "$work/extracted" "$work/extracted-execution-root" spawn-extracted
check_non_pie "$work/extracted" "$work/extracted-execution-root" "$work/libextracted.so" non-pie-extracted
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/second"
cmp "$work/installed/share/crabc/manifest.json" "$work/second/share/crabc/manifest.json"
python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" package "$work/second" "$work/second-runtime.tar"
cmp "$work/runtime.tar" "$work/second-runtime.tar"
bash "$ROOT/compat/x86_64/run_general_dynamic_dlopen.sh" "$work/installed"
bash "$ROOT/compat/x86_64/run_general_dynamic_dlopen.sh" "$work/extracted"
bash "$ROOT/compat/x86_64/run_general_dynamic_constructor_exit.sh" "$work/installed"
bash "$ROOT/compat/x86_64/run_general_dynamic_constructor_exit.sh" "$work/extracted"
bash "$ROOT/compat/x86_64/run_general_dynamic_pthread_exit.sh" "$work/installed"
bash "$ROOT/compat/x86_64/run_general_dynamic_pthread_exit.sh" "$work/extracted"
CRABC_GENERAL_DYNAMIC_ENTRY_MODE=--dynamic-non-pie bash "$ROOT/compat/x86_64/run_general_dynamic_dlopen.sh" "$work/installed"
CRABC_GENERAL_DYNAMIC_ENTRY_MODE=--dynamic-non-pie bash "$ROOT/compat/x86_64/run_general_dynamic_dlopen.sh" "$work/extracted"
bash "$ROOT/compat/x86_64/run_general_dynamic_lazy.sh" "$work/installed"
bash "$ROOT/compat/x86_64/run_general_dynamic_lazy.sh" "$work/extracted"
CRABC_GENERAL_DYNAMIC_ENTRY_MODE=--dynamic-non-pie bash "$ROOT/compat/x86_64/run_general_dynamic_lazy.sh" "$work/installed"
CRABC_GENERAL_DYNAMIC_ENTRY_MODE=--dynamic-non-pie bash "$ROOT/compat/x86_64/run_general_dynamic_lazy.sh" "$work/extracted"
printf 'materialized dynamic sysroot: PASS (initial and retained runtime graphs); evidence: %s\n' "$work"
