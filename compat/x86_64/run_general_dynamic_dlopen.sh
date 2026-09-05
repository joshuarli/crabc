#!/usr/bin/env bash
# General runtime-load component evidence through a sealed installed driver.
# This does not by itself qualify the complete dynamic product campaign.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ulimit -c 0
[ "$#" -eq 1 ] || { printf 'usage: %s INSTALLED_DYNAMIC_SYSROOT\n' "$0" >&2; exit 2; }
readonly installed="$1"
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly entry_mode="${CRABC_GENERAL_DYNAMIC_ENTRY_MODE:---dynamic-pie}"
case "$entry_mode" in --dynamic-pie|--dynamic-non-pie) ;; *) exit 2 ;; esac
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('general dynamic dlopen TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/general-dynamic-dlopen.XXXXXX")"
readonly work
# Reuse existing portable source fixtures unchanged. The executable has no
# initial dependency on either plugin; the middle's leaf is also runtime-new.
"$driver" --dynamic-shared-object "$ROOT/compat/ldso/fixtures/nested_leaf.c" -o "$work/libnested_leaf.so"
"$driver" --dynamic-shared-object "$ROOT/compat/ldso/fixtures/nested_mid.c" \
    --application-dso "$work/libnested_leaf.so" -o "$work/libnested_mid.so"
"$driver" "$entry_mode" "$ROOT/compat/ldso/fixtures/nested_dlopen.c" -o "$work/consumer"
cp -a "$installed" "$work/execution-root"
cp "$work/consumer" "$work/execution-root/consumer"
cp "$work/libnested_leaf.so" "$work/libnested_mid.so" "$work/execution-root/usr/lib/"
status=0
timeout 20 chroot "$work/execution-root" /consumer >"$work/consumer.stdout" || status=$?
if [ "$status" -ne 0 ]; then
    printf 'general runtime dlopen: FAIL status=%s; evidence: %s\n' "$status" "$work" >&2
    exit 1
fi
[ "$(<"$work/consumer.stdout")" = 'nested-dlopen=42' ]
printf 'general runtime dlopen: PASS (runtime-new dependency closure); evidence: %s\n' "$work"
bash "$ROOT/compat/x86_64/run_musl_oracle.sh"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
oracle_entry_flags=(-fPIE -pie)
[ "$entry_mode" = --dynamic-pie ] || oracle_entry_flags=(-fno-pie -no-pie)
mkdir "$work/oracle"
for generation in $(seq 0 40); do
    "$driver" --dynamic-shared-object -DGENERATION="$generation" \
        "$ROOT/compat/x86_64/general_dynamic_tls_plugin.c" -o "$work/libgrowth$generation.so"
    "$oracle_cc" -fPIC -shared -DGENERATION="$generation" \
        "$ROOT/compat/x86_64/general_dynamic_tls_plugin.c" \
        -Wl,-z,now,-soname,"libgrowth$generation.so" -o "$work/oracle/libgrowth$generation.so"
    cp "$work/libgrowth$generation.so" "$work/execution-root/usr/lib/"
done
"$driver" "$entry_mode" "$ROOT/compat/x86_64/general_dynamic_tls_consumer.c" -o "$work/growth"
"$oracle_cc" "${oracle_entry_flags[@]}" "$ROOT/compat/x86_64/general_dynamic_tls_consumer.c" \
    -Wl,-rpath,"$work/oracle" -o "$work/oracle/growth"
cp "$work/growth" "$work/execution-root/growth"
LD_LIBRARY_PATH="$work/oracle" timeout 40 "$work/oracle/growth" >"$work/oracle.stdout"
status=0
timeout 40 chroot "$work/execution-root" /growth >"$work/growth.stdout" || status=$?
if [ "$status" -ne 0 ]; then
    printf 'general runtime TLS: FAIL status=%s; evidence: %s\n' "$status" "$work" >&2
    exit 1
fi
cmp "$work/oracle.stdout" "$work/growth.stdout"
printf 'general runtime TLS: PASS (musl differential, 41 runtime modules and existing/new workers); evidence: %s\n' "$work"
"$driver" --dynamic-shared-object "$ROOT/compat/x86_64/general_dynamic_failure_plugin.c" -o "$work/libfailure.so"
"$driver" --dynamic-shared-object -DINITIAL_EXEC "$ROOT/compat/x86_64/general_dynamic_failure_plugin.c" -o "$work/libfailure-ie.so"
"$driver" "$entry_mode" "$ROOT/compat/x86_64/general_dynamic_failure_consumer.c" -o "$work/failure"
"$oracle_cc" -fPIC -shared "$ROOT/compat/x86_64/general_dynamic_failure_plugin.c" \
    -Wl,-z,now,-soname,libfailure.so -o "$work/oracle/libfailure.so"
"$oracle_cc" -fPIC -shared -DINITIAL_EXEC "$ROOT/compat/x86_64/general_dynamic_failure_plugin.c" \
    -Wl,-z,now,-soname,libfailure-ie.so -o "$work/oracle/libfailure-ie.so"
"$oracle_cc" "${oracle_entry_flags[@]}" "$ROOT/compat/x86_64/general_dynamic_failure_consumer.c" \
    -Wl,-rpath,"$work/oracle" -o "$work/oracle/failure"
cp "$work/failure" "$work/execution-root/failure"
cp "$work/libfailure-ie.so" "$work/execution-root/usr/lib/"
for case in unresolved array-half tls-filesz relocation-kind; do
    python3 -B "$ROOT/compat/x86_64/general_dynamic_failure_mutate.py" \
        "$work/libfailure.so" "$work/execution-root/usr/lib/libfailure-$case.so" "$case"
done
python3 -B "$ROOT/compat/x86_64/general_dynamic_failure_mutate.py" \
    "$work/oracle/libfailure.so" "$work/oracle/libfailure-unresolved.so" unresolved
for case in ie unresolved array-half tls-filesz relocation-kind; do
    timeout 20 chroot "$work/execution-root" /failure "libfailure-$case.so" >"$work/failure-$case.stdout"
done
# Invalid ELF encodings are owned rejection tests, not forced musl parity.
# Genuine undefined-symbol and new initial-exec failures are differential.
for case in ie unresolved; do
    LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/failure" "libfailure-$case.so" >"$work/oracle-failure-$case.stdout"
    cmp "$work/oracle-failure-$case.stdout" "$work/failure-$case.stdout"
done
printf 'general runtime rollback: PASS (5 pre-callback failures, 2 musl differentials); evidence: %s\n' "$work"
for provider in first second; do
    flags=()
    [ "$provider" = first ] || flags=(-DSECOND_PROVIDER)
    "$driver" --dynamic-shared-object "${flags[@]}" "$ROOT/compat/x86_64/general_dynamic_scope_plugin.c" -o "$work/libscope-$provider.so"
    "$oracle_cc" -fPIC -shared "${flags[@]}" "$ROOT/compat/x86_64/general_dynamic_scope_plugin.c" \
        -Wl,-z,now,-soname,"libscope-$provider.so" -o "$work/oracle/libscope-$provider.so"
    cp "$work/libscope-$provider.so" "$work/execution-root/usr/lib/"
done
"$driver" "$entry_mode" "$ROOT/compat/x86_64/general_dynamic_scope_consumer.c" -o "$work/scope"
"$oracle_cc" "${oracle_entry_flags[@]}" "$ROOT/compat/x86_64/general_dynamic_scope_consumer.c" \
    -Wl,-rpath,"$work/oracle" -o "$work/oracle/scope"
cp "$work/scope" "$work/execution-root/scope"
timeout 20 chroot "$work/execution-root" /scope >"$work/scope.stdout"
LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/scope" >"$work/oracle-scope.stdout"
cmp "$work/scope.stdout" "$work/oracle-scope.stdout"
printf 'general runtime scope: PASS (musl differential, caller RTLD_NEXT and promotion); evidence: %s\n' "$work"

bash "$ROOT/compat/x86_64/run_general_dynamic_search.sh" "$installed"
