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
# The runtime-registry attachment consumes the six dlfcn calls and its
# 41-module behavior only. Its supplied-product container has SYS_CHROOT but
# intentionally lacks the separate search leaf's proc-mount authority. Keep
# the normal runner complete by default; a sealed caller must explicitly opt
# into this bounded path and records that omission in its own receipt.
readonly skip_search="${CRABC_GENERAL_DYNAMIC_DLOPEN_SKIP_SEARCH:-0}"
case "$skip_search" in 0|1) ;; *) exit 2 ;; esac
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
# A pure-TBSS main has no initialized template bytes in the executable.
# Its per-thread zero fill can extend beyond every ordinary PT_LOAD.
"$driver" "$entry_mode" "$ROOT/compat/x86_64/general_dynamic_tbss.c" -o "$work/tbss-consumer"
readelf -lW "$work/tbss-consumer" >"$work/tbss-consumer.phdr"
python3 -B - "$work/tbss-consumer" <<'PYTHON'
from pathlib import Path
import struct
import sys
image = Path(sys.argv[1]).read_bytes()
offset = struct.unpack_from('<Q', image, 32)[0]
entry_size, count = struct.unpack_from('<HH', image, 54)
headers = [struct.unpack_from('<IIQQQQQQ', image, offset + index * entry_size) for index in range(count)]
tls, = [header for header in headers if header[0] == 7]
assert tls[5] == 0 and tls[6] == 8192 and tls[7] == 4096
assert not any(header[0] == 1 and header[3] <= tls[3] and tls[3] + tls[6] <= header[3] + header[6] for header in headers)
PYTHON
cp "$work/tbss-consumer" "$work/execution-root/tbss-consumer"
timeout 20 chroot "$work/execution-root" /tbss-consumer >"$work/tbss-candidate.stdout"
"$oracle_cc" "${oracle_entry_flags[@]}" "$ROOT/compat/x86_64/general_dynamic_tbss.c" -o "$work/tbss-oracle"
timeout 20 "$work/tbss-oracle" >"$work/tbss-oracle.stdout"
cmp "$work/tbss-candidate.stdout" "$work/tbss-oracle.stdout"
[ "$(<"$work/tbss-candidate.stdout")" = 'initial-tbss=8192,worker=isolated' ]
printf 'general initial pure TBSS: PASS (mapped-prefix boundary and independent worker zero fill); evidence: %s\n' "$work"

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
"$driver" "$entry_mode" "$ROOT/compat/x86_64/general_dynamic_iterate_consumer.c" -o "$work/iterate"
"$oracle_cc" "${oracle_entry_flags[@]}" "$ROOT/compat/x86_64/general_dynamic_iterate_consumer.c" \
    -Wl,-rpath,"$work/oracle" -o "$work/oracle/iterate"
cp "$work/iterate" "$work/execution-root/iterate"
timeout 20 chroot "$work/execution-root" /iterate >"$work/iterate-candidate.stdout"
LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/iterate" >"$work/iterate-oracle.stdout"
cmp "$work/iterate-oracle.stdout" "$work/iterate-candidate.stdout"
# A separate process keeps both DSOs runtime-new for the cross-thread append.
timeout 20 chroot "$work/execution-root" /iterate worker >"$work/iterate-worker-candidate.stdout"
LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/iterate" worker >"$work/iterate-worker-oracle.stdout"
cmp "$work/iterate-worker-oracle.stdout" "$work/iterate-worker-candidate.stdout"
[ "$(<"$work/iterate-candidate.stdout")" = 'dl_iterate_phdr: nested callback, retained mapping, bounded append' ]
printf 'general runtime iterate: PASS (nested callback, retained close, bounded appended DSO); evidence: %s\n' "$work"

# Hold a runtime DSO constructor while independent threads enter dlsym and
# dl_iterate_phdr. Pinned musl exposes the published image to both readers
# before the constructor returns; the constructor also reenters both APIs.
barrier_state="$ROOT/compat/x86_64/general_dynamic_constructor_barrier_state.c"
barrier_plugin="$ROOT/compat/x86_64/general_dynamic_constructor_barrier_plugin.c"
barrier_consumer="$ROOT/compat/x86_64/general_dynamic_constructor_barrier_consumer.c"
barrier_state_name=libconstructor-barrier-state.so
barrier_plugin_name=libconstructor-barrier.so
"$driver" --dynamic-shared-object "$barrier_state" -o "$work/$barrier_state_name"
"$driver" --dynamic-shared-object "$barrier_plugin" \
    --application-dso "$work/$barrier_state_name" -o "$work/$barrier_plugin_name"
"$driver" "$entry_mode" "$barrier_consumer" \
    --application-dso "$work/$barrier_state_name" -o "$work/constructor-barrier"
mkdir -p "$work/execution-root/usr/lib"
cp "$work/$barrier_state_name" "$work/$barrier_plugin_name" "$work/execution-root/usr/lib/"
cp "$work/constructor-barrier" "$work/execution-root/constructor-barrier"
status=0
timeout 20 chroot "$work/execution-root" /constructor-barrier \
    >"$work/constructor-barrier-candidate.stdout" 2>"$work/constructor-barrier-candidate.stderr" || status=$?
if [ "$status" -ne 0 ]; then
    printf 'general constructor visibility: FAIL status=%s; evidence: %s\n' "$status" "$work" >&2
    cat "$work/constructor-barrier-candidate.stderr" >&2
    exit 1
fi

mkdir -p "$work/oracle/constructor-barrier"
"$oracle_cc" -fPIC -shared -std=c11 "$barrier_state" \
    -Wl,-z,now,-soname,"$barrier_state_name" -o "$work/oracle/constructor-barrier/$barrier_state_name"
"$oracle_cc" -fPIC -shared -std=c11 "$barrier_plugin" \
    -I"$ROOT/compat/x86_64" -L"$work/oracle/constructor-barrier" \
    -l:libconstructor-barrier-state.so -Wl,-rpath,'$ORIGIN' \
    -Wl,-z,now,-soname,"$barrier_plugin_name" -o "$work/oracle/constructor-barrier/$barrier_plugin_name"
"$oracle_cc" "${oracle_entry_flags[@]}" -std=c11 "$barrier_consumer" \
    -I"$ROOT/compat/x86_64" -L"$work/oracle/constructor-barrier" \
    -l:libconstructor-barrier-state.so -Wl,-rpath,'$ORIGIN' \
    -o "$work/oracle/constructor-barrier/consumer"
LD_LIBRARY_PATH="$work/oracle/constructor-barrier" timeout 20 \
    "$work/oracle/constructor-barrier/consumer" \
    >"$work/constructor-barrier-oracle.stdout" 2>"$work/constructor-barrier-oracle.stderr"
cmp "$work/constructor-barrier-oracle.stdout" "$work/constructor-barrier-candidate.stdout"
[ "$(<"$work/constructor-barrier-candidate.stdout")" = \
    'constructor visibility: same-thread reentry and foreign dlsym/iterate visibility' ]
printf 'general constructor visibility: PASS (foreign dlsym/iterate visibility, same-thread reentry); evidence: %s\n' "$work"

"$driver" "$entry_mode" "$ROOT/compat/x86_64/general_dynamic_scope_consumer.c" -o "$work/scope"
"$oracle_cc" "${oracle_entry_flags[@]}" "$ROOT/compat/x86_64/general_dynamic_scope_consumer.c" \
    -Wl,-rpath,"$work/oracle" -o "$work/oracle/scope"
cp "$work/scope" "$work/execution-root/scope"
timeout 20 chroot "$work/execution-root" /scope >"$work/scope.stdout"
LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/scope" >"$work/oracle-scope.stdout"
cmp "$work/scope.stdout" "$work/oracle-scope.stdout"
printf 'general runtime scope: PASS (musl differential, caller RTLD_NEXT and promotion); evidence: %s\n' "$work"

if [ "$skip_search" = 0 ]; then
    bash "$ROOT/compat/x86_64/run_general_dynamic_search.sh" "$installed"
else
    printf 'general dynamic search: SKIPPED (separate proc-mount component; bounded dlfcn-only capture)\n'
fi
