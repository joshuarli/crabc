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

# Exact public dlfcn contract over an initial dependency plus a runtime-new
# closure: dlerror text, handle scope, mode bits, dladdr, dlinfo link maps,
# dl_iterate_phdr naming and exit-time dlopen. Absolute paths are reduced to
# basenames by the consumer; everything else must match pinned musl bytes.
contract_source="$ROOT/compat/x86_64/general_dynamic_dlfcn_contract_dso.c"
mkdir "$work/contract" "$work/oracle/contract"
contract_dso() {
    local name="$1" variant="$2" dependencies="${3:-}"
    local -a candidate_dependencies=() oracle_dependencies=()
    local dependency
    for dependency in $dependencies; do
        candidate_dependencies+=(--application-dso "$work/contract/lib$dependency.so")
        oracle_dependencies+=(-l:"lib$dependency.so")
    done
    "$driver" --dynamic-shared-object -D"$variant" "$contract_source" \
        "${candidate_dependencies[@]}" -o "$work/contract/lib$name.so"
    "$oracle_cc" -fPIC -shared -D"$variant" "$contract_source" -L"$work/oracle/contract" \
        -Wl,--no-as-needed "${oracle_dependencies[@]}" \
        -Wl,-z,now,-soname,"lib$name.so" -o "$work/oracle/contract/lib$name.so"
}
contract_dso dc_base BASE
contract_dso dc_init INIT dc_base
contract_dso dc_rtdep RTDEP
contract_dso dc_rt RT "dc_rtdep dc_base"
contract_dso dc_absent PROVIDER
contract_dso dc_missing MISSING dc_absent
contract_dso dc_provider PROVIDER
contract_dso dc_unresolved UNRESOLVED dc_provider
contract_dso dc_ie INITIAL_EXEC
contract_dso dc_plain PLAIN
# The missing dependency is absent and the unresolved provider lacks the
# requested definition in both runtime roots.
rm "$work/contract/libdc_absent.so" "$work/oracle/contract/libdc_absent.so"
"$driver" --dynamic-shared-object -DPROVIDER -DOMIT_PROVIDED "$contract_source" -o "$work/contract/libdc_provider.so.runtime"
mv "$work/contract/libdc_provider.so.runtime" "$work/contract/libdc_provider.so"
"$oracle_cc" -fPIC -shared -DPROVIDER -DOMIT_PROVIDED "$contract_source" \
    -Wl,-z,now,-soname,libdc_provider.so -o "$work/oracle/contract/libdc_provider.so"
for root in "$work/contract" "$work/oracle/contract"; do
    python3 -B "$ROOT/compat/x86_64/general_dynamic_failure_mutate.py" \
        "$root/libdc_plain.so" "$root/libdc_badtype.so" relocation-kind
    printf 'this is not an ELF object\n' >"$root/libdc_notelf.so"
done
"$driver" "$entry_mode" "$ROOT/compat/x86_64/general_dynamic_dlfcn_contract.c" \
    --application-dso "$work/contract/libdc_init.so" \
    --transitive-application-dso "$work/contract/libdc_base.so" -o "$work/dlfcn-contract"
"$oracle_cc" "${oracle_entry_flags[@]}" "$ROOT/compat/x86_64/general_dynamic_dlfcn_contract.c" \
    -L"$work/oracle/contract" -Wl,--no-as-needed -l:libdc_init.so -Wl,-rpath-link,"$work/oracle/contract" \
    -o "$work/oracle/contract/dlfcn-contract"
cp "$work"/contract/libdc_*.so "$work/execution-root/usr/lib/"
cp "$work/dlfcn-contract" "$work/execution-root/dlfcn-contract"
status=0
timeout 20 chroot "$work/execution-root" /dlfcn-contract \
    >"$work/dlfcn-contract-candidate.stdout" 2>"$work/dlfcn-contract-candidate.stderr" || status=$?
LD_LIBRARY_PATH="$work/oracle/contract" timeout 20 "$work/oracle/contract/dlfcn-contract" \
    >"$work/dlfcn-contract-oracle.stdout" 2>"$work/dlfcn-contract-oracle.stderr"
if [ "$status" -ne 0 ] || ! cmp -s "$work/dlfcn-contract-oracle.stdout" "$work/dlfcn-contract-candidate.stdout"; then
    printf 'general dlfcn contract: FAIL status=%s; evidence: %s\n' "$status" "$work" >&2
    diff -u "$work/dlfcn-contract-oracle.stdout" "$work/dlfcn-contract-candidate.stdout" >&2 || true
    exit 1
fi
grep -Fxq 'dlfcn contract: complete' "$work/dlfcn-contract-candidate.stdout"
grep -Fxq 'destructor dlopen: null; Cannot dlopen while program is exiting.' "$work/dlfcn-contract-candidate.stdout"
printf 'general dlfcn contract: PASS (musl differential, diagnostics, scope, modes, introspection); evidence: %s\n' "$work"

# Failed multi-object load rollback: a TLS dependency is mapped before a later
# dependency is missing or lacks a relocated symbol. Musl's rtld_fail cleanup
# publishes nothing; a retry succeeds once the complete dependency appears.
rollback_source="$ROOT/compat/x86_64/general_dynamic_dlfcn_contract_dso.c"
rollback_consumer="$ROOT/compat/x86_64/general_dynamic_dlfcn_contract_rollback.c"
mkdir "$work/rollback" "$work/oracle/rollback"
"$driver" --dynamic-shared-object -DFR_TLS "$rollback_source" -o "$work/rollback/libfr_tls.so"
"$driver" --dynamic-shared-object -DFR_LATE "$rollback_source" -o "$work/rollback/libfr_late.so"
"$driver" --dynamic-shared-object -DFR_LATE -DOMIT_PROVIDED "$rollback_source" -o "$work/rollback/libfr_late_omit.so"
"$driver" --dynamic-shared-object -DFR_ROOT "$rollback_source" \
    --application-dso "$work/rollback/libfr_tls.so" --application-dso "$work/rollback/libfr_late.so" \
    -o "$work/rollback/libfr_root.so"
"$driver" "$entry_mode" "$rollback_consumer" -o "$work/rollback/consumer"
"$oracle_cc" -fPIC -shared -DFR_TLS "$rollback_source" -Wl,-z,now,-soname,libfr_tls.so -o "$work/oracle/rollback/libfr_tls.so"
"$oracle_cc" -fPIC -shared -DFR_LATE "$rollback_source" -Wl,-z,now,-soname,libfr_late.so -o "$work/oracle/rollback/libfr_late.so"
"$oracle_cc" -fPIC -shared -DFR_LATE -DOMIT_PROVIDED "$rollback_source" \
    -Wl,-z,now,-soname,libfr_late.so -o "$work/oracle/rollback/libfr_late_omit.so"
"$oracle_cc" -fPIC -shared -DFR_ROOT "$rollback_source" -L"$work/oracle/rollback" -Wl,--no-as-needed \
    -l:libfr_tls.so -l:libfr_late.so -Wl,-z,now,-soname,libfr_root.so -o "$work/oracle/rollback/libfr_root.so"
"$oracle_cc" "${oracle_entry_flags[@]}" "$rollback_consumer" -pthread -o "$work/oracle/rollback/consumer"
cp "$work/rollback/consumer" "$work/execution-root/rollback"
for mode in missing unresolved; do
    for side in candidate oracle; do
        if [ "$side" = candidate ]; then
            built="$work/rollback" directory="$work/execution-root/rollback-$mode"
        else
            built="$work/oracle/rollback" directory="$work/oracle/rollback-$mode"
        fi
        mkdir "$directory"
        cp "$built/libfr_root.so" "$built/libfr_tls.so" "$directory/"
        cp "$built/libfr_late.so" "$directory/libfr_late.so.next"
        [ "$mode" = missing ] || cp "$built/libfr_late_omit.so" "$directory/libfr_late.so"
    done
    status=0
    LD_LIBRARY_PATH="/rollback-$mode" timeout 20 chroot "$work/execution-root" /rollback "/rollback-$mode" "$mode" \
        >"$work/rollback-$mode-candidate.stdout" 2>"$work/rollback-$mode-candidate.stderr" || status=$?
    LD_LIBRARY_PATH="$work/oracle/rollback-$mode" timeout 20 "$work/oracle/rollback/consumer" \
        "$work/oracle/rollback-$mode" "$mode" \
        >"$work/rollback-$mode-oracle.stdout" 2>"$work/rollback-$mode-oracle.stderr"
    if [ "$status" -ne 0 ] || ! cmp -s "$work/rollback-$mode-oracle.stdout" "$work/rollback-$mode-candidate.stdout"; then
        printf 'general failed-load rollback (%s): FAIL status=%s; evidence: %s\n' "$mode" "$status" "$work" >&2
        diff -u "$work/rollback-$mode-oracle.stdout" "$work/rollback-$mode-candidate.stdout" >&2 || true
        exit 1
    fi
    grep -Fxq 'rollback contract: complete' "$work/rollback-$mode-candidate.stdout"
done
printf 'general failed-load rollback: PASS (musl differential, missing and unresolved later dependency after TLS); evidence: %s\n' "$work"

# Concurrent successful and failed loads beside dlsym/dl_iterate_phdr readers.
# The failed graph is the rollback fixture above; readers must never observe
# it, and every published global success must stay resolvable.
concurrent_consumer="$ROOT/compat/x86_64/general_dynamic_dlfcn_contract_concurrent.c"
for index in $(seq 0 15); do
    "$driver" --dynamic-shared-object -DCC_OK -DINDEX="$index" "$rollback_source" -o "$work/rollback/libcc_ok$index.so"
    "$oracle_cc" -fPIC -shared -DCC_OK -DINDEX="$index" "$rollback_source" \
        -Wl,-z,now,-soname,"libcc_ok$index.so" -o "$work/oracle/rollback/libcc_ok$index.so"
done
"$driver" "$entry_mode" "$concurrent_consumer" -o "$work/rollback/concurrent"
"$oracle_cc" "${oracle_entry_flags[@]}" "$concurrent_consumer" -pthread -o "$work/oracle/rollback/concurrent"
cp "$work/rollback/concurrent" "$work/execution-root/concurrent"
for mode in missing unresolved; do
    for side in candidate oracle; do
        if [ "$side" = candidate ]; then
            built="$work/rollback" directory="$work/execution-root/concurrent-$mode"
        else
            built="$work/oracle/rollback" directory="$work/oracle/concurrent-$mode"
        fi
        mkdir "$directory"
        cp "$built/libfr_root.so" "$built/libfr_tls.so" "$built"/libcc_ok*.so "$directory/"
        [ "$mode" = missing ] || cp "$built/libfr_late_omit.so" "$directory/libfr_late.so"
    done
    for round in 1 2 3; do
        status=0
        LD_LIBRARY_PATH="/concurrent-$mode" timeout 60 chroot "$work/execution-root" /concurrent "$mode" \
            >"$work/concurrent-$mode-candidate.stdout" 2>"$work/concurrent-$mode-candidate.stderr" || status=$?
        LD_LIBRARY_PATH="$work/oracle/concurrent-$mode" timeout 60 "$work/oracle/rollback/concurrent" "$mode" \
            >"$work/concurrent-$mode-oracle.stdout" 2>"$work/concurrent-$mode-oracle.stderr"
        if [ "$status" -ne 0 ] || ! cmp -s "$work/concurrent-$mode-oracle.stdout" "$work/concurrent-$mode-candidate.stdout"; then
            printf 'general concurrent load (%s round %s): FAIL status=%s; evidence: %s\n' "$mode" "$round" "$status" "$work" >&2
            diff -u "$work/concurrent-$mode-oracle.stdout" "$work/concurrent-$mode-candidate.stdout" >&2 || true
            exit 1
        fi
    done
    grep -Fxq 'concurrent contract: complete' "$work/concurrent-$mode-candidate.stdout"
done
printf 'general concurrent load: PASS (musl differential, success/failure loads beside dlsym and dl_iterate_phdr readers); evidence: %s\n' "$work"

# dlfcn reentry from runtime constructors: nested NOLOAD of an unconstructed
# root, self reopen/close, nested loads and a pending caller-visible error.
reentrant_consumer="$ROOT/compat/x86_64/general_dynamic_dlfcn_contract_reentrant.c"
mkdir "$work/reentrant" "$work/oracle/reentrant"
"$driver" --dynamic-shared-object -DRE_DEP "$rollback_source" -o "$work/reentrant/libre_dep.so"
"$driver" --dynamic-shared-object -DRE_PLAIN "$rollback_source" -o "$work/reentrant/libre_plain.so"
"$driver" --dynamic-shared-object -DRE_ROOT "$rollback_source" \
    --application-dso "$work/reentrant/libre_dep.so" -o "$work/reentrant/libre_root.so"
"$driver" --dynamic-shared-object -DRE_PLAIN "$rollback_source" -o "$work/reentrant/libre_missing.so"
"$driver" --dynamic-shared-object -DRE_SHARED_FAIL "$rollback_source" --application-dso "$work/reentrant/libre_dep.so" \
    --application-dso "$work/reentrant/libre_missing.so" -o "$work/reentrant/libre_sharedfail.so"
"$driver" "$entry_mode" "$reentrant_consumer" -o "$work/reentrant/consumer"
"$oracle_cc" -fPIC -shared -DRE_DEP "$rollback_source" -Wl,-z,now,-soname,libre_dep.so -o "$work/oracle/reentrant/libre_dep.so"
"$oracle_cc" -fPIC -shared -DRE_PLAIN "$rollback_source" -Wl,-z,now,-soname,libre_plain.so -o "$work/oracle/reentrant/libre_plain.so"
"$oracle_cc" -fPIC -shared -DRE_ROOT "$rollback_source" -L"$work/oracle/reentrant" -Wl,--no-as-needed \
    -l:libre_dep.so -Wl,-z,now,-soname,libre_root.so -o "$work/oracle/reentrant/libre_root.so"
"$oracle_cc" -fPIC -shared -DRE_PLAIN "$rollback_source" -Wl,-z,now,-soname,libre_missing.so -o "$work/oracle/reentrant/libre_missing.so"
"$oracle_cc" -fPIC -shared -DRE_SHARED_FAIL "$rollback_source" -L"$work/oracle/reentrant" -Wl,--no-as-needed \
    -l:libre_dep.so -l:libre_missing.so -Wl,-z,now,-soname,libre_sharedfail.so -o "$work/oracle/reentrant/libre_sharedfail.so"
"$oracle_cc" "${oracle_entry_flags[@]}" "$reentrant_consumer" -o "$work/oracle/reentrant/consumer"
# The shared-failure object's second dependency is absent at run time.
rm "$work/reentrant/libre_missing.so" "$work/oracle/reentrant/libre_missing.so"
mkdir "$work/execution-root/reentrant"
cp "$work"/reentrant/libre_*.so "$work/execution-root/reentrant/"
cp "$work/reentrant/consumer" "$work/execution-root/reentrant-consumer"
status=0
LD_LIBRARY_PATH=/reentrant timeout 20 chroot "$work/execution-root" /reentrant-consumer \
    >"$work/reentrant-candidate.stdout" 2>"$work/reentrant-candidate.stderr" || status=$?
LD_LIBRARY_PATH="$work/oracle/reentrant" timeout 20 "$work/oracle/reentrant/consumer" \
    >"$work/reentrant-oracle.stdout" 2>"$work/reentrant-oracle.stderr"
if [ "$status" -ne 0 ] || ! cmp -s "$work/reentrant-oracle.stdout" "$work/reentrant-candidate.stdout"; then
    printf 'general constructor reentry: FAIL status=%s; evidence: %s\n' "$status" "$work" >&2
    diff -u "$work/reentrant-oracle.stdout" "$work/reentrant-candidate.stdout" >&2 || true
    exit 1
fi
grep -Fxq 'reentrant contract: complete' "$work/reentrant-candidate.stdout"
printf 'general constructor reentry: PASS (musl differential, nested NOLOAD/self/new loads and pending dlerror); evidence: %s\n' "$work"

# Malformed inputs musl's map_library rejects with ENOEXEC. Both roots mutate
# their own copy of the same valid source object.
malformed_consumer="$ROOT/compat/x86_64/general_dynamic_dlfcn_contract_malformed.c"
malformed_cases=(empty short relocatable core truncated-phdr no-phdr no-dynamic needs)
mkdir "$work/execution-root/malformed" "$work/oracle/malformed"
"$driver" --dynamic-shared-object -DPLAIN "$rollback_source" -o "$work/execution-root/malformed/libmf_valid.so"
"$oracle_cc" -fPIC -shared -DPLAIN "$rollback_source" -Wl,-z,now,-soname,libmf_valid.so -o "$work/oracle/malformed/libmf_valid.so"
# libmf_needs.so links against a valid libmf_dep.so that is then replaced by
# a relocatable copy, so the rejection is reported for a dependency.
"$driver" --dynamic-shared-object -DPLAIN "$rollback_source" -o "$work/execution-root/malformed/libmf_dep.so"
"$driver" --dynamic-shared-object -DPROVIDER "$rollback_source" \
    --application-dso "$work/execution-root/malformed/libmf_dep.so" -o "$work/execution-root/malformed/libmf_needs.so"
"$oracle_cc" -fPIC -shared -DPLAIN "$rollback_source" -Wl,-z,now,-soname,libmf_dep.so -o "$work/oracle/malformed/libmf_dep.so"
"$oracle_cc" -fPIC -shared -DPROVIDER "$rollback_source" -L"$work/oracle/malformed" -Wl,--no-as-needed -l:libmf_dep.so \
    -Wl,-z,now,-soname,libmf_needs.so -o "$work/oracle/malformed/libmf_needs.so"
for directory in "$work/execution-root/malformed" "$work/oracle/malformed"; do
    python3 -B "$ROOT/compat/x86_64/general_dynamic_dlfcn_contract_malformed.py" "$directory/libmf_valid.so" "$directory"
    mv "$directory/libmf_relocatable.so" "$directory/libmf_dep.so"
    python3 -B "$ROOT/compat/x86_64/general_dynamic_dlfcn_contract_malformed.py" "$directory/libmf_valid.so" "$directory" relocatable
done
"$driver" "$entry_mode" "$malformed_consumer" -o "$work/execution-root/malformed-consumer"
"$oracle_cc" "${oracle_entry_flags[@]}" "$malformed_consumer" -o "$work/oracle/malformed-consumer"
status=0
LD_LIBRARY_PATH=/malformed timeout 20 chroot "$work/execution-root" /malformed-consumer "${malformed_cases[@]}" \
    >"$work/malformed-candidate.stdout" 2>"$work/malformed-candidate.stderr" || status=$?
LD_LIBRARY_PATH="$work/oracle/malformed" timeout 20 "$work/oracle/malformed-consumer" "${malformed_cases[@]}" \
    >"$work/malformed-oracle.stdout" 2>"$work/malformed-oracle.stderr"
if [ "$status" -ne 0 ] || ! cmp -s "$work/malformed-oracle.stdout" "$work/malformed-candidate.stdout"; then
    printf 'general malformed input: FAIL status=%s; evidence: %s\n' "$status" "$work" >&2
    diff -u "$work/malformed-oracle.stdout" "$work/malformed-candidate.stdout" >&2 || true
    exit 1
fi
grep -Fxq 'malformed contract: complete' "$work/malformed-candidate.stdout"
printf 'general malformed input: PASS (musl differential, %s map_library rejections, one as a dependency, and a later valid load); evidence: %s\n' \
    "${#malformed_cases[@]}" "$work"

if [ "$skip_search" = 0 ]; then
    bash "$ROOT/compat/x86_64/run_general_dynamic_search.sh" "$installed"
else
    printf 'general dynamic search: SKIPPED (separate proc-mount component; bounded dlfcn-only capture)\n'
fi
