#!/usr/bin/env bash
# Deferred binding through the real installed driver, with a pinned-source
# RELRO safety difference reported separately from ordinary PLT parity.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || { printf 'usage: %s INSTALLED_DYNAMIC_SYSROOT\n' "$0" >&2; exit 2; }
readonly installed="$1" driver="$1/bin/crabc-cc-dynamic"
readonly entry_mode="${CRABC_GENERAL_DYNAMIC_ENTRY_MODE:---dynamic-pie}"
case "$entry_mode" in --dynamic-pie|--dynamic-non-pie) ;; *) exit 2 ;; esac
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('deferred binding TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/general-dynamic-lazy.XXXXXX")"
readonly work
mkdir "$work/oracle"
cp -a "$installed" "$work/execution-root"
bash "$ROOT/compat/x86_64/run_musl_oracle.sh"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
for contract in undeclared wrong-name; do
    imports=()
    [ "$contract" = undeclared ] || imports=(--runtime-import accidental_import)
    status=0
    "$driver" --dynamic-shared-object --binding lazy "${imports[@]}" \
        "$ROOT/compat/x86_64/general_dynamic_lazy_plugin.c" -o "$work/$contract.so" \
        >"$work/$contract.stdout" 2>"$work/$contract.stderr" || status=$?
    [ "$status" -ne 0 ]
    [ ! -e "$work/$contract.so.crabc-link.json" ]
done
oracle_entry=(-fPIE -pie)
[ "$entry_mode" = --dynamic-pie ] || oracle_entry=(-fno-pie -no-pie)
for mode in plt got; do
    flags=() import=deferred_function
    [ "$mode" = plt ] || { flags=(-DDEFERRED_GOT); import=deferred_value; }
    "$driver" --dynamic-shared-object --binding lazy --runtime-import "$import" "${flags[@]}" \
        "$ROOT/compat/x86_64/general_dynamic_lazy_plugin.c" -o "$work/libdeferred-$mode.so"
    "$oracle_cc" -fPIC -shared "${flags[@]}" "$ROOT/compat/x86_64/general_dynamic_lazy_plugin.c" \
        -Wl,-z,lazy,-z,relro,-soname,"libdeferred-$mode.so" -o "$work/oracle/libdeferred-$mode.so"
    readelf -rW "$work/libdeferred-$mode.so" >"$work/$mode.relocations"
    readelf -dW "$work/libdeferred-$mode.so" >"$work/$mode.dynamic"
    ! grep -E 'BIND_NOW|FLAGS_1.*NOW' "$work/$mode.dynamic"
    cp "$work/libdeferred-$mode.so" "$work/execution-root/usr/lib/"
done
grep -F 'R_X86_64_JUMP_SLOT' "$work/plt.relocations" | grep -F 'deferred_function'
grep -F 'R_X86_64_GLOB_DAT' "$work/got.relocations" | grep -F 'deferred_value'
"$driver" --dynamic-shared-object "$ROOT/compat/x86_64/general_dynamic_lazy_provider.c" -o "$work/libdeferred-provider.so"
"$driver" --dynamic-shared-object --binding lazy --runtime-import unrelated_missing -DDEFERRED_BAD \
    "$ROOT/compat/x86_64/general_dynamic_lazy_provider.c" -o "$work/libdeferred-bad.so"
"$oracle_cc" -fPIC -shared "$ROOT/compat/x86_64/general_dynamic_lazy_provider.c" \
    -Wl,-z,now,-soname,libdeferred-provider.so -o "$work/oracle/libdeferred-provider.so"
"$oracle_cc" -fPIC -shared -DDEFERRED_BAD "$ROOT/compat/x86_64/general_dynamic_lazy_provider.c" \
    -Wl,-z,lazy,-soname,libdeferred-bad.so -o "$work/oracle/libdeferred-bad.so"
"$driver" "$entry_mode" "$ROOT/compat/x86_64/general_dynamic_lazy_consumer.c" -o "$work/consumer"
"$oracle_cc" "${oracle_entry[@]}" "$ROOT/compat/x86_64/general_dynamic_lazy_consumer.c" -o "$work/oracle/consumer"
cp "$work/consumer" "$work/execution-root/consumer"
cp "$work/libdeferred-provider.so" "$work/libdeferred-bad.so" "$work/execution-root/usr/lib/"
for mode in plt got; do
    timeout 20 chroot "$work/execution-root" /consumer "libdeferred-$mode.so" "$mode" >"$work/$mode.stdout"
done
LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/consumer" libdeferred-plt.so plt >"$work/oracle-plt.stdout"
cmp "$work/plt.stdout" "$work/oracle-plt.stdout"
cmp "$work/plt.stdout" "$work/got.stdout"
# Pinned musl retries this GLOB_DAT by writing through an already read-only
# RELRO page. Preserve the actual fault as evidence; do not call it parity.
status=0
{ LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/consumer" libdeferred-got.so got >"$work/oracle-got.stdout"; } 2>"$work/oracle-got.stderr" || status=$?
[ "$status" -eq 139 ]
printf 'deferred binding: PASS (PLT musl differential, isolated GOT/RELRO safety correction); evidence: %s\n' "$work"
