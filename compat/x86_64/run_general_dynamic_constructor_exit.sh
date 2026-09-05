#!/usr/bin/env bash
# A constructor calling exit must not finalize its own incomplete object.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('constructor-exit TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/general-constructor-exit.XXXXXX")"
readonly work
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
mkdir "$work/oracle"
"$driver" --dynamic-shared-object "$ROOT/compat/x86_64/general_dynamic_tls_plugin.c" -o "$work/libgrowth0.so"
"$driver" --dynamic-shared-object "$ROOT/compat/x86_64/general_dynamic_constructor_exit_plugin.c" -o "$work/libconstructor-exit.so"
"$driver" --dynamic-pie "$ROOT/compat/x86_64/general_dynamic_constructor_exit_consumer.c" -o "$work/consumer"
"$oracle_cc" -fPIC -shared "$ROOT/compat/x86_64/general_dynamic_tls_plugin.c" \
    -Wl,-z,now,-soname,libgrowth0.so -o "$work/oracle/libgrowth0.so"
"$oracle_cc" -fPIC -shared "$ROOT/compat/x86_64/general_dynamic_constructor_exit_plugin.c" \
    -Wl,-z,now,-soname,libconstructor-exit.so -o "$work/oracle/libconstructor-exit.so"
"$oracle_cc" -fPIE -pie "$ROOT/compat/x86_64/general_dynamic_constructor_exit_consumer.c" \
    -Wl,-rpath,"$work/oracle" -o "$work/oracle/consumer"
cp -a "$installed" "$work/execution-root"
cp "$work/consumer" "$work/execution-root/consumer"
cp "$work/libgrowth0.so" "$work/libconstructor-exit.so" "$work/execution-root/usr/lib/"
candidate=0 oracle=0
timeout 20 chroot "$work/execution-root" /consumer >"$work/candidate.stdout" || candidate=$?
LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/consumer" >"$work/oracle.stdout" || oracle=$?
[ "$candidate" -eq 23 ] && [ "$oracle" -eq 23 ]
printf 'constructor exits before completion\nruntime fini 0\n' >"$work/expected.stdout"
cmp "$work/expected.stdout" "$work/oracle.stdout"
cmp "$work/oracle.stdout" "$work/candidate.stdout"
"$driver" --dynamic-pie "$ROOT/compat/x86_64/general_dynamic_constructor_exit_consumer.c" \
    --application-dso "$work/libgrowth0.so" --application-dso "$work/libconstructor-exit.so" \
    -o "$work/initial-consumer"
"$oracle_cc" -fPIE -pie "$ROOT/compat/x86_64/general_dynamic_constructor_exit_consumer.c" \
    -Wl,--no-as-needed "$work/oracle/libgrowth0.so" "$work/oracle/libconstructor-exit.so" \
    -Wl,-rpath,"$work/oracle" -o "$work/oracle/initial-consumer"
cp "$work/initial-consumer" "$work/execution-root/initial-consumer"
candidate=0 oracle=0
timeout 20 chroot "$work/execution-root" /initial-consumer >"$work/initial-candidate.stdout" || candidate=$?
LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/initial-consumer" >"$work/initial-oracle.stdout" || oracle=$?
[ "$candidate" -eq 23 ] && [ "$oracle" -eq 23 ]
cmp "$work/expected.stdout" "$work/initial-oracle.stdout"
cmp "$work/initial-oracle.stdout" "$work/initial-candidate.stdout"
printf 'general constructor exit: PASS (completed objects only); evidence: %s\n' "$work"
