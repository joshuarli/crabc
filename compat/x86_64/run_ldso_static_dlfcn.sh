#!/usr/bin/env bash
# Installed static product dlfcn surface against pinned musl 1.2.6 libc.a.
#
# Musl's static archive has no loader: its dlfcn entries are the stubs in
# src/ldso/{dlopen,__dlsym,dlerror,dladdr,dl_iterate_phdr}.c plus the global
# dlsym/dlclose/dlerror/dlinfo bodies. The candidate archive must publish the
# same seven symbols with musl's archive bindings (dlopen, dladdr and
# dl_iterate_phdr weak), produce the same stdout from one consumer as static
# ET_EXEC and static PIE, and let application definitions override the three
# weak entries exactly as musl does. Neither image may import a loader record.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [STATIC_SYSROOT]\n' "$0" >&2; exit 2; }
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('static dlfcn TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/ldso-static-dlfcn.XXXXXX")"
readonly work
chmod a+rx "$work"
if [ "$#" -eq 1 ]; then
    installed="$1"
else
    installed="$work/static"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$installed" >"$work/static-build.log"
fi
readonly installed
readonly driver="$installed/bin/crabc-cc"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
bash "$ROOT/compat/x86_64/run_musl_oracle.sh"
symbols=(dlopen dlsym dlclose dlerror dladdr dlinfo dl_iterate_phdr)
bindings() {
    local archive="$1" symbol
    nm -A "$archive" 2>/dev/null >"$work/nm.txt" || true
    for symbol in "${symbols[@]}"; do
        awk -v symbol="$symbol" '$NF == symbol && $(NF-1) != "U" { print symbol, $(NF-1) }' "$work/nm.txt" | sort -u
    done
}
bindings "$("$oracle_cc" -print-file-name=libc.a)" >"$work/oracle-bindings.txt"
bindings "$installed/usr/lib/libc.a" >"$work/candidate-bindings.txt"
[ "$(wc -l <"$work/oracle-bindings.txt")" -eq "${#symbols[@]}" ]
if ! cmp -s "$work/oracle-bindings.txt" "$work/candidate-bindings.txt"; then
    printf 'static dlfcn: FAIL archive bindings differ; evidence: %s\n' "$work" >&2
    diff -u "$work/oracle-bindings.txt" "$work/candidate-bindings.txt" >&2 || true
    exit 1
fi
contract="$ROOT/compat/x86_64/ldso_static_dlfcn_contract.c"
override="$ROOT/compat/x86_64/ldso_static_dlfcn_override.c"
"$oracle_cc" -static -fno-pie -no-pie -pthread "$contract" -o "$work/oracle-contract"
"$oracle_cc" -static -fno-pie -no-pie "$override" -o "$work/oracle-override"
timeout 20 env -i "$work/oracle-contract" >"$work/oracle-contract.stdout"
timeout 20 env -i "$work/oracle-override" >"$work/oracle-override.stdout"
for mode in static-et-exec static-pie; do
    "$driver" "--$mode" "$contract" -o "$work/$mode-contract"
    "$driver" "--$mode" "$override" -o "$work/$mode-override"
    for program in contract override; do
        status=0
        timeout 20 env -i "$work/$mode-$program" >"$work/$mode-$program.stdout" 2>"$work/$mode-$program.stderr" || status=$?
        if [ "$status" -ne 0 ] || ! cmp -s "$work/oracle-$program.stdout" "$work/$mode-$program.stdout"; then
            printf 'static dlfcn: FAIL %s %s status=%s; evidence: %s\n' "$mode" "$program" "$status" "$work" >&2
            diff -u "$work/oracle-$program.stdout" "$work/$mode-$program.stdout" >&2 || true
            exit 1
        fi
    done
done
grep -Fxq 'static dlfcn contract: complete' "$work/static-pie-contract.stdout"
# The closed static images import no loader record or other private symbol.
for image in "$work"/static-et-exec-contract "$work"/static-pie-contract; do
    ! readelf -lW "$image" | grep -F INTERP >/dev/null
    ! nm -u "$image" | grep -F __crabc_ >/dev/null
done
printf 'static dlfcn: PASS (musl differential, 7 archive bindings, ET_EXEC and static PIE, weak overrides); evidence: %s\n' "$work"
