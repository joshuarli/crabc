#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
eval "$(python3 -B "$ROOT/compat/x86_64/native_arch.py")"
work="$(mktemp -d "$TMPDIR/mimalloc-secure-environment.XXXXXX")"
printf 'mimalloc secure environment evidence: %s\n' "$work"
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow --output "$work/static-product" >"$work/static-build.json"
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow --output "$work/dynamic-product" >"$work/dynamic-build.json"
cc -O2 "$ROOT/compat/x86_64/mimalloc_secure_environment_start.c" -o "$work/start"
"$oracle" -static -fno-builtin "$ROOT/compat/x86_64/mimalloc_secure_environment_probe.c" -o "$work/oracle"
"$work/dynamic-product/bin/crabc-cc-dynamic" --dynamic-pie -fno-builtin -c "$ROOT/compat/x86_64/mimalloc_secure_environment_probe.c" -o "$work/probe.o"
(cd "$work" && "$work/static-product/bin/crabc-cc" -static --link-receipt static-link.json probe.o -o static)
"$work/dynamic-product/bin/crabc-cc-dynamic" --dynamic-pie "$work/probe.o" -o "$work/dynamic"
result=0
for mode in oracle static dynamic; do
    root="$work/$mode-root"
    mkdir -p "$root/work" "$root/lib" "$root/usr/lib"
    cp "$work/$mode" "$root/work/probe"
    if [ "$mode" = dynamic ]; then
        cp "$work/dynamic-product/lib/ld-crabc-${arch}.so.1" "$root/lib/"
        cp "$work/dynamic-product/usr/lib/libc.so" "$root/usr/lib/"
    fi
    for security in secure normal; do
        status=0
        if [ "$security" = secure ]; then
            env -i MIMALLOC_VERBOSE=1 MIMALLOC_SHOW_STATS=1 MIMALLOC_SHOW_ERRORS=1 "$work/start" "$root" secure >"$work/$mode-$security.stdout" 2>"$work/$mode-$security.stderr" || status=$?
        else
            env -i MIMALLOC_VERBOSE=1 MIMALLOC_SHOW_STATS=1 MIMALLOC_SHOW_ERRORS=1 chroot "$root" /work/probe >"$work/$mode-$security.stdout" 2>"$work/$mode-$security.stderr" || status=$?
        fi
        bytes=$(wc -c <"$work/$mode-$security.stderr")
        printf '%s %s: exit=%s stderr_bytes=%s\n' "$mode" "$security" "$status" "$bytes"
        if [ "$status" -ne 0 ] || [ -s "$work/$mode-$security.stdout" ]; then result=1; fi
        if [ "$security" = secure ] || [ "$mode" = oracle ]; then
            if [ "$bytes" -ne 0 ]; then result=1; fi
        elif [ "$bytes" -eq 0 ] || ! rg -q 'mimalloc:' "$work/$mode-$security.stderr"; then
            result=1
        fi
    done
done
if [ "$result" -eq 0 ]; then echo 'mimalloc secure environment: PASS'; else echo 'mimalloc secure environment: FAIL' >&2; fi
exit "$result"
