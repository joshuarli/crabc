#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = aarch64 ] && [ "$#" -eq 1 ]
archive="$(realpath -e "$1")"
cc=/usr/local/bin/crabc-aarch64-musl-gcc
mkdir -p "$root/.work/aarch64/tmp"
work="$(mktemp -d "$root/.work/aarch64/tmp/compiler-helper-regression.XXXXXX")"
probe="$root/builtins/fixtures/x86_64_compiler_helper_aggregate_probe.c"
"$cc" -std=c11 -O2 -fno-builtin -Wno-builtin-declaration-mismatch -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-unwind-tables -ffreestanding -fno-pic -fno-pie \
    -DCRABC_BUILTINS_FREESTANDING -c "$probe" -o "$work/candidate.o"
"$cc" -c "$root/builtins/fixtures/aarch64_compiler_helper_aggregate_start.S" -o "$work/start.o"
nm -u "$work/candidate.o" | awk '{print $NF}' | LC_ALL=C sort -u > "$work/imports"
cmp "$root/builtins/fixtures/aarch64_compiler_helper_imports.txt" "$work/imports"
for symbol in __divdc3 __divsc3 __divtc3 __mulsc3 __popcountdi2; do
    grep -Fxq "$symbol" "$work/imports"
done
if "$cc" -nostdlib -static -no-pie -Wl,--no-undefined -Wl,-e,_start \
    "$work/start.o" "$work/candidate.o" -o "$work/without" >"$work/without.stdout" 2>"$work/without.stderr"; then
    printf 'archive-free helper link unexpectedly succeeded\n' >&2
    exit 1
fi
"$cc" -nostdlib -static -no-pie -Wl,--no-undefined -Wl,-e,_start -Wl,--trace \
    "$work/start.o" "$work/candidate.o" "$archive" -o "$work/candidate" >"$work/link.trace"
if grep -Eq 'libgcc|compiler-rt|libc\.a|/[Sr]?crt[^/[:space:]]*\.o' "$work/link.trace"; then
    printf 'candidate linked an ambient runtime\n' >&2
    exit 1
fi
readelf -hW "$work/candidate" >"$work/header"
readelf -lW "$work/candidate" >"$work/segments"
readelf -dW "$work/candidate" >"$work/dynamic"
grep -Eq 'Machine:[[:space:]]+AArch64' "$work/header"
grep -Eq 'Type:[[:space:]]+EXEC' "$work/header"
if grep -Eq 'INTERP|[[:space:]]TLS[[:space:]]' "$work/segments" ||
    grep -Eq '\((NEEDED|JMPREL|PLTGOT)\)' "$work/dynamic"; then
    printf 'candidate has dynamic or TLS state\n' >&2
    exit 1
fi
nm --undefined-only "$work/candidate" >"$work/undefined"
if awk '$NF != "_PROCEDURE_LINKAGE_TABLE_" && $NF != "__rela_iplt_start" && $NF != "__rela_iplt_end" { found=1 } END { exit !found }' "$work/undefined"; then
    printf 'candidate retains unresolved symbols\n' >&2
    exit 1
fi
"$cc" -std=c11 -O2 -fno-stack-protector -fno-pie -DCRABC_HELPER_REFERENCE \
    -c "$probe" -o "$work/reference.o"
"$cc" -no-pie "$work/reference.o" -o "$work/reference"
"$work/reference" >"$work/reference.stdout"
"$work/candidate" >"$work/candidate.stdout"
printf 'compiler-helper-aggregate-ok\n' >"$work/expected.stdout"
cmp "$work/expected.stdout" "$work/reference.stdout"
cmp "$work/reference.stdout" "$work/candidate.stdout"
printf 'arm64 compiler helpers: PASS (%s)\n' "$work"
