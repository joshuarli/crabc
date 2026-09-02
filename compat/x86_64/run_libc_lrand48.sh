#!/usr/bin/env bash
# Pinned-musl/x86 true-static legacy rand48 provider evidence.
set -euo pipefail
export LC_ALL=C
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; oracle=/usr/local/bin/crabc-x86_64-musl-gcc
fail(){ printf 'ERROR: x86 lrand48: %s\n' "$*" >&2; exit 1; }
[ "$(uname -m)" = x86_64 ] || fail "requires native x86_64"; [ -x "$oracle" ] || fail "missing pinned musl compiler"
for x in ar awk cargo comm grep nm objcopy objdump readelf sort; do command -v "$x" >/dev/null || fail "missing $x"; done
work="$(mktemp -d /tmp/crabc-x86-lrand48.XXXXXX)"; trap 'rm -rf -- "$work"' EXIT
# The standalone header is unconditional; the shared stdlib matrix separately
# keeps its X/Open/GNU/BSD gate. Compare project and exact pinned-musl headers
# in C and C++: every C++ undefined reference must keep the unmangled C name.
symbols=(drand48 erand48 jrand48 lcong48 lrand48 mrand48 nrand48 seed48 srand48)
for header_root in "$root/include" /opt/musl-1.2.6/include; do
 label="$(basename "$header_root")"
 header_flags=()
 [ "$header_root" = /opt/musl-1.2.6/include ] && header_flags=(-DCRABC_LRAND48_MUSL_STDLIB)
 for cc in "$oracle" /usr/bin/gcc; do
  compiler="$(basename "$cc")"
  "$cc" -std=c11 "${header_flags[@]}" -I"$header_root" -fsyntax-only "$root/compat/x86_64/lrand48_header_abi_probe.c"
  object="$work/header.$label.$compiler.o"
  "$cc" -x c++ -std=c++17 "${header_flags[@]}" -I"$header_root" -c "$root/compat/x86_64/lrand48_header_abi_probe.cpp" -o "$object"
  for s in "${symbols[@]}"; do
   nm -u "$object" | grep -Eq "[[:space:]]$s$" || fail "$label C++ linkage lost $s"
  done
  nm -u "$object" | grep -Eq '[[:space:]]_Z' && fail "$label C++ linkage is mangled"
 done
done
"$oracle" -std=c11 -I"$root/include" "$root/compat/x86_64/libc_lrand48_probe.c" -o "$work/reference"; "$work/reference" || { status=$?; fail "pinned-musl differential failed at probe $status"; }
target="$work/target"; CARGO_TARGET_DIR="$target" cargo rustc --locked -p crabc-libc --lib --target x86_64-unknown-linux-musl -- -C relocation-model=static -C panic=abort
archive="$target/x86_64-unknown-linux-musl/debug/libc.a"; [ -f "$archive" ] || fail "missing archive"
for s in "${symbols[@]}"; do grep -Fqx "$s" "$root/compat/x86_64/static_c_abi_exports.txt" || fail "export list omits $s"; done
mapfile -t owner < <(nm -A --defined-only "$archive" | awk '$NF=="lrand48" {x=$1;sub(/^.*\.a:/,"",x);sub(/:.*$/,"",x);print x}' | sort -u); [ "${#owner[@]}" = 1 ] || fail "lrand48 needs one owner"
mkdir "$work/o"; (cd "$work/o"; ar x "$archive" "${owner[0]}"; mv "${owner[0]}" provider.o; ar rcs "$work/provider.a" provider.o)
for s in "${symbols[@]}"; do nm -g --defined-only "$work/o/provider.o" | grep -Eq "[[:space:]]$s$" || fail "provider omits $s"; done
# Rust's private mutable-state symbols stay compiler-mangled; only unmangled
# names cross this C ABI boundary, where the exact closure is the nine APIs.
unexpected_exports="$(comm -23 <(nm -g --defined-only "$work/o/provider.o" | awk '$NF !~ /^_R/ {print $NF}' | sort -u) <(printf '%s\n' "${symbols[@]}" | sort))"; [ -z "$unexpected_exports" ] || fail "provider has non-rand48 C ABI export: $unexpected_exports"
undefined="$(nm -u "$work/o/provider.o")"; [ -z "$undefined" ] || fail "provider has undefined dependency: $undefined"
objdump -d "$work/o/provider.o" >"$work/dis"; grep -Eq '[[:space:]]syscall([[:space:]]|$)|__errno_location|memcpy|memmove|memset' "$work/dis" && fail "provider widened into runtime helper"
"$oracle" -std=c11 -DCRABC_LRAND48_FREESTANDING -I"$root/include" -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined "$root/compat/x86_64/libc_lrand48_probe.c" "$root/compat/x86_64/libc_lrand48_start.S" "$work/provider.a" -o "$work/candidate"
readelf -l "$work/candidate" | grep -Eq '[[:space:]]TLS[[:space:]]' && fail "candidate has TLS"; readelf -d "$work/candidate" 2>/dev/null | grep -Eq 'NEEDED|INTERP' && fail "candidate has dynamic dependency" || true
"$work/candidate" || fail "static differential failed"
printf 'x86 static libc lrand48: PASS\n'
