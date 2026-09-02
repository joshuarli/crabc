#!/usr/bin/env bash
# Native Linux/x86-64 source-closed static musl service lifecycle evidence.
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
fail() { printf 'ERROR: x86 static libc service lifecycle: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] && case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64";; esac
for tool in ar cargo grep mkdir mktemp nm objdump readelf; do command -v "$tool" >/dev/null || fail "requires $tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_service_lifecycle_header_abi.sh" >/dev/null
for symbol in getservent setservent; do grep -Eq "^${symbol}[[:space:]]+serv\\.lo[[:space:]]+T[[:space:]]+GLOBAL" "$ABI" || fail "AArch64 musl ABI lost $symbol ownership"; done
work_dir="$(mktemp -d /tmp/crabc-x86-64-service-lifecycle.XXXXXX)"; trap 'rm -rf -- "$work_dir"' EXIT
target="$work_dir/target"; archive="$target/x86_64-unknown-linux-musl/debug/libc.a"; reference="$work_dir/reference"; candidate="$work_dir/candidate"; members="$work_dir/members"; mkdir "$members"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"; [ -f "$musl_archive" ] || fail "missing pinned musl archive"
ar p "$musl_archive" serv.lo >"$work_dir/musl-serv.o"
readelf --symbols --wide "$work_dir/musl-serv.o" >"$work_dir/musl-symbols"
grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+serv\.c$' "$work_dir/musl-symbols" || fail "pinned musl object lost serv.c mapping"
for symbol in getservent setservent; do
  grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT.*[[:space:]]${symbol}$" "$work_dir/musl-symbols" || fail "pinned musl serv object lacks $symbol"
  objdump -dr --disassemble="$symbol" "$work_dir/musl-serv.o" | grep -Eq '[[:space:]]ret([[:space:]]|$)' || fail "pinned musl $symbol is not a direct leaf"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" "$ROOT_DIR/compat/x86_64/libc_service_lifecycle_probe.c" -o "$reference"
env -i LC_ALL=C TZ=UTC "$reference" || fail "pinned-musl lifecycle fixture failed"
CARGO_TARGET_DIR="$target" cargo rustc --locked -p crabc-libc --lib --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit static archive"
(cd "$members" && ar x "$archive" $(ar t "$archive" | grep -E '^c\\..+\\.rcgu\\.o$'))
mapfile -t selected < <(for obj in "$members"/*; do names="$(nm -g --defined-only "$obj")"; if printf '%s\n' "$names" | grep -Eq '[[:space:]]T[[:space:]]getservent$'; then printf '%s\n' "$obj"; fi; done)
[ "${#selected[@]}" = 1 ] || fail "getservent must have one provider object"
provider="${selected[0]}"; definitions="$(nm -g --defined-only "$provider")"
for symbol in getservent setservent; do printf '%s\n' "$definitions" | grep -Eq "[[:space:]]T[[:space:]]${symbol}$" || fail "provider lacks $symbol"; done
if printf '%s\n' "$definitions" | grep -Eq '[[:space:]](endservent|getservbyname|getservbyport|getprotoent|res_query|getaddrinfo|malloc|free)$'; then fail "provider leaks unselected service/resolver sibling"; fi
"$ORACLE_CC" -std=c11 -DCRABC_SERVICE_LIFECYCLE_FREESTANDING -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--gc-sections -Wl,--no-undefined "$ROOT_DIR/compat/x86_64/libc_service_lifecycle_probe.c" "$ROOT_DIR/compat/x86_64/libc_service_lifecycle_start.S" "$provider" -o "$candidate"
readelf --symbols --wide "$candidate" >"$work_dir/symbols"; readelf --program-headers --wide "$candidate" >"$work_dir/headers"; readelf --dynamic --wide "$candidate" >"$work_dir/dynamic" || true; objdump -d "$candidate" >"$work_dir/disassembly"
if awk '$7 == "UND" && NF >= 8 {print}' "$work_dir/symbols" | grep -q . || grep -Eq 'INTERP|NEEDED|[[:space:]]TLS[[:space:]]|__errno_location|__h_errno_location|%fs:|crabc_core|mimalloc' "$work_dir/symbols" "$work_dir/headers" "$work_dir/dynamic" "$work_dir/disassembly"; then fail "candidate is not source-closed static provider"; fi
for symbol in getservent setservent; do objdump -d --disassemble="$symbol" "$candidate" | grep -Eq '[[:space:]]ret([[:space:]]|$)' || fail "$symbol lacks direct return"; done
if objdump -d --disassemble=getservent "$candidate" | grep -Eq '\b(call|syscall)\b'; then fail "getservent unexpectedly calls"; fi
env -i LC_ALL=C TZ=UTC "$candidate" || fail "candidate lifecycle fixture failed"
printf 'x86 static crabc-libc service lifecycle: PASS\n'
