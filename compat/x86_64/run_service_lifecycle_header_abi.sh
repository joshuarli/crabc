#!/usr/bin/env bash
# Pinned-musl/project C/C++ <netdb.h> service lifecycle declaration proof.
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_ROOT=/opt/musl-1.2.6
fail() { printf 'ERROR: x86 service lifecycle headers: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] && case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64";; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
command -v nm >/dev/null || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-x86-64-service-lifecycle-header.XXXXXX)"; trap 'rm -rf -- "$work_dir"' EXIT
for tree in musl project; do
  include="$MUSL_ROOT/include"; [ "$tree" = project ] && include="$ROOT_DIR/include"
  for profile in strict posix xopen gnu bsd; do
    defs=(-D__STRICT_ANSI__); case "$profile" in posix) defs=(-D_POSIX_C_SOURCE=200809L);; xopen) defs=(-D_XOPEN_SOURCE=700);; gnu) defs=(-D_GNU_SOURCE);; bsd) defs=(-D_BSD_SOURCE);; esac
    "$ORACLE_CC" -nostdinc -I "$include" -std=c11 -U_GNU_SOURCE -U_POSIX_C_SOURCE -U_XOPEN_SOURCE "${defs[@]}" -Werror=implicit-function-declaration -fsyntax-only "$ROOT_DIR/compat/x86_64/service_lifecycle_header_abi_probe.c" || fail "$tree C $profile declaration"
    object="$work_dir/$tree-$profile.o"
    "$ORACLE_CC" -nostdinc -nostdinc++ -I "$include" -std=c++17 -x c++ -U_GNU_SOURCE -U_POSIX_C_SOURCE -U_XOPEN_SOURCE "${defs[@]}" -c "$ROOT_DIR/compat/x86_64/service_lifecycle_header_abi_probe.cpp" -o "$object" || fail "$tree C++ $profile declaration"
    undefined="$(nm --undefined-only "$object")"
    for symbol in getservent setservent; do printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" || fail "$tree C++ $profile lacks C linkage for $symbol"; done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(getservent|setservent)'; then fail "$tree C++ $profile retained mangled linkage"; fi
  done
done
printf 'x86 pinned-musl/project C/C++ <netdb.h> service lifecycle ABI: PASS\n'
