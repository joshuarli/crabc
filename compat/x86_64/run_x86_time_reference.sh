#!/usr/bin/env bash
# Pinned-musl Linux/x86-64 timespec ABI reference check.
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
[ "$(uname -s)" = Linux ] || { echo 'ERROR: x86 time reference requires native Linux' >&2; exit 1; }
case "$(uname -m)" in x86_64|amd64) ;; *) echo "ERROR: refuses emulation on $(uname -m)" >&2; exit 1 ;; esac
[ -x "$ORACLE_CC" ] || { echo 'ERROR: missing pinned musl oracle compiler' >&2; exit 1; }
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
"$ORACLE_CC" -std=c11 -fsyntax-only "$ROOT_DIR/compat/x86_64/x86_time_reference_probe.c"
printf 'x86 pinned-musl timespec ABI reference: PASS\n'
