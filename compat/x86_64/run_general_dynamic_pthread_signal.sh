#!/usr/bin/env bash
# Legacy dynamic-qualification launcher.
#
# `owned_dynamic_qualification.CASES` retains this one-argument name.  The
# canonical runner owns the installed-header object, product receipts and raw
# observations so direct callers use one evidence contract as well.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
exec "$ROOT/compat/x86_64/run_owned_pthread_signal.sh" "$1"
