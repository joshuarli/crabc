#!/usr/bin/env bash
# Capture the independent wordexp native tool/oracle input seal for supplied
# products.  It runs no wordexp cell; the POSIX native aggregate replays a
# separately produced wordexp report against this seal rather than trusting
# the report's own embedded expectation.
set -euo pipefail
readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 -B "$ROOT_DIR/compat/x86_64/owned_wordexp_evidence.py" capture-expected-inputs "$@"
