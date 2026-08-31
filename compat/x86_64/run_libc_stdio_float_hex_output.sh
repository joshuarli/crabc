#!/usr/bin/env bash
# Focused pinned-musl/static-candidate binary64 hexadecimal printf evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export CRABC_STDIO_FORMAT_SCAN_PROFILE=float-hex-output
exec bash "$ROOT_DIR/compat/x86_64/run_libc_stdio_format_scan.sh"
