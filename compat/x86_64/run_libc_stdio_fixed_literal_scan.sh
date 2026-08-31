#!/usr/bin/env bash
# Run the sealed x86 static raw-literal scanf profile.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-literal-scan
exec bash "$ROOT_DIR/compat/x86_64/run_libc_stdio_format_scan.sh"
