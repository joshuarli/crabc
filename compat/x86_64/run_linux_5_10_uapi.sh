#!/usr/bin/env bash
# Native Linux/x86-64 declared Linux 5.10 exported-UAPI input check.
#
# This verifies the separately installed, hash-pinned UAPI tree used by the
# candidate-header closure diagnostic.  It is intentionally not `/usr/include`
# and it is neither a libc oracle nor a source of crabc implementation code.
set -euo pipefail
export LC_ALL=C

readonly LINUX_UAPI_ROOT=/opt/linux-5.10-uapi
readonly LINUX_UAPI_INCLUDE="$LINUX_UAPI_ROOT/include"
readonly PROVENANCE_PATH="$LINUX_UAPI_ROOT/.crabc-linux-uapi"
readonly HEADER_HASHES_PATH="$LINUX_UAPI_ROOT/.crabc-linux-uapi.headers.sha256"
readonly LINUX_UAPI_VERSION=5.10
readonly LINUX_UAPI_SHA256=dcdf99e43e98330d925016985bfbc7b83c66d367b714b2de0cbbfcbf83d8ca43
readonly LINUX_UAPI_HEADER_COUNT=935
readonly LINUX_UAPI_HEADER_MANIFEST_SHA256=00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e

fail() {
    printf 'ERROR: pinned x86 Linux 5.10 UAPI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64
for tool in grep sed sha256sum tr wc; do
    require_tool "$tool"
done

for path in "$LINUX_UAPI_ROOT" "$LINUX_UAPI_INCLUDE" "$PROVENANCE_PATH" \
    "$HEADER_HASHES_PATH"; do
    [ ! -L "$path" ] || fail "declared UAPI path is a symlink: $path"
done
[ -d "$LINUX_UAPI_ROOT" ] || fail "missing declared UAPI root: $LINUX_UAPI_ROOT"
[ -d "$LINUX_UAPI_INCLUDE" ] || fail "missing declared UAPI include root: $LINUX_UAPI_INCLUDE"
[ -f "$PROVENANCE_PATH" ] || fail "missing UAPI provenance manifest: $PROVENANCE_PATH"
[ -f "$HEADER_HASHES_PATH" ] || fail "missing UAPI header hash manifest: $HEADER_HASHES_PATH"

provenance_line_count="$(wc -l < "$PROVENANCE_PATH" | tr -d '[:space:]')"
[ "$provenance_line_count" = 7 ] || fail "UAPI provenance manifest line count drifted"
for expected in \
    'format=crabc-linux-uapi-v1' \
    "version=${LINUX_UAPI_VERSION}" \
    "source_sha256=${LINUX_UAPI_SHA256}" \
    'architecture=x86_64' \
    'install_arch=x86' \
    "header_count=${LINUX_UAPI_HEADER_COUNT}" \
    "header_manifest_sha256=${LINUX_UAPI_HEADER_MANIFEST_SHA256}"; do
    grep -Fxq "$expected" "$PROVENANCE_PATH" ||
        fail "UAPI provenance manifest is missing: $expected"
done

observed_header_count="$(wc -l < "$HEADER_HASHES_PATH" | tr -d '[:space:]')"
[ "$observed_header_count" = "$LINUX_UAPI_HEADER_COUNT" ] ||
    fail "UAPI header hash manifest count drifted: expected $LINUX_UAPI_HEADER_COUNT, got $observed_header_count"
observed_header_manifest_sha256="$(sha256sum "$HEADER_HASHES_PATH" | sed 's/[[:space:]].*$//')"
[ "$observed_header_manifest_sha256" = "$LINUX_UAPI_HEADER_MANIFEST_SHA256" ] ||
    fail "UAPI header hash manifest digest drifted"

for header in linux/kd.h linux/soundcard.h linux/vt.h; do
    [ -f "$LINUX_UAPI_INCLUDE/$header" ] ||
        fail "declared Linux 5.10 UAPI tree lacks $header"
done
(
    cd "$LINUX_UAPI_INCLUDE"
    sha256sum -c "$HEADER_HASHES_PATH"
) >/dev/null || fail "declared Linux 5.10 UAPI header hashes drifted"

printf 'x86 pinned Linux %s UAPI input: PASS (%s exported headers)\n' \
    "$LINUX_UAPI_VERSION" "$LINUX_UAPI_HEADER_COUNT"
