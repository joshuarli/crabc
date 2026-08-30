#!/usr/bin/env bash
# Native Linux/x86-64 evidence launcher for the bounded CRT static-PIE slice.
# It deliberately exposes no generic x86 build, shell, sysroot, libc, or ldso
# command surface.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PLATFORM="linux/amd64"
readonly IMAGE="crabc-crt-static-pie-evidence:x86_64"
readonly DOCKERFILE="$ROOT_DIR/crt/Dockerfile.x86_64"

usage() {
    cat <<'EOF'
Usage: ./crt/run-x86_64.sh <command>

Native Linux/x86-64 bounded CRT evidence commands:
  image
  static-pie
  static-pie-bundle

The launcher refuses emulation and does not provide an x86 crabc runtime,
libc, dynamic linker, sysroot, generic cargo, or shell command.
EOF
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

require_native_x86_64_host() {
    if [ "$(uname -s)" != "Linux" ]; then
        fail "native x86-64 CRT evidence requires a Linux host (host: $(uname -s))"
    fi
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "native x86-64 CRT evidence refuses emulation (host: $(uname -m))" ;;
    esac
}

build_image() {
    docker build \
        --platform "$PLATFORM" \
        --tag "$IMAGE" \
        --file "$DOCKERFILE" \
        "$ROOT_DIR"
}

ensure_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        build_image
    fi
    local identity
    identity="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")"
    if [ "$identity" != "linux/amd64" ]; then
        fail "$IMAGE is $identity; rebuild it with ./crt/run-x86_64.sh image"
    fi
}

run_static_pie() {
    docker run --rm --init --read-only \
        --platform "$PLATFORM" \
        --workdir /workspace \
        --env CRABC_CRT_X86_64_EVIDENCE=native \
        --env CRABC_EXECUTION_MODE=native \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --tmpfs /tmp:rw,exec,nosuid,size=256m \
        --volume "$ROOT_DIR:/workspace:ro" \
        "$IMAGE" \
        python3 crt/tests/test_x86_64_static_pie.py
}

run_static_pie_bundle() {
    docker run --rm --init --read-only \
        --platform "$PLATFORM" \
        --workdir /workspace \
        --env CRABC_CRT_X86_64_EVIDENCE=native \
        --env CRABC_CRT_X86_64_EVIDENCE_SLICE=bundle \
        --env CRABC_EXECUTION_MODE=native \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --tmpfs /tmp:rw,exec,nosuid,size=256m \
        --volume "$ROOT_DIR:/workspace:ro" \
        "$IMAGE" \
        python3 crt/tests/test_x86_64_static_pie.py
}

if [ "$#" -ne 1 ]; then
    usage >&2
    exit 2
fi

case "$1" in
    --help|-h)
        usage
        exit 0
        ;;
    image|static-pie|static-pie-bundle)
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

require_native_x86_64_host

case "$1" in
    image)
        build_image
        ;;
    static-pie)
        ensure_image
        run_static_pie
        ;;
    static-pie-bundle)
        ensure_image
        run_static_pie_bundle
        ;;
esac
