#!/usr/bin/env bash
# Legacy host-architecture convenience check. It does not reproduce the
# pinned Docker-first Linux/AArch64 evidence environment; use scripts/dev.sh
# for authoritative development and compatibility results.
set -euo pipefail

RUNNER="${CI_RUNNER:-podman}"
if ! command -v "$RUNNER" >/dev/null 2>&1; then
    RUNNER=docker
fi

exec "$RUNNER" run --rm -v "$(pwd):/workspace" -w /workspace "${CI_IMAGE:-ubuntu:24.04}" bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl musl-tools ca-certificates
    curl --proto '"'"'=https'"'"' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly --profile minimal
    . "$HOME/.cargo/env"
    cargo build --workspace
    cargo test --workspace
'
