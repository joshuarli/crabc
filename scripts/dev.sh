#!/usr/bin/env bash
# Native Alpine/AArch64 development entry point.
#
# The image contains a pinned musl reference and Rust toolchain. The source
# tree and target directory remain outside the image so normal edit/build loops
# do not rebuild it.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PLATFORM="linux/arm64"
readonly IMAGE="${CRABC_DEV_IMAGE:-crabc-dev:aarch64}"
readonly TARGET_VOLUME="${CRABC_TARGET_VOLUME:-crabc-target-aarch64}"
readonly CARGO_VOLUME="${CRABC_CARGO_VOLUME:-crabc-cargo-aarch64}"

usage() {
    cat <<'EOF'
Usage: ./scripts/dev.sh <command> [arguments]

Commands:
  image               build the pinned Linux/AArch64 development image
  build [cargo args]  cargo build --workspace
  test [cargo args]   cargo test --workspace
  symbols             compare libc.so exports with pinned musl 1.2.6
  compat              refresh symbol evidence and enforce its regression ratchet
  ratchet             alias for compat
  libc-test [subset]  run the pinned libc-test checkout (functional by default)
  differential [case] run a pinned musl-vs-crabc workload comparison
  loader-inventory   generate/check pinned musl and crabc loader reports
  dashboard           generate COMPATIBILITY.md from current structured reports
  environment         write reproducibility metadata for compatibility reports
  shell               open a shell in the development image

The image and containers are always requested as linux/arm64. `target/` and
the Cargo download cache use Docker volumes so the macOS host does not need a
Rust installation.
EOF
}

build_image() {
    docker build \
        --platform "$PLATFORM" \
        --tag "$IMAGE" \
        --file "$ROOT_DIR/docker/Dockerfile" \
        "$ROOT_DIR"
}

ensure_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        build_image
    fi

    local architecture
    architecture="$(docker image inspect --format '{{.Architecture}}' "$IMAGE")"
    if [ "$architecture" != "arm64" ]; then
        printf 'ERROR: %s is %s; rebuild it for linux/arm64 with ./scripts/dev.sh image\n' \
            "$IMAGE" "$architecture" >&2
        exit 1
    fi
}

run_in_container() {
    docker run --rm --init \
        --platform "$PLATFORM" \
        --workdir /workspace \
        --env CARGO_HOME=/opt/cargo \
        --env LIBC_TEST_DIR=/opt/libc-test \
        --env MUSL_REFERENCE_LIBDIR=/opt/musl-1.2.6/lib \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/opt/cargo" \
        "$IMAGE" "$@"
}

collect_symbol_report() {
    run_in_container cargo build --workspace
    run_in_container python3 scripts/collect_environment.py
    run_in_container python3 scripts/check_symbols.py
}

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi

command="$1"
shift

case "$command" in
    image)
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        build_image
        ;;
    build)
        ensure_image
        run_in_container cargo build --workspace "$@"
        ;;
    test)
        ensure_image
        # Integration tests execute target/debug/lib{c,ldso}.so directly, so
        # build their runtime artifacts before compiling the test harness.
        run_in_container cargo build --workspace
        run_in_container cargo test --workspace "$@"
        ;;
    symbols)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        collect_symbol_report
        ;;
    compat|ratchet)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        # Full parity is intentionally still red. Preserve its report while
        # letting the ratchet prove that the known ABI frontier did not recede.
        if collect_symbol_report; then
            :
        else
            symbol_status=$?
            printf 'symbol parity remains incomplete (exit %s); checking for regressions\n' \
                "$symbol_status"
        fi
        run_in_container python3 scripts/check_compat_ratchet.py check
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    libc-test)
        ensure_image
        # The Python runner deliberately reuses existing artifacts when they
        # exist. Build here so a harness invocation always measures the
        # checked-out source rather than an earlier compatibility run.
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 libc-test-harness/runner.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    differential)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/differential/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    loader-inventory)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        run_in_container cargo build --workspace
        run_in_container python3 compat/scripts/generate-aarch64-loader-inventory.py
        run_in_container python3 compat/scripts/generate-aarch64-loader-inventory.py --check
        ;;
    dashboard)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    environment)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        run_in_container python3 scripts/collect_environment.py
        ;;
    shell)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        run_in_container -it bash
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        printf 'ERROR: unknown command: %s\n\n' "$command" >&2
        usage >&2
        exit 2
        ;;
esac
