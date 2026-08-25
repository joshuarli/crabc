#!/usr/bin/env bash
# Private native Linux/x86-64 fixed-mimalloc evidence launcher.
#
# This is intentionally not a second `scripts/dev.sh`: its closed command set
# cannot build crabc libc, ldso, crabc-rs, a sysroot, or a public x86 runtime.
# It exists solely to run the allocator evidence named in the x86 ledger.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PLATFORM="linux/amd64"
readonly IMAGE="crabc-allocator-evidence:x86_64"
readonly TARGET_VOLUME="crabc-allocator-evidence-target-x86_64"
readonly CARGO_VOLUME="crabc-allocator-evidence-cargo-x86_64"
readonly DOCKERFILE="$ROOT_DIR/compat/allocator/Dockerfile.x86_64"

usage() {
    cat <<'EOF'
Usage: ./compat/allocator/run-x86_64.sh <command> [arguments]

Private native Linux/x86-64 mimalloc evidence commands:
  image
  allocator --quick
  allocator-tls | allocator-lifecycle | allocator-fault
  allocator-release-evidence | allocator-api-coverage
  allocator-header-modes | allocator-static-modes
  allocator-remote-free | allocator-direct-remote | allocator-mapped-reclaim
  allocator-unmapped-reabandon | allocator-on-demand | allocator-direct-on-demand
  allocator-regular-small
  allocator-medium-full-retire
  allocator-full-non-direct-small-force-collect-post-exit
  allocator-full-direct-small-force-collect-post-exit
  allocator-mapped-post-exit
  allocator-retired-prepass | allocator-aggregate-post-exit
  allocator-aggregate-still-live | allocator-aggregate-same-bin-still-live
  allocator-perf --smoke|--full [options]
  allocator-unit | allocator-core-unit

This launcher rejects emulation and does not provide x86 crabc runtime,
libc, ldso, crabc-rs, sysroot, generic cargo, or shell commands.
EOF
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

require_native_x86_64_host() {
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "native x86-64 allocator evidence refuses emulation (host: $(uname -m))" ;;
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
        fail "$IMAGE is $identity; rebuild it with ./compat/allocator/run-x86_64.sh image"
    fi
}

run_in_container() {
    docker run --rm --init \
        --platform "$PLATFORM" \
        --workdir /workspace \
        --env CARGO_HOME=/opt/cargo \
        --env CRABC_ALLOCATOR_EVIDENCE_ARCH=x86_64 \
        --env CRABC_EXECUTION_MODE=native \
        --env CRABC_HOST_ARCH=x86_64 \
        --env MUSL_REFERENCE_LIBDIR=/opt/musl-1.2.6/lib \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/opt/cargo" \
        "$IMAGE" "$@"
}

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi

command="$1"
shift

# Reject unsupported commands before probing the host or Docker. This makes
# the absence of a generic x86 development surface an observable boundary.
case "$command" in
    --help|-h)
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        usage
        exit 0
        ;;
    image|allocator|allocator-tls|allocator-lifecycle|allocator-fault|allocator-release-evidence|allocator-api-coverage|allocator-header-modes|allocator-static-modes|allocator-remote-free|allocator-direct-remote|allocator-mapped-reclaim|allocator-unmapped-reabandon|allocator-on-demand|allocator-direct-on-demand|allocator-regular-small|allocator-medium-full-retire|allocator-full-non-direct-small-force-collect-post-exit|allocator-full-direct-small-force-collect-post-exit|allocator-mapped-post-exit|allocator-retired-prepass|allocator-aggregate-post-exit|allocator-aggregate-still-live|allocator-aggregate-same-bin-still-live|allocator-perf|allocator-unit|allocator-core-unit)
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

require_native_x86_64_host

case "$command" in
    image)
        [ "$#" -eq 0 ] || fail "image takes no arguments"
        build_image
        ;;
    allocator)
        [ "$#" -eq 1 ] && [ "$1" = "--quick" ] || fail "allocator requires exactly --quick"
        ensure_image
        run_in_container python3 compat/allocator/run.py --quick
        ;;
    allocator-tls)
        [ "$#" -eq 0 ] || fail "allocator-tls takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/tls-codegen/run-x86_64.py
        ;;
    allocator-lifecycle)
        [ "$#" -eq 0 ] || fail "allocator-lifecycle takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_lifecycle_evidence.py
        ;;
    allocator-fault)
        [ "$#" -eq 0 ] || fail "allocator-fault takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_fault_evidence.py
        ;;
    allocator-release-evidence)
        [ "$#" -eq 0 ] || fail "allocator-release-evidence takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_release_evidence.py --offline
        ;;
    allocator-api-coverage)
        [ "$#" -eq 0 ] || fail "allocator-api-coverage takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_release_evidence.py --offline
        run_in_container python3 compat/allocator/x86_64_api_native_coverage.py
        ;;
    allocator-header-modes)
        [ "$#" -eq 0 ] || fail "allocator-header-modes takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_header_mode_evidence.py --offline
        ;;
    allocator-static-modes)
        [ "$#" -eq 0 ] || fail "allocator-static-modes takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_static_mode_evidence.py --offline
        ;;
    allocator-remote-free)
        [ "$#" -eq 0 ] || fail "allocator-remote-free takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_remote_free_evidence.py --offline
        ;;
    allocator-direct-remote)
        [ "$#" -eq 0 ] || fail "allocator-direct-remote takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_direct_remote_evidence.py --offline
        ;;
    allocator-mapped-reclaim)
        [ "$#" -eq 0 ] || fail "allocator-mapped-reclaim takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_mapped_reclaim_evidence.py --offline
        ;;
    allocator-unmapped-reabandon)
        [ "$#" -eq 0 ] || fail "allocator-unmapped-reabandon takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_unmapped_reabandon_evidence.py --offline
        ;;
    allocator-on-demand)
        [ "$#" -eq 0 ] || fail "allocator-on-demand takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_on_demand_evidence.py --offline
        ;;
    allocator-direct-on-demand)
        [ "$#" -eq 0 ] || fail "allocator-direct-on-demand takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_direct_on_demand_evidence.py --offline
        ;;
    allocator-regular-small)
        [ "$#" -eq 0 ] || fail "allocator-regular-small takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_regular_small_evidence.py --offline
        ;;
    allocator-medium-full-retire)
        [ "$#" -eq 0 ] || fail "allocator-medium-full-retire takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_medium_full_retire_evidence.py --offline
        ;;
    allocator-full-non-direct-small-force-collect-post-exit)
        [ "$#" -eq 0 ] || fail "allocator-full-non-direct-small-force-collect-post-exit takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_full_non_direct_small_force_collect_post_exit_evidence.py --offline
        ;;
    allocator-full-direct-small-force-collect-post-exit)
        [ "$#" -eq 0 ] || fail "allocator-full-direct-small-force-collect-post-exit takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_full_direct_small_force_collect_post_exit_evidence.py --offline
        ;;
    allocator-mapped-post-exit)
        [ "$#" -eq 0 ] || fail "allocator-mapped-post-exit takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_mapped_post_exit_evidence.py --offline
        ;;
    allocator-retired-prepass)
        [ "$#" -eq 0 ] || fail "allocator-retired-prepass takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_retired_prepass_evidence.py --offline
        ;;
    allocator-aggregate-post-exit)
        [ "$#" -eq 0 ] || fail "allocator-aggregate-post-exit takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_aggregate_post_exit_evidence.py --offline
        ;;
    allocator-aggregate-still-live)
        [ "$#" -eq 0 ] || fail "allocator-aggregate-still-live takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_aggregate_still_live_evidence.py --offline
        ;;
    allocator-aggregate-same-bin-still-live)
        [ "$#" -eq 0 ] || fail "allocator-aggregate-same-bin-still-live takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_aggregate_same_bin_still_live_evidence.py --offline
        ;;
    allocator-perf)
        [ "$#" -gt 0 ] || fail "allocator-perf requires --smoke or --full"
        ensure_image
        run_in_container python3 compat/allocator/perf_x86_64.py "$@"
        ;;
    allocator-unit)
        [ "$#" -eq 0 ] || fail "allocator-unit takes no arguments"
        ensure_image
        run_in_container cargo test --locked --target x86_64-unknown-linux-musl -p crabc-mimalloc --lib --no-default-features
        ;;
    allocator-core-unit)
        [ "$#" -eq 0 ] || fail "allocator-core-unit takes no arguments"
        ensure_image
        run_in_container cargo test --locked --target x86_64-unknown-linux-musl -p crabc-core --lib --no-default-features --features allocator-x86-evidence tests::thread_pointer_identity_is_stable_for_the_calling_thread -- --exact --test-threads=1
        ;;
esac
