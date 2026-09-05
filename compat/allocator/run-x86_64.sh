#!/usr/bin/env bash
# Private native Linux/x86-64 fixed-mimalloc evidence launcher.
#
# This is intentionally not a second `scripts/dev.sh`: its closed command set
# cannot build crabc libc, ldso, crabc-rs, a sysroot, or a public x86 runtime.
# It exists solely to run the allocator evidence named in the x86 ledger.
set -euo pipefail

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PLATFORM="linux/amd64"
readonly IMAGE="crabc-allocator-evidence:x86_64"
readonly DOCKERFILE="$ROOT_DIR/compat/allocator/Dockerfile.x86_64"
readonly WORK_BOUNDARY="$ROOT_DIR/.work/allocator-x86_64"

usage() {
    cat <<'EOF'
Usage: ./compat/allocator/run-x86_64.sh <command> [arguments]

Mutable evidence, Cargo state, sources, and scratch stay under
.work/allocator-x86_64. CRABC_ALLOCATOR_X86_64_WORK_DIR may select a physical
descendant of that directory; external paths and named volumes are rejected.

Private native Linux/x86-64 mimalloc evidence commands:
  image
  allocator --quick
  allocator-m1
  allocator-m2
  allocator-tls | allocator-lifecycle | allocator-init-recursion | allocator-fault
  allocator-release-evidence | allocator-api-coverage | allocator-cmake-modes
  allocator-header-modes | allocator-static-modes
  allocator-remote-free | allocator-live-owner-full-medium-remote-release | allocator-live-owner-full-medium-one-remote-unfull-reuse | allocator-direct-remote | allocator-mapped-reclaim | allocator-mapped-adoption
  allocator-direct-small-allocation-adoption
  allocator-unmapped-reabandon | allocator-on-demand | allocator-direct-on-demand
  allocator-aligned-overalloc-realloc
  allocator-regular-small
  allocator-direct-small-full-retire
  allocator-medium-full-retire
  allocator-full-non-direct-small-force-collect-post-exit
  allocator-full-direct-small-force-collect-post-exit
  allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped
  allocator-dynamic-full-direct-small-unmapped-reabandon
  allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped
  allocator-dynamic-full-non-direct-small-unmapped-reabandon
  allocator-dynamic-full-medium-one-remote-force-collect-to-mapped
  allocator-dynamic-full-medium-unmapped-reabandon
  allocator-dynamic-full-large-one-remote-force-collect-to-mapped
  allocator-dynamic-full-large-unmapped-reabandon
  allocator-dynamic-full-large-homogeneous-aggregate
  allocator-dynamic-full-medium-homogeneous-aggregate
  allocator-dynamic-full-singleton-homogeneous-aggregate
  allocator-dynamic-full-non-direct-small-homogeneous-aggregate
  allocator-later-thread-exit-full-direct-small-pages
  allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate
  allocator-automatic-pthread-destructor
  allocator-cancellation-pthread-destructor
  allocator-dynamic-os-aligned-singleton
  allocator-dynamic-arena-singleton-post-exit
  allocator-mapped-post-exit
  allocator-retired-prepass | allocator-aggregate-post-exit
  allocator-aggregate-still-live | allocator-aggregate-same-bin-still-live
  allocator-perf --smoke|--full [options]
  allocator-huge-registry | allocator-huge-reservation
  allocator-unit | allocator-core-unit

This launcher rejects emulation and does not provide x86 crabc runtime,
libc, ldso, crabc-rs, sysroot, generic cargo, or shell commands.
EOF
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

normalize_absolute_path() {
    local path="${1#/}"
    local component
    local last_index
    local normalized=""
    local -a components=()

    while [ -n "$path" ]; do
        if [[ "$path" == */* ]]; then
            component="${path%%/*}"
            path="${path#*/}"
        else
            component="$path"
            path=""
        fi
        case "$component" in
            ""|.)
                ;;
            ..)
                if [ "${#components[@]}" -gt 0 ]; then
                    last_index=$((${#components[@]} - 1))
                    unset "components[$last_index]"
                fi
                ;;
            *)
                components+=("$component")
                ;;
        esac
    done

    for component in "${components[@]}"; do
        normalized="$normalized/$component"
    done
    printf '%s\n' "${normalized:-/}"
}

resolve_existing_directory() {
    local candidate="$1"
    local existing="$candidate"
    local missing_component
    local missing_suffix=""
    local physical_existing

    # Resolve every existing prefix physically before making the missing tail.
    # This catches a symlink below .work before `mkdir -p` could follow it.
    while [ ! -e "$existing" ] && [ ! -L "$existing" ]; do
        missing_component="${existing##*/}"
        missing_suffix="/$missing_component$missing_suffix"
        existing="${existing%/*}"
        if [ -z "$existing" ]; then
            existing="/"
        fi
    done
    if ! physical_existing="$(cd -P "$existing" 2>/dev/null && pwd)"; then
        return 1
    fi
    if [ -z "$missing_suffix" ]; then
        printf '%s\n' "$physical_existing"
    elif [ "$physical_existing" = "/" ]; then
        printf '%s\n' "$missing_suffix"
    else
        printf '%s%s\n' "$physical_existing" "$missing_suffix"
    fi
}

path_is_within_work_boundary() {
    [ "$1" = "$WORK_BOUNDARY" ] || [[ "$1" == "$WORK_BOUNDARY/"* ]]
}

configuration_error() {
    printf 'ERROR: %s\n' "$*" >&2
    return 1
}

resolve_bounded_directory() {
    local name="$1"
    local configured_path="$2"
    local relative_base="$3"
    local candidate
    local resolved

    if [[ "/$configured_path/" == */../* ]]; then
        configuration_error "$name must not contain '..' path components: $configured_path"
        return 1
    fi
    if [[ "$configured_path" == *:* ]]; then
        configuration_error "$name must be a host directory path, not Docker mount syntax: $configured_path"
        return 1
    fi
    if [[ "$configured_path" = /* ]]; then
        candidate="$configured_path"
    else
        candidate="$relative_base/$configured_path"
    fi
    candidate="$(normalize_absolute_path "$candidate")"
    if ! resolved="$(resolve_existing_directory "$candidate")"; then
        configuration_error "$name must name a directory: $candidate"
        return 1
    fi
    if ! path_is_within_work_boundary "$resolved"; then
        configuration_error "$name must resolve below $WORK_BOUNDARY: $resolved"
        return 1
    fi
    printf '%s\n' "$resolved"
}

configure_work_dir() {
    local physical_boundary
    local directory
    if ! physical_boundary="$(resolve_existing_directory "$WORK_BOUNDARY")" ||
        [ "$physical_boundary" != "$WORK_BOUNDARY" ]; then
        fail "allocator work boundary must be a physical checkout directory"
    fi
    WORK_DIR="$(resolve_bounded_directory CRABC_ALLOCATOR_X86_64_WORK_DIR \
        "${CRABC_ALLOCATOR_X86_64_WORK_DIR:-$WORK_BOUNDARY}" "$ROOT_DIR")" || exit 2
    # Validate all fixed runner roots before Docker or mkdir can follow them.
    for directory in target cargo tmp reports allocator-cache; do
        resolve_bounded_directory "$directory" "$WORK_DIR/$directory" "$WORK_DIR" \
            >/dev/null || exit 2
    done
}

require_native_x86_64_host() {
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "native x86-64 allocator evidence refuses emulation (host: $(uname -m))" ;;
    esac
}

build_image() {
    configure_work_dir
    docker build \
        --platform "$PLATFORM" \
        --tag "$IMAGE" \
        --file "$DOCKERFILE" \
        "$ROOT_DIR"
}

ensure_image() {
    configure_work_dir
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        build_image
    fi
    local identity
    identity="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")"
    if [ "$identity" != "linux/amd64" ]; then
        fail "$IMAGE is $identity; rebuild it with ./compat/allocator/run-x86_64.sh image"
    fi
}

linked_worktree_git_mounts() {
    # A linked worktree's `.git` is a file whose gitdir points outside the
    # `/workspace` bind mount. Git must see those exact files to attest the
    # checked-out revision; copying status or inventing a clean state would
    # make a native report meaningless. Mount the real worktree view and its
    # common metadata read-only at their original absolute paths so ordinary
    # Git discovery from `/workspace` follows the existing gitfile unchanged.
    #
    # Do not set GIT_DIR/GIT_WORK_TREE in the container. The runner also uses
    # Git for operations that are not this checkout (for example `ls-remote`),
    # and a global override would contaminate those independent commands.
    GIT_METADATA_MOUNTS=()
    [ -e "$ROOT_DIR/.git" ] || return 0

    local git_common_dir
    local git_dir
    local physical_common_dir
    local physical_git_dir
    git_common_dir="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)" \
        || fail "cannot locate allocator worktree Git common directory"
    git_dir="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-dir)" \
        || fail "cannot locate allocator worktree Git directory"
    physical_common_dir="$(cd -P "$git_common_dir" 2>/dev/null && pwd)" \
        || fail "allocator worktree Git common directory is not physical"
    physical_git_dir="$(cd -P "$git_dir" 2>/dev/null && pwd)" \
        || fail "allocator worktree Git directory is not physical"
    case "$physical_git_dir" in
        "$physical_common_dir"|"$physical_common_dir"/*) ;;
        *) fail "allocator worktree Git directory is outside its common metadata" ;;
    esac

    GIT_METADATA_MOUNTS=(
        --volume "$physical_common_dir:$physical_common_dir:ro"
        --volume "$ROOT_DIR:$ROOT_DIR:ro"
    )
}

run_in_container() {
    # Contain old runner spellings as well as the CRABC_WORK_DIR-aware paths.
    # Keep /opt/cargo/bin from the pinned image visible; only Cargo's mutable
    # home moves into the checkout.
    mkdir -p "$WORK_DIR/target" "$WORK_DIR/cargo" "$WORK_DIR/tmp" \
        "$WORK_DIR/reports" "$WORK_DIR/allocator-cache"
    linked_worktree_git_mounts
    docker run --rm --init \
        --platform "$PLATFORM" \
        --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/allocator-x86_64/cargo \
        --env CARGO_TARGET_DIR=/workspace/.work/allocator-x86_64/target \
        --env CRABC_WORK_DIR=/workspace/.work/allocator-x86_64 \
        --env TMPDIR=/workspace/.work/allocator-x86_64/tmp \
        --env CRABC_ALLOCATOR_EVIDENCE_ARCH=x86_64 \
        --env CRABC_EXECUTION_MODE=native \
        --env CRABC_HOST_ARCH=x86_64 \
        --env MUSL_REFERENCE_LIBDIR=/opt/musl-1.2.6/lib \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$WORK_DIR:/workspace/.work/allocator-x86_64" \
        --volume "$WORK_DIR/target:/workspace/target" \
        --volume "$WORK_DIR/reports:/workspace/compat/reports" \
        --volume "$WORK_DIR/allocator-cache:/workspace/compat/allocator/.cache" \
        --volume "$WORK_DIR/tmp:/tmp" \
        "${GIT_METADATA_MOUNTS[@]}" \
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
    allocator-dynamic-full-direct-small-unmapped-reabandon|image|allocator|allocator-m1|allocator-m2|allocator-tls|allocator-lifecycle|allocator-fault|allocator-release-evidence|allocator-api-coverage|allocator-cmake-modes|allocator-header-modes|allocator-static-modes|allocator-remote-free|allocator-live-owner-full-medium-remote-release|allocator-live-owner-full-medium-one-remote-unfull-reuse|allocator-direct-remote|allocator-mapped-reclaim|allocator-mapped-adoption|allocator-direct-small-allocation-adoption|allocator-unmapped-reabandon|allocator-on-demand|allocator-direct-on-demand|allocator-aligned-overalloc-realloc|allocator-regular-small|allocator-direct-small-full-retire|allocator-medium-full-retire|allocator-full-non-direct-small-force-collect-post-exit|allocator-full-direct-small-force-collect-post-exit|allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped|allocator-dynamic-full-non-direct-small-unmapped-reabandon|allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped|allocator-dynamic-full-non-direct-small-unmapped-reabandon|allocator-dynamic-full-medium-one-remote-force-collect-to-mapped|allocator-dynamic-full-medium-unmapped-reabandon|allocator-dynamic-full-large-one-remote-force-collect-to-mapped|allocator-dynamic-full-large-unmapped-reabandon|allocator-dynamic-full-large-homogeneous-aggregate|allocator-dynamic-full-medium-homogeneous-aggregate|allocator-dynamic-full-singleton-homogeneous-aggregate|allocator-dynamic-full-non-direct-small-homogeneous-aggregate|allocator-later-thread-exit-full-direct-small-pages|allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate|allocator-automatic-pthread-destructor|allocator-cancellation-pthread-destructor|allocator-dynamic-os-aligned-singleton|allocator-dynamic-arena-singleton-post-exit|allocator-mapped-post-exit|allocator-retired-prepass|allocator-aggregate-post-exit|allocator-aggregate-still-live|allocator-aggregate-same-bin-still-live|allocator-perf|allocator-huge-registry|allocator-huge-reservation|allocator-unit|allocator-core-unit)
        ;;
    allocator-init-recursion)
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
    allocator-m1)
        [ "$#" -eq 0 ] || fail "allocator-m1 takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/run.py --m1 --offline
        ;;
    allocator-m2)
        [ "$#" -eq 0 ] || fail "allocator-m2 takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/run.py --m2 --offline
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
    allocator-init-recursion)
        [ "$#" -eq 0 ] || fail "allocator-init-recursion takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_init_recursion_evidence.py --offline
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
    allocator-cmake-modes)
        [ "$#" -eq 0 ] || fail "allocator-cmake-modes takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_cmake_mode_evidence.py --offline
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
    allocator-live-owner-full-medium-remote-release)
        [ "$#" -eq 0 ] || fail "allocator-live-owner-full-medium-remote-release takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_live_owner_full_medium_remote_release_evidence.py --offline
        ;;
    allocator-live-owner-full-medium-one-remote-unfull-reuse)
        [ "$#" -eq 0 ] || fail "allocator-live-owner-full-medium-one-remote-unfull-reuse takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_live_owner_full_medium_one_remote_unfull_reuse_evidence.py --offline
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
    allocator-mapped-adoption)
        [ "$#" -eq 0 ] || fail "allocator-mapped-adoption takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_mapped_adoption_evidence.py --offline
        ;;
    allocator-direct-small-allocation-adoption)
        [ "$#" -eq 0 ] || fail "allocator-direct-small-allocation-adoption takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_direct_small_allocation_adoption_evidence.py --offline
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
    allocator-aligned-overalloc-realloc)
        [ "$#" -eq 0 ] || fail "allocator-aligned-overalloc-realloc takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_aligned_overalloc_realloc_evidence.py --offline
        ;;
    allocator-regular-small)
        [ "$#" -eq 0 ] || fail "allocator-regular-small takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_regular_small_evidence.py --offline
        ;;
    allocator-direct-small-full-retire)
        [ "$#" -eq 0 ] || fail "allocator-direct-small-full-retire takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_direct_small_full_retire_evidence.py --offline
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
    allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_direct_small_one_remote_force_collect_to_mapped_evidence.py --offline
        ;;
    allocator-dynamic-full-direct-small-unmapped-reabandon)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-direct-small-unmapped-reabandon takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_direct_small_unmapped_reabandon_evidence.py --offline
        ;;
    allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_non_direct_small_one_remote_force_collect_to_mapped_evidence.py --offline
        ;;
    allocator-dynamic-full-non-direct-small-unmapped-reabandon)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-non-direct-small-unmapped-reabandon takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_non_direct_small_unmapped_reabandon_evidence.py --offline
        ;;
    allocator-dynamic-full-medium-one-remote-force-collect-to-mapped)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-medium-one-remote-force-collect-to-mapped takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_medium_one_remote_force_collect_to_mapped_evidence.py --offline
        ;;
    allocator-dynamic-full-medium-unmapped-reabandon)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-medium-unmapped-reabandon takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_medium_unmapped_reabandon_evidence.py --offline
        ;;
    allocator-dynamic-full-large-one-remote-force-collect-to-mapped)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-large-one-remote-force-collect-to-mapped takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_large_one_remote_force_collect_to_mapped_evidence.py --offline
        ;;
    allocator-dynamic-full-large-unmapped-reabandon)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-large-unmapped-reabandon takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_large_unmapped_reabandon_evidence.py --offline
        ;;
    allocator-dynamic-full-large-homogeneous-aggregate)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-large-homogeneous-aggregate takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_large_homogeneous_aggregate_evidence.py --offline
        ;;
    allocator-dynamic-full-medium-homogeneous-aggregate)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-medium-homogeneous-aggregate takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_medium_homogeneous_aggregate_evidence.py --offline
        ;;
    allocator-dynamic-full-singleton-homogeneous-aggregate)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-singleton-homogeneous-aggregate takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_singleton_homogeneous_aggregate_evidence.py --offline
        ;;
    allocator-dynamic-full-non-direct-small-homogeneous-aggregate)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-full-non-direct-small-homogeneous-aggregate takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_full_non_direct_small_homogeneous_aggregate_evidence.py --offline
        ;;
    allocator-later-thread-exit-full-direct-small-pages)
        [ "$#" -eq 0 ] || fail "allocator-later-thread-exit-full-direct-small-pages takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_later_thread_exit_full_direct_small_pages_evidence.py --offline
        ;;
    allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_nonfull_regular_pages_distinct_bin_aggregate_evidence.py --offline
        ;;
    allocator-automatic-pthread-destructor)
        [ "$#" -eq 0 ] || fail "allocator-automatic-pthread-destructor takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_automatic_pthread_destructor_evidence.py --offline
        ;;
    allocator-cancellation-pthread-destructor)
        [ "$#" -eq 0 ] || fail "allocator-cancellation-pthread-destructor takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_cancellation_pthread_destructor_evidence.py --offline
        ;;
    allocator-dynamic-os-aligned-singleton)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-os-aligned-singleton takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_os_aligned_singleton_evidence.py --offline
        ;;
    allocator-dynamic-arena-singleton-post-exit)
        [ "$#" -eq 0 ] || fail "allocator-dynamic-arena-singleton-post-exit takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_dynamic_arena_singleton_post_exit_evidence.py --offline
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
    allocator-huge-reservation)
        [ "$#" -eq 0 ] || fail "allocator-huge-reservation takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_huge_reservation_evidence.py
        ;;
    allocator-huge-registry)
        [ "$#" -eq 0 ] || fail "allocator-huge-registry takes no arguments"
        ensure_image
        run_in_container python3 compat/allocator/x86_64_huge_registry_evidence.py
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
