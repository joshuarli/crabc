#!/usr/bin/env bash
# Native Alpine/AArch64 development entry point.
#
# The image contains a pinned musl reference and Rust toolchain. The source
# tree and repository-local mutable work directory remain outside the image so
# normal edit/build loops do not rebuild it.
set -euo pipefail

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly WORK_BOUNDARY="$ROOT_DIR/.work"

# Docker interprets an unqualified --volume source as a named volume. Resolve
# every mutable host path before creating it so no configuration can turn that
# convenience syntax, a `..` traversal, or a symlink into an escape from the
# checkout-local .work boundary.
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

resolve_container_bind_directory() {
    local name="$1"
    local configured_path="$2"
    local relative_base="$3"

    # A bare word is Docker's named-volume syntax. Require an explicit host
    # path marker for overrides, then apply the same physical boundary check.
    if [[ "$configured_path" != /* && "$configured_path" != .* ]]; then
        configuration_error "$name must be an explicit host path; named Docker volumes are not allowed: $configured_path"
        return 1
    fi
    resolve_bounded_directory "$name" "$configured_path" "$relative_base"
}

if ! resolved_work_boundary="$(resolve_existing_directory "$WORK_BOUNDARY")"; then
    printf 'ERROR: checkout work boundary is not a directory: %s\n' "$WORK_BOUNDARY" >&2
    exit 2
fi
if [ "$resolved_work_boundary" != "$WORK_BOUNDARY" ]; then
    printf 'ERROR: checkout work boundary must resolve to %s, not %s\n' \
        "$WORK_BOUNDARY" "$resolved_work_boundary" >&2
    exit 2
fi

work_dir_input="${CRABC_WORK_DIR:-$WORK_BOUNDARY}"
if ! WORK_DIR="$(resolve_bounded_directory CRABC_WORK_DIR "$work_dir_input" "$ROOT_DIR")"; then
    exit 2
fi
readonly WORK_DIR
target_volume_input="${CRABC_TARGET_VOLUME:-$WORK_DIR/target}"
if ! TARGET_VOLUME="$(resolve_container_bind_directory CRABC_TARGET_VOLUME "$target_volume_input" "$WORK_DIR")"; then
    exit 2
fi
readonly TARGET_VOLUME
cargo_volume_input="${CRABC_CARGO_VOLUME:-$WORK_DIR/cargo}"
if ! CARGO_VOLUME="$(resolve_container_bind_directory CRABC_CARGO_VOLUME "$cargo_volume_input" "$WORK_DIR")"; then
    exit 2
fi
readonly CARGO_VOLUME
readonly PLATFORM="linux/arm64"
readonly IMAGE="${CRABC_DEV_IMAGE:-crabc-dev:aarch64}"

usage() {
    cat <<'EOF'
Usage: ./scripts/dev.sh <command> [arguments]

Commands:
  image               build the pinned Linux/AArch64 development image
  build [cargo args]  cargo build --workspace
  structure           check repository ownership and composition invariants
  test [cargo args]   cargo test --workspace test targets (staticlib examples run under crabc-rs)
  symbols             compare libc.so exports with pinned musl 1.2.6
  compat              refresh symbol evidence and enforce its regression ratchet
  ratchet             alias for compat
  libc-test [subset]  run the pinned libc-test checkout (functional by default)
  differential [case] run a pinned musl-vs-crabc workload comparison
  os-test [options]   run the pinned POSIX os-test profile against musl and crabc
  pthread-stress [options] run bounded pthread/TLS stress against musl and crabc
  static-pthread-tls [options] run conventional static libc.a pthread/TLS lifecycle against musl and crabc
  signal-process [case] run the isolated signal/process comparison workload
  resolver-network [options] run the deterministic local resolver/network workload
  ldso [options]      run the synthetic loader differential suite
  corpus [options]    run the pinned Alpine AArch64 package corpus (Tier A by default)
  rust-std [options]  run the stock Rust std musl-vs-crabc differential fixture
  rust-std-dependent  run the dependency-bearing stock Rust application
  lto [options]       run the AArch64 static/build-std LTO evidence matrix
  lto-native-facade [options] run the native crabc-rs facade LTO proof
  sysroot [options]   build and prove the owned CRT/sysroot and sealed C driver
  sysroot-dist [options]
                      build, deterministically package, and smoke a commit sysroot snapshot
  sysroot-smoke <archive>
                      smoke-test one packaged sysroot archive without rebuilding it
  lua [options]       build Lua 5.4 through the owned crabc sysroot
  allocator --quick|--full|--churn|--soak|--tls-terminal-prototype
                      build/check the pinned mimalloc v3.5.0 C-oracle baseline
  allocator-m1        run the current-commit M1 foundations evidence gate
  allocator-upstream [options]
                      run exact pinned upstream pthread stress on the native shadow libc
  allocator-shadow    run the nondefault native-mimalloc libc ABI/pthread shadow gate
  allocator-tls       prove private initial-exec allocator TLS codegen
  allocator-perf --smoke|--full
                      request allocator comparison evidence (unavailable until its milestone)
  perf [options]      measure equivalent musl/crabc C-runtime workloads (release build)
  perf-native [options] measure crabc-rs direct facades against pinned Rustix
  crabc-rs            run the native crabc-rs capability/accounting/evidence gate
  abi-probe [options] generate selected public AArch64 ABI evidence
  loader-inventory   generate/check pinned musl and crabc loader reports
  dashboard           generate COMPATIBILITY.md from current structured reports
  environment         write reproducibility metadata for compatibility reports
  shell               open a shell in the development image

The image and containers are always requested as linux/arm64. Mutable build
state is confined to this checkout's `.work/` boundary: targets live in
`.work/target`, Cargo's download cache lives in `.work/cargo`, and reports and
scratch state live below `.work/`. `CRABC_WORK_DIR` may select another physical
descendant of `.work/`. `CRABC_TARGET_VOLUME` and `CRABC_CARGO_VOLUME` accept
only explicit host paths below that boundary; relative overrides resolve from
the selected work directory. Docker named volumes, `..` path components,
symlink escapes, and external paths are rejected.
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

prepare_work_dir() {
    mkdir -p \
        "$WORK_DIR" \
        "$WORK_DIR/target" \
        "$WORK_DIR/cargo" \
        "$WORK_DIR/reports" \
        "$WORK_DIR/allocator-cache" \
        "$WORK_DIR/tmp" \
        "$TARGET_VOLUME" \
        "$CARGO_VOLUME"
}

run_in_container() {
    prepare_work_dir
    local rustix_source_host="${CRABC_RUSTIX_SOURCE_HOST:-$ROOT_DIR/../rustix}"
    local rustybench_source_host="${CRABC_RUSTYBENCH_SOURCE_HOST:-$ROOT_DIR/../rustybench}"
    local git_common_dir=""
    local git_common_physical=""
    local -a rustix_mount=()
    local -a rustybench_mount=()
    local -a git_common_mount=()
    if [ "${1:-}" = "--allocator-git-common-dir" ]; then
        shift
        if ! git_common_dir="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)"; then
            configuration_error "allocator evidence requires a Git worktree with a readable common directory"
            return 1
        fi
        if [[ "$git_common_dir" != /* ]] || [ ! -d "$git_common_dir" ]; then
            configuration_error "allocator evidence Git common directory is not an existing absolute path: $git_common_dir"
            return 1
        fi
        if ! git_common_physical="$(cd -P "$git_common_dir" && pwd)"; then
            configuration_error "allocator evidence Git common directory cannot be resolved physically: $git_common_dir"
            return 1
        fi
        if [ "$git_common_dir" != "$git_common_physical" ]; then
            configuration_error "allocator evidence Git common directory must be a physical path: $git_common_dir"
            return 1
        fi
    fi
    if [ -d "$rustix_source_host" ]; then
        # The comparison harness treats Rustix only as a pinned test oracle.
        # Keep a user checkout read-only, outside the worktree, and expose its
        # container path through explicit variables.  Otherwise Git records a
        # Docker-injected untracked directory as source-tree dirtiness.
        # Production Cargo manifests never name this checkout.
        rustix_mount=(
            --env CRABC_RUSTIX_SOURCE=/opt/rustix
            --env CRABC_NATIVE_RUSTIX_SOURCE=/opt/rustix
            --volume "$rustix_source_host:/opt/rustix:ro"
        )
    fi
    if [ -d "$rustybench_source_host" ]; then
        # Rustybench is a local benchmark-tool checkout, never a crabc
        # production dependency. Mount it outside the worktree so it cannot
        # affect evidence provenance.
        rustybench_mount=(
            --env CRABC_RUSTYBENCH_SOURCE=/opt/rustybench
            --volume "$rustybench_source_host:/opt/rustybench:ro"
        )
    fi
    if [ -n "$git_common_dir" ]; then
        # A linked worktree's .git file records its common directory as a
        # host-absolute path. Mount that one Git metadata directory read-only
        # at the same path only for an attested command, so in-container Git
        # can read the worktree state without making source metadata mutable.
        git_common_mount=(--volume "$git_common_dir:$git_common_dir:ro")
    fi
    # The bind-mounted checkout can be owned by the host runner while the
    # container queries it as root. Scope Git's ownership exception to this
    # one mount instead of mutating a shared global config.
    local -a docker_args=(
        docker run --rm --init
        --platform "$PLATFORM"
        --workdir /workspace
        # Keep the image's Rust toolchain visible at /opt/cargo/bin while
        # directing Cargo's mutable registry and git caches into .work.
        --env CARGO_HOME=/workspace/.work/cargo
        # Python harnesses must not leave bytecode caches in the source mount.
        --env PYTHONDONTWRITEBYTECODE=1
        --env LIBC_TEST_DIR=/opt/libc-test
        --env MUSL_REFERENCE_LIBDIR=/opt/musl-1.2.6/lib
        --env CRABC_WORK_DIR=/workspace/.work
        --env TMPDIR=/workspace/.work/tmp
        --env GIT_CONFIG_COUNT=1
        --env GIT_CONFIG_KEY_0=safe.directory
        --env GIT_CONFIG_VALUE_0=/workspace
        --volume "$ROOT_DIR:/workspace"
        --volume "$WORK_DIR:/workspace/.work"
        --volume "$TARGET_VOLUME:/workspace/target"
        --volume "$CARGO_VOLUME:/workspace/.work/cargo"
    )
    if [ -d "$rustix_source_host" ]; then
        docker_args+=("${rustix_mount[@]}")
    fi
    if [ -d "$rustybench_source_host" ]; then
        docker_args+=("${rustybench_mount[@]}")
    fi
    if [ -n "$git_common_dir" ]; then
        docker_args+=("${git_common_mount[@]}")
    fi
    docker_args+=("$IMAGE" "$@")
    "${docker_args[@]}"
}

run_allocator_evidence() {
    # The runner attests source provenance in every lane. A linked worktree's
    # .git file names its common directory with a host-absolute path, so grant
    # each attested allocator run the same read-only metadata mount.
    run_in_container --allocator-git-common-dir python3 compat/allocator/run.py "$@"
}

# Resolver evidence must not inherit Docker's host-derived DNS configuration.
# This private network namespace has only loopback, and Docker writes an
# isolated regular /etc/resolv.conf pointing at the fixture. The Python runner
# verifies that boundary before temporarily installing its three loopback
# nameservers and restores the file before it exits.
run_in_resolver_container() {
    prepare_work_dir
    docker run --rm --init \
        --platform "$PLATFORM" \
        --network none \
        --dns 127.0.0.1 \
        --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/cargo \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env LIBC_TEST_DIR=/opt/libc-test \
        --env MUSL_REFERENCE_LIBDIR=/opt/musl-1.2.6/lib \
        --env CRABC_WORK_DIR=/workspace/.work \
        --env TMPDIR=/workspace/.work/tmp \
        --env CRABC_RESOLVER_NETWORK_ISOLATED=1 \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$WORK_DIR:/workspace/.work" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/workspace/.work/cargo" \
        "$IMAGE" "$@"
}

collect_symbol_report() {
    run_in_container cargo build --workspace
    run_in_container python3 scripts/collect_environment.py
    run_in_container python3 scripts/check_symbols.py
}

# Batch evidence must measure an unchanged source tree. Most harness commands
# normally refresh the checked-in dashboard for interactive use; suppress only
# that derived write when the final suite requests it, then run `dashboard`
# explicitly as the evidence-only child commit.
refresh_dashboard() {
    if [ "${CRABC_SKIP_DASHBOARD:-0}" = "1" ]; then
        return
    fi
    local runner="$1"
    "$runner" python3 scripts/generate_compatibility_dashboard.py
}

run_workspace_tests() {
    # Native Linux/AArch64 Cargo uses the target rustflags for build scripts
    # and proc-macros too. Keep target runtime crates on initial-exec while
    # the test-only wrapper removes that model solely from dynamically loaded
    # host tools; see `rustc_test_host_tool_wrapper.sh` for the boundary.
    local test_rustc_wrapper="/workspace/scripts/rustc_test_host_tool_wrapper.sh"
    # Without an explicit target selector, Cargo's test default also compiles
    # crabc-rs static-library examples. Those no_std proof artifacts own their
    # panic handlers and are built independently by the crabc-rs evidence gate.
    # Preserve an explicit target selection, such as documented `--test`
    # regressions, while making the generic route integration-test only.
    local argument
    local package_scoped=0
    for argument in "$@"; do
        case "$argument" in
            -p|--package|--package=*)
                package_scoped=1
                ;;
        esac
    done
    if [ "$package_scoped" -eq 1 ]; then
        # An explicit package selector is already a complete Cargo scope.
        # Injecting `--workspace` also selects unrelated no_std runtime lib-test
        # targets and makes focused package commands fail during their link.
        run_in_container env RUSTC_WRAPPER="$test_rustc_wrapper" python3 scripts/run_owned_test_suite.py \
            --sysroot target/crabc-sysroot \
            --loader target/debug/libldso.so \
            -- cargo test "$@"
        return
    fi
    for argument in "$@"; do
        case "$argument" in
            --lib|--bins|--tests|--examples|--benches|--all-targets|--doc|--bin|--bin=*|--example|--example=*|--test|--test=*|--bench|--bench=*)
                run_in_container env RUSTC_WRAPPER="$test_rustc_wrapper" python3 scripts/run_owned_test_suite.py \
                    --sysroot target/crabc-sysroot \
                    --loader target/debug/libldso.so \
                    -- cargo test --workspace "$@"
                return
                ;;
        esac
    done
    run_in_container env RUSTC_WRAPPER="$test_rustc_wrapper" python3 scripts/run_owned_test_suite.py \
        --sysroot target/crabc-sysroot \
        --loader target/debug/libldso.so \
        -- cargo test --workspace --tests "$@"
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
    structure)
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        ensure_image
        run_in_container python3 scripts/check_structure.py
        ;;
    test)
        ensure_image
        # Integration tests execute target/debug/lib{c,ldso}.so directly, so
        # build their runtime artifacts before compiling the test harness.
        run_in_container cargo build --workspace
        # The generic integration suite includes conventional static C
        # programs. Build the sealed installed tree first so those tests link
        # through crabc's own CRT and helper archive rather than a musl CRT
        # bridge.
        run_in_container cargo build --workspace --release
        run_in_container python3 scripts/build_owned_sysroot.py
        # crabc-rs examples are no_std static-library proofs with their own
        # panic handlers. Cargo's default test target set compiles them with
        # the package's default std feature; its manifest-driven crabc-rs gate
        # builds every proof independently with its declared feature boundary.
        # libc and ldso are no_std runtime images, not hosted lib-test
        # executables. Their focused unit evidence belongs to their dedicated
        # gates; this generic command runs the workspace integration regressions.
        run_workspace_tests "$@"
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
        refresh_dashboard run_in_container
        ;;
    libc-test)
        ensure_image
        # The Python runner deliberately reuses existing artifacts when they
        # exist. Build here so a harness invocation always measures the
        # checked-out source rather than an earlier compatibility run.
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 libc-test-harness/runner.py "$@"
        refresh_dashboard run_in_container
        ;;
    differential)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/differential/run.py "$@"
        refresh_dashboard run_in_container
        ;;
    os-test)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/os-test/run.py "$@"
        refresh_dashboard run_in_container
        ;;
    pthread-stress)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/pthread-stress/run.py "$@"
        refresh_dashboard run_in_container
        ;;
    static-pthread-tls)
        ensure_image
        # Build the installed tree once; the candidate then uses only its
        # sealed driver, CRT, libc archive, and compiler-helper archive.
        run_in_container python3 scripts/build_owned_sysroot.py
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/static-pthread-tls/run.py --sysroot target/crabc-sysroot "$@"
        refresh_dashboard run_in_container
        ;;
    signal-process)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/signal-process/run.py "$@"
        refresh_dashboard run_in_container
        ;;
    resolver-network)
        ensure_image
        run_in_resolver_container cargo build --workspace
        run_in_resolver_container python3 scripts/collect_environment.py
        run_in_resolver_container python3 compat/resolver-network/run.py "$@"
        refresh_dashboard run_in_resolver_container
        ;;
    ldso)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/ldso/run.py "$@"
        refresh_dashboard run_in_container
        ;;
    corpus)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/corpus/run.py "$@"
        refresh_dashboard run_in_container
        ;;
    rust-std)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/rust-std/run.py "$@"
        refresh_dashboard run_in_container
        ;;
    rust-std-dependent)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/rust-std/run.py \
            --fixture compat/rust-std/dependent-fixture/src/main.rs \
            --report compat/reports/rust-std-dependent/latest.json "$@"
        refresh_dashboard run_in_container
        ;;
    lto)
        ensure_image
        run_in_container cargo build --workspace
        # Controlled-C candidate B links through the sealed installed driver,
        # not musl/GCC CRT or compiler-runtime support files.
        run_in_container python3 scripts/build_owned_sysroot.py
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/lto/run.py "$@"
        refresh_dashboard run_in_container
        ;;
    lto-native-facade)
        ensure_image
        # Native-facade candidate lanes link only through the installed sealed
        # driver. Build the owned CRT/sysroot first; the retained stock-std
        # musl comparison is a separately labelled oracle lane, not candidate
        # build provenance.
        run_in_container python3 scripts/build_owned_sysroot.py
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/lto/native_facade_lto.py --sysroot target/crabc-sysroot "$@"
        refresh_dashboard run_in_container
        ;;
    sysroot)
        ensure_image
        # The Python entry point performs two independently clean production
        # builds, assembly, mode/link/map evidence, and the reproducibility
        # comparison. It owns all generated sysroot paths deliberately.
        run_in_container python3 scripts/build_owned_sysroot.py "$@"
        ;;
    sysroot-dist)
        ensure_image
        # The release entry point owns all work on the container's Linux
        # filesystem and copies only four final assets to /workspace/dist.
        run_in_container python3 scripts/sysroot_dist.py dist "$@"
        ;;
    sysroot-smoke)
        ensure_image
        if [ "$#" -ne 1 ]; then
            usage >&2
            exit 2
        fi
        run_in_container python3 scripts/sysroot_dist.py smoke --archive "$1"
        ;;
    lua)
        ensure_image
        # Lua is built from the hash-pinned upstream source through the
        # installed sealed driver. Musl remains an execution oracle only.
        run_in_container python3 scripts/build_owned_sysroot.py
        run_in_container python3 compat/lua/run.py --sysroot target/crabc-sysroot "$@"
        refresh_dashboard run_in_container
        ;;
    allocator)
        ensure_image
        if [ "$#" -ne 1 ]; then
            usage >&2
            exit 2
        fi
        case "$1" in
            --quick)
                run_allocator_evidence --quick
                ;;
            --full)
                # This runner builds the complete C-oracle/M4 boundary, runs
                # the recorded 128-cycle M5 lifecycle lane, and reports each
                # reviewed unmet M5 gate without turning absent Rust work into
                # a pass.
                run_allocator_evidence --full
                ;;
            --churn)
                # This bounded lane repeats the mixed-local and live-owner
                # remote-free pthread witnesses under a watchdog; it is not a
                # general allocator pass.
                run_allocator_evidence --churn
                ;;
            --soak)
                # This opt-in larger lane uses the same pointer-private
                # witnesses and a longer watchdog. It is lifecycle stability
                # evidence, not a general allocator pass.
                run_allocator_evidence --soak
                ;;
            --tls-terminal-prototype)
                # This is the standalone C half of the selected same-TLD
                # terminal trace. It does not by itself write an M1 report
                # or select a libc allocator backend.
                run_allocator_evidence --m1-tls-terminal-prototype
                ;;
            *)
                usage >&2
                exit 2
                ;;
        esac
        ;;
    allocator-m1)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        # This is an acceptance-record producer, not a synonym for a green
        # allocator milestone. It returns the runner's intentional unmet-M1
        # status while the checked contract has remaining conditions.
        run_allocator_evidence --m1
        ;;
    allocator-upstream)
        ensure_image
        # Build the owned runtime first, then capture the exact compiler-artifact
        # emitted by the selected nondefault libc build. The runner binds both
        # selected libc outputs to that record before starting stress.
        run_in_container cargo build --workspace --locked
        run_in_container cargo build --workspace --release --locked
        run_in_container python3 scripts/build_owned_sysroot.py
        selected_libc_build_record=".work/target/compat/allocator/upstream-stress/selected-libc-build.json"
        run_in_container python3 compat/allocator/upstream-stress/run.py \
            --capture-selected-libc-build "$selected_libc_build_record"
        run_in_container python3 scripts/run_owned_test_suite.py \
            --sysroot target/crabc-sysroot \
            --loader target/debug/libldso.so \
            -- python3 compat/allocator/upstream-stress/run.py \
                --libc-build-record "$selected_libc_build_record" "$@"
        ;;
    allocator-shadow)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        # C stays the production allocator. Build the ordinary workspace and
        # owned sysroot first because the C fixtures need the normal loader
        # and installed aliases, then build the selected shadow libc *last*.
        # The generic `test` command deliberately rebuilds the default
        # workspace runtime, so it cannot serve as evidence for this feature.
        run_in_container cargo build --workspace
        run_in_container cargo build --workspace --release
        run_in_container python3 scripts/build_owned_sysroot.py
        # Preserve and attest the ordinary C-backed dynamic libc before the
        # feature build replaces target/debug/libc.so. The paired runner later
        # compiles the same normalized local C trace against this snapshot and
        # the selected Rust artifact; it does not create runtime selection.
        run_in_container python3 compat/allocator/shadow-abi-matrix/run.py capture
        run_in_container cargo build -p crabc-libc --features native-mimalloc-shadow
        run_in_container python3 scripts/run_owned_test_suite.py \
            --sysroot target/crabc-sysroot \
            --loader target/debug/libldso.so \
            -- python3 compat/allocator/shadow-abi-matrix/run.py run
        # The direct runtime regressions keep live-owner PageMap remote
        # publication observable without selecting the ordinary C allocator
        # artifact before the C ABI fixture exercises the selected shared object.
        run_in_container cargo test -p crabc-mimalloc \
            --test native_live_remote_free \
            --test native_two_live_remote_owners \
            --test native_live_remote_owner_registry_reuse \
            --test native_page_local_live_remote_protocol \
            --test native_post_exit_claimed_remote_producers \
            --test native_pointer_first_initial_foreign_free \
            -- --test-threads=1
        # These direct tests compile scalar-only lifecycle and admission audits
        # behind their own default-off feature. They establish that pointer-
        # first post-exit operations leave B teardown independent of A and
        # that a live owner-exit source head CAS retries real PageMap-derived
        # foreign publications.
        run_in_container cargo test -p crabc-mimalloc \
            --features native-runtime-test-audit \
            --test native_multiple_post_exit_completions \
            --test native_terminal_completion_live_remote_free \
            --test native_concurrent_post_exit_os_singletons \
            --test native_concurrent_mixed_post_exit_completions \
            --test native_persistent_worker_fastpath \
            --test native_pointer_first_current_owner_reallocate \
            --test native_pointer_first_usable_size \
            --test native_owner_exit_collection_race \
            --test native_ordinary_mapped_medium_reclaim \
            -- --test-threads=1
        # The next-`munmap` injection is a separately gated direct witness:
        # a failed OS terminal release must retain its PageMap source without
        # making B's independently empty owner terminal.
        run_in_container cargo test -p crabc-mimalloc \
            --features native-runtime-test-audit,native-runtime-test-fault \
            --test native_post_exit_failed_os_release \
            --test native_post_exit_terminal_owner_retention \
            --test native_pointer_first_post_exit_os_release \
            -- --test-threads=1
        # A joined pointer-first source publication is collected during A's
        # ordinary persistent-owner teardown before a fresh releaser frees
        # A's surviving client through process PageMap/page state.
        run_in_container cargo test -p crabc-mimalloc \
            --test native_source_published_live_owner_exit \
            --test native_concurrent_post_exit_page_release \
            -- --test-threads=1
        run_in_container env RUSTC_WRAPPER="/workspace/scripts/rustc_test_host_tool_wrapper.sh" \
            python3 scripts/run_owned_test_suite.py \
            --sysroot target/crabc-sysroot \
            --loader target/debug/libldso.so \
            -- cargo test -q -p crabc-libc --features native-mimalloc-shadow \
            --test allocator \
            --test native_mimalloc_shadow_abi \
            --test native_mimalloc_owner_exit \
            --test native_mimalloc_retired_owner_exit \
            --test native_mimalloc_two_owner_exit \
            --test native_mimalloc_three_owner_exit \
            --test native_mimalloc_post_exit_split_releaser \
            --test native_mimalloc_aggregate_reclaim \
            --test native_mimalloc_owner_exit_realloc \
            --test native_mimalloc_live_remote_free \
            --test native_mimalloc_live_remote_from_parked_worker \
            --test native_mimalloc_source_published_exit \
            --test native_mimalloc_source_published_live_owner_exit \
            --test native_mimalloc_post_exit_source_published_successor \
            --test native_mimalloc_post_exit_source_published_all_free_proof \
            --test native_mimalloc_two_live_remote_owners \
            --test native_mimalloc_initial_post_exit_free \
            --test native_mimalloc_initial_remote_free \
            --test native_mimalloc_parallel_local_workers \
            --test native_mimalloc_cabi_local_worker_scaling \
            --test native_mimalloc_concurrent_session_start \
            --test native_mimalloc_many_local_allocations \
            --test native_mimalloc_initial_live_local_worker \
            --test native_mimalloc_initial_live_owner_exit \
            --test native_mimalloc_initial_free_while_owner_exit \
            --test native_mimalloc_initial_live_parallel_workers \
            --test native_mimalloc_many_owner_exit_allocations \
            --test native_mimalloc_concurrent_post_exit_release \
            --test native_mimalloc_post_exit_concurrent_realloc \
            --test native_mimalloc_concurrent_owner_exit \
            --test native_mimalloc_live_remote_owner_exit \
            --test pthread_atfork \
            --test pthread_create_join_tls_regression \
            -- --test-threads=1
        # Keep the source-derived pthread workload outside the one-thread
        # prefixed adapter. This wrapper stages the exact owned loader and
        # debug libc aliases before the runner selects the native-shadow
        # `libc.so` for all standard C allocation calls.
        run_in_container python3 scripts/run_owned_test_suite.py \
            --sysroot target/crabc-sysroot \
            --loader target/debug/libldso.so \
            -- python3 compat/allocator/run.py --native-shadow-stress
        ;;
    allocator-tls)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        run_in_container python3 compat/allocator/tls-codegen/run.py
        ;;
    allocator-perf)
        ensure_image
        if [ "$#" -ne 1 ]; then
            usage >&2
            exit 2
        fi
        case "$1" in
            --smoke)
                run_in_container python3 compat/allocator/run.py --perf-smoke
                ;;
            --full)
                run_in_container python3 compat/allocator/run.py --perf-full
                ;;
            *)
                usage >&2
                exit 2
                ;;
        esac
        ;;
    perf)
        ensure_image
        # Keep this separate from correctness gates. The report records the
        # release profile source and artifact hashes, so a later optimization
        # experiment can be compared with the baseline rather than overwrite it.
        run_in_container cargo build --workspace --release
        run_in_container python3 compat/perf/run.py "$@"
        ;;
    perf-native)
        ensure_image
        run_in_container python3 compat/perf/native/run.py "$@"
        ;;
    crabc-rs)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        # The capability ledger retains and validates the complete, hash-pinned semantic
        # ledger. Its first three bounded seams are immutable timezone rules,
        # configured DNS UDP/TCP transport, and a private-runtime basic loader
        # facade. Keep all native and C-regression evidence together so a
        # later facade change cannot add a C/errno hop.
        # Keep no-std, native, source-compatibility, and assembly evidence
        # together so a later facade change cannot add a C/errno hop.
        run_in_container cargo check -p crabc-rs --no-default-features
        run_in_container cargo check -p crabc-rs --no-default-features --features alloc
        run_in_container cargo check -p crabc-rs --no-default-features --features runtime-thread
        run_in_container cargo check -p crabc-rs --no-default-features --features runtime-thread-alloc
        run_in_container cargo check -p crabc-rs --no-default-features --features runtime-stdio
        run_in_container cargo test -p crabc-core --lib
        run_in_container cargo test -p crabc-rs --test direct --test foundation --test filesystem --test core_os --test process_system --test fs_io --test event_time --test file_mapping --test descriptor_stdio --test signal_process --test synchronization --test resolver_netdb --test fenv --test fnmatch --test glob --test text --test text_stateful --test ctype --test format --test number --test numeric_legacy --test random --test memory_special --test memory_vm --test fs_metadata --test statx --test positioned --test vectored --test positioned_vectored --test preadv2 --test directory --test memfd --test fallocate --test fadvise --test sendfile --test syncfs --test ppoll --test readiness --test msync --test mincore --test mlock --test mremap --test madvise --test identity --test rusage --test getgroups --test priority --test setpriority --test rlimit --test sleep --test clock_nanosleep --test time --test time_dynamic --test getitimer --test time_timers --test calendar_utc --test calendar_local --test time_realtime_millis --test readahead --test copy_file_range --test sync_file_range --test network_address --test ethernet_address --test ethers --test network_socket --test network_socket_options --test network_messages --test network_mmsg --test network_connect --test network_bind_getsockname --test network_getpeername --test network_listen_accept --test network_datagram --test descriptor --test subsumed --test resolver_transport --test timezone_rules
        run_in_container cargo test -p crabc-rs --test resolver_system
        run_in_container cargo test -p crabc-rs --test cfile --features runtime-stdio
        run_in_container cargo test -p crabc-rs --test directory_position
        run_in_container cargo test -p crabc-rs --test network_socket_type
        run_in_container cargo test -p crabc-rs --test network_socket_protocol
        run_in_container cargo test -p crabc-rs --test network_socket_cookie
        run_in_container cargo test -p crabc-rs --test network_socket_domain
        run_in_container cargo test -p crabc-rs --test network_socket_acceptconn
        run_in_container cargo test -p crabc-rs --test network_socket_oobinline
        run_in_container cargo test -p crabc-rs --test network_socket_broadcast
        run_in_container cargo test -p crabc-rs --test pipe_tee
        run_in_container cargo test -p crabc-rs --test descriptor
        run_in_container cargo test -p crabc-rs --test readiness
        run_in_container cargo test -p crabc-rs --test pipe_size
        run_in_container cargo test -p crabc-rs --test fcntl_seals
        run_in_container cargo test -p crabc-rs --test fcntl_getlk
        run_in_container cargo test -p crabc-rs --test getcwd --test current_dir_name --test eventfd --test times
        run_in_container cargo test -p crabc-rs --test setpriority
        run_in_container cargo test -p crabc-rs --test scheduler_priority_bounds
        run_in_container cargo test -p crabc-rs --test sched_rr_interval
        run_in_container cargo test -p crabc-rs --test sched_getaffinity
        run_in_container cargo test -p crabc-rs --test sched_setaffinity
        run_in_container cargo test -p crabc-rs --test pidfd_open
        run_in_container cargo test -p crabc-rs --test session_observation --test thread_identity
        run_in_container cargo test -p crabc-rs --test access --test truncate --test process_identity
        run_in_container cargo test -p crabc-rs --test accessat
        run_in_container cargo test -p crabc-rs --test process_cwd --test fs_canonicalize --test fs_tempdir --test fs_tempfile --test fs_named_tempfile --test filesystem_sync --test inotify --test ipc --test users_databases
        run_in_container cargo test -p crabc-rs --test process_chroot
        run_in_container cargo test -p crabc-rs --test process_clock_id --test time_settime --test time_timespec_get --test param_auxv
        run_in_container cargo test -p crabc-rs --test network_interface_index --test network_interface_index_name --test interface_names --test interface_addresses
        run_in_container cargo test -p crabc-rs --test network_ipaddr --test ipv4_legacy --test pause --test ttyname --test pty_session --test termios_exclusive --test termios_special_codes --test termios_queue --test terminal_control --test futex --test thread_credentials --test fs_credentials
        run_in_container cargo test -p crabc-rs --test sched_cpu
        run_in_container cargo test -p crabc-rs --test ownership
        run_in_container cargo test -p crabc-rs --test special_nodes
        run_in_container cargo test -p crabc-rs --test system_names
        run_in_container cargo test -p crabc-rs --test load_average
        run_in_container cargo test -p crabc-rs --test process_cpu_time
        run_in_container cargo test -p crabc-rs --test getentropy --test create
        run_in_container cargo test -p crabc-rs --test fcntl_flags
        run_in_container cargo test -p crabc-rs --test futimes
        run_in_container cargo test -p crabc-rs --test lutimes
        run_in_container cargo test -p crabc-rs --test futimesat
        run_in_container cargo test -p crabc-rs --test utimes
        run_in_container cargo test -p crabc-rs --test utime
        # Cargo combines allocator domains when it builds all examples at once.
        # The manifest-driven runner keeps each static-library proof target and
        # its required feature set independent without duplicating target names here.
        run_in_container python3 compat/crabc-rs/build_examples.py
        run_in_container cargo build -p crabc-libc
        run_in_container cargo test -p crabc-libc --test loader_runtime --test loader_dlfcn_basic --test loader_dlfcn_introspection --test runtime_thread --test cfile_runtime --test fclose_lifecycle --test fenv --test fnmatch --test iconv --test iconv_error_progress --test stdio_full --test stdio_exports --test stdio_extensions_exports --test cookie_stream_exports --test wmemstream_exports --test select --test break_exports --test memory_vm_exports --test host_process_exports --test filesystem_paths_exports
        run_in_container python3 compat/rustix/run.py --check
        run_in_container python3 -m unittest discover -s compat/rustix/tests -p 'test_*.py'
        run_in_container python3 -m unittest discover -s compat/crabc-rs/tests -p 'test_*.py'
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/foundation.rs
        run_in_container python3 compat/crabc-rs/verify_direct_io.py --target-dir target
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/statat.rs \
            --fixture compat/rustix/source/links.rs \
            --fixture compat/rustix/source/metadata.rs \
            --fixture compat/rustix/source/raw_dir.rs \
            --fixture compat/rustix/source/locks.rs \
            --fixture compat/rustix/source/openat2.rs \
            --fixture compat/rustix/source/xattr.rs
        run_in_container python3 compat/crabc-rs/verify_filesystem.py --target-dir target
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/time_pipe_random.rs \
            --fixture compat/rustix/source/event.rs \
            --fixture compat/rustix/source/net_mm.rs
        run_in_container python3 compat/crabc-rs/verify_core_os.py --target-dir target
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/process_system.rs
        run_in_container python3 compat/crabc-rs/verify_process_system.py --target-dir target
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/process.rs
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/time_dynamic.rs
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/accessat.rs \
            --fixture compat/rustix/source/sched_getaffinity.rs \
            --fixture compat/rustix/source/pidfd_open.rs \
            --fixture compat/rustix/source/socket_type.rs \
            --fixture compat/rustix/source/socket_cookie.rs \
            --fixture compat/rustix/source/socket_domain.rs \
            --fixture compat/rustix/source/socket_acceptconn.rs \
            --fixture compat/rustix/source/socket_oobinline.rs \
            --fixture compat/rustix/source/socket_broadcast.rs \
            --fixture compat/rustix/source/pipe_tee.rs \
            --fixture compat/rustix/source/pipe_splice.rs \
            --fixture compat/rustix/source/readiness.rs \
            --fixture compat/rustix/source/pipe_size.rs \
            --fixture compat/rustix/source/fcntl_seals.rs \
            --fixture compat/rustix/source/fcntl_add_seals.rs \
            --fixture compat/rustix/source/fcntl_getlk.rs \
            --fixture compat/rustix/source/socket_protocol.rs \
            --fixture compat/rustix/source/memory_vm.rs \
            --fixture compat/rustix/source/process_chroot.rs \
            --fixture compat/rustix/source/process_umask.rs \
            --fixture compat/rustix/source/process_setrlimit.rs \
            --fixture compat/rustix/source/posix_fallocate.rs \
            --fixture compat/rustix/source/time_settime.rs \
            --fixture compat/rustix/source/param_auxv.rs \
            --fixture compat/rustix/source/network_interface_index.rs \
            --fixture compat/rustix/source/network_interface_index_name.rs \
            --fixture compat/rustix/source/pause.rs \
            --fixture compat/rustix/source/ttyname.rs \
            --fixture compat/rustix/source/termios_exclusive.rs \
            --fixture compat/rustix/source/futex.rs \
            --fixture compat/rustix/source/network_ipaddr.rs \
            --fixture compat/rustix/source/termios_special_codes.rs \
            --fixture compat/rustix/source/termios_queue.rs \
            --fixture compat/rustix/source/thread_credentials.rs \
            --fixture compat/rustix/source/fs_tempdir.rs
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/fs_io.rs \
            --fixture compat/rustix/source/event_time.rs \
            --fixture compat/rustix/source/file_mapping.rs \
            --fixture compat/rustix/source/descriptor_stdio.rs
        run_in_container python3 compat/crabc-rs/verify_descriptor_mapping.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_signal_process.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_sync.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_resolver.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_loader_runtime.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_loader_dlfcn.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_runtime_thread.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_fenv.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_fnmatch.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_cfile.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_text.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_stateful_text.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_ctype.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_special_memory.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_format.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_number.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_numeric_legacy.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_random.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fs-metadata --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fs-canonicalize --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fs-tempdir --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fs-tempfile --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fs-named-tempfile --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py inotify --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py mqueue --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py users-databases --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py positioned --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py vectored --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py positioned-vectored --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py directory --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py directory-position --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py pipe-tee --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py descriptor --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py pipe-size --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fcntl-seals --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fcntl-add-seals --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fcntl-getlk --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py memfd --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fallocate --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py syncfs --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py rlimit --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py rlimit-for --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py process-limits-umask --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py process-chroot --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py calendar-utc --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py process-clock-id --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py param-auxv --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-interface-index --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-interface-index-name --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py interface-names --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py interface-names-alloc --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py interface-addresses --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py pause --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py ttyname --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py pty-session --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py termios-exclusive --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py futex --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py clock-set --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py timespec-get --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py realtime-millis --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py ppoll --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py readiness --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py sleep --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py clock-sleep --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py madvise --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py identity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py wall-clock --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py process-cpu-time --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py time-dynamic --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-socket --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-connect --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py preadv2 --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fadvise --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fcntl-flags --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py futimes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py lutimes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py futimesat --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py utimes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py utime --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-bind-getsockname --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py msync --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py sendfile --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-getpeername --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py mincore --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py rusage --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py getgroups --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py mlock --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-listen-accept --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-datagram --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py priority --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py scheduler-priority-bounds --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py sched-rr-interval --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py sched-getaffinity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py sched-setaffinity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py pidfd-open --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py setpriority --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py mremap --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py getitimer --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py readahead --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-socket-options --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-socket-type --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-socket-protocol --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-socket-cookie --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-socket-domain --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py copy-file-range --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py sync-file-range --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-messages --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py network-multimessage --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py memory-vm --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py time-timers --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py getcwd --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py current-dir-name --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py eventfd --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py times --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py session-observation --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py thread-identity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py access --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py accessat --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py truncate --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py process-identity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py process-cwd --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py sync --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py sched-cpu --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py ownership --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py special-nodes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py system-names --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py load-average --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py getentropy --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py create --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py termios-special-codes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py termios-queue --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py terminal-control --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py thread-credentials --target-dir target
        run_in_container python3 compat/crabc-rs/verify_kernel_probes.py fs-credentials --target-dir target
        run_in_container python3 compat/crabc-rs/verify_network_address.py network-address --target-dir target
        run_in_container python3 compat/crabc-rs/verify_network_address.py ipaddr --target-dir target
        run_in_container python3 compat/crabc-rs/verify_network_address.py ipv4-legacy --target-dir target
        run_in_container python3 compat/crabc-rs/verify_network_address.py ipv4-classful --target-dir target
        run_in_container python3 compat/crabc-rs/verify_network_address.py ethernet-address --target-dir target
        run_in_container python3 compat/crabc-rs/verify_network_address.py ethers --target-dir target
        ;;
    abi-probe)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/scripts/probe_aarch64_abi.py "$@"
        refresh_dashboard run_in_container
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
