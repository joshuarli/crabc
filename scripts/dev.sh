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
  allocator --quick|--full|--churn|--soak
                      build/check the pinned mimalloc v3.5.0 C-oracle baseline
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
    local rustix_source_host="${CRABC_RUSTIX_SOURCE_HOST:-$ROOT_DIR/../rustix}"
    local rustybench_source_host="${CRABC_RUSTYBENCH_SOURCE_HOST:-$ROOT_DIR/../rustybench}"
    local -a rustix_mount=()
    local -a rustybench_mount=()
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
    # The bind-mounted checkout can be owned by the host runner while the
    # container queries it as root. Scope Git's ownership exception to this
    # one mount instead of mutating a shared global config.
    local -a docker_args=(
        docker run --rm --init
        --platform "$PLATFORM"
        --workdir /workspace
        --env CARGO_HOME=/opt/cargo
        --env LIBC_TEST_DIR=/opt/libc-test
        --env MUSL_REFERENCE_LIBDIR=/opt/musl-1.2.6/lib
        --env GIT_CONFIG_COUNT=1
        --env GIT_CONFIG_KEY_0=safe.directory
        --env GIT_CONFIG_VALUE_0=/workspace
        --volume "$ROOT_DIR:/workspace"
        --volume "$TARGET_VOLUME:/workspace/target"
        --volume "$CARGO_VOLUME:/opt/cargo"
    )
    if [ -d "$rustix_source_host" ]; then
        docker_args+=("${rustix_mount[@]}")
    fi
    if [ -d "$rustybench_source_host" ]; then
        docker_args+=("${rustybench_mount[@]}")
    fi
    docker_args+=("$IMAGE" "$@")
    "${docker_args[@]}"
}

# Resolver evidence must not inherit Docker's host-derived DNS configuration.
# This private network namespace has only loopback, and Docker writes an
# isolated regular /etc/resolv.conf pointing at the fixture. The Python runner
# verifies that boundary before temporarily installing its three loopback
# nameservers and restores the file before it exits.
run_in_resolver_container() {
    docker run --rm --init \
        --platform "$PLATFORM" \
        --network none \
        --dns 127.0.0.1 \
        --workdir /workspace \
        --env CARGO_HOME=/opt/cargo \
        --env LIBC_TEST_DIR=/opt/libc-test \
        --env MUSL_REFERENCE_LIBDIR=/opt/musl-1.2.6/lib \
        --env CRABC_RESOLVER_NETWORK_ISOLATED=1 \
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
                run_in_container python3 compat/allocator/run.py --quick
                ;;
            --full)
                # This runner builds the complete C-oracle/M4 boundary, runs
                # the recorded 128-cycle M5 lifecycle lane, and reports each
                # reviewed unmet M5 gate without turning absent Rust work into
                # a pass.
                run_in_container python3 compat/allocator/run.py --full
                ;;
            --churn)
                # This bounded lane repeats the existing mixed local,
                # remote-free, mixed owner-exit, and sole-reclamation pthread
                # witnesses under a watchdog; it is not a general allocator pass.
                run_in_container python3 compat/allocator/run.py --churn
                ;;
            --soak)
                # This opt-in larger lane uses the same pointer-private
                # witnesses and a longer watchdog. It is lifecycle stability
                # evidence, not a general allocator pass.
                run_in_container python3 compat/allocator/run.py --soak
                ;;
            *)
                usage >&2
                exit 2
                ;;
        esac
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
        run_in_container cargo build -p crabc-libc --features native-mimalloc-shadow
        # The direct runtime regressions keep the typed post-exit proof and
        # live-owner remote-publication boundaries observable without
        # accidentally selecting the ordinary C allocator artifact. They
        # cover aggregate, source-proved sole mapped-regular, parked-A source
        # remote-free, and the two nominally distinct bounded post-exit B/C/D
        # routes before the C ABI fixture exercises the selected shared object.
        run_in_container cargo test -p crabc-mimalloc \
            --test native_post_exit_lifecycle \
            --test native_sole_post_exit_lifecycle \
            --test native_two_post_exit_lifecycle \
            --test native_three_post_exit_lifecycle \
            --test native_post_exit_registry_reuse \
            --test native_post_exit_with_local_session \
            --test native_live_remote_free \
            --test native_two_live_remote_owners \
            --test runtime_lifecycle_session_post_exit_publisher \
            --test runtime_lifecycle_session_post_exit_mapped_medium_publisher \
            --test runtime_lifecycle_session_post_exit_mapped_medium_requires_publisher \
            --test runtime_lifecycle_session_post_exit_mismatch_publisher \
            -- --test-threads=1
        # These direct tests compile scalar-only registry audits behind their
        # own default-off feature. They establish the detached three-route and
        # live two-owner concurrent high-waters, then prove later epochs reuse
        # those exact stable metadata nodes without exposing a route or client
        # capability.
        run_in_container cargo test -p crabc-mimalloc \
            --features native-runtime-test-audit \
            --test native_post_exit_registry_high_water \
            --test native_live_remote_owner_registry_reuse \
            -- --test-threads=1
        # The next-`munmap` injection is a separately gated direct witness:
        # a failed OS terminal release must retain the opaque B-side route and
        # A's scheduler/admission claim instead of manufacturing completion.
        run_in_container cargo test -p crabc-mimalloc \
            --features native-runtime-test-audit,native-runtime-test-fault \
            --test native_post_exit_failed_os_release \
            -- --test-threads=1
        run_in_container env RUSTC_WRAPPER="/workspace/scripts/rustc_test_host_tool_wrapper.sh" \
            python3 scripts/run_owned_test_suite.py \
            --sysroot target/crabc-sysroot \
            --loader target/debug/libldso.so \
            -- cargo test -q -p crabc-libc --features native-mimalloc-shadow \
            --test allocator \
            --test native_mimalloc_owner_exit \
            --test native_mimalloc_two_owner_exit \
            --test native_mimalloc_three_owner_exit \
            --test native_mimalloc_aggregate_reclaim \
            --test native_mimalloc_owner_exit_realloc \
            --test native_mimalloc_live_remote_free \
            --test native_mimalloc_two_live_remote_owners \
            --test native_mimalloc_initial_remote_free \
            --test native_mimalloc_parallel_local_workers \
            --test native_mimalloc_many_local_allocations \
            --test native_mimalloc_initial_live_local_worker \
            --test native_mimalloc_initial_live_owner_exit \
            --test native_mimalloc_initial_live_parallel_workers \
            --test native_mimalloc_many_owner_exit_allocations \
            --test native_mimalloc_live_remote_owner_exit \
            --test pthread_atfork \
            --test pthread_create_join_tls_regression \
            -- --test-threads=1
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
