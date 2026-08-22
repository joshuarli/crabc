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
  os-test [options]   run the pinned POSIX os-test M6 profile against musl and crabc
  pthread-stress [options] run bounded pthread/TLS stress against musl and crabc
  static-pthread-tls [options] run conventional static libc.a pthread/TLS lifecycle against musl and crabc
  signal-process [case] run the isolated M6 signal/process comparison workload
  resolver-network [options] run the deterministic local M6 resolver/network workload
  ldso [options]      run the synthetic M7 loader differential suite
  corpus [options]    run the pinned Alpine AArch64 package corpus (Tier A by default)
  rust-std [options]  run the M9 stock Rust std musl-vs-crabc differential fixture
  rust-std-dependent  run the M10.5 dependency-bearing stock Rust application
  lto [options]       run the M10 AArch64 static/build-std LTO evidence matrix
  crabc-rs            run the M4 native Rust facade architecture/evidence gate
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
    local -a rustix_mount=()
    if [ -d "$rustix_source_host" ]; then
        # The comparison harness treats Rustix only as a pinned test oracle.
        # Keep a user checkout read-only and expose its container path through
        # an explicit variable; production Cargo manifests never name it.
        rustix_mount=(
            --env CRABC_RUSTIX_SOURCE=/opt/rustix
            --volume "$rustix_source_host:/opt/rustix:ro"
        )
    fi
    docker run --rm --init \
        --platform "$PLATFORM" \
        --workdir /workspace \
        --env CARGO_HOME=/opt/cargo \
        --env LIBC_TEST_DIR=/opt/libc-test \
        --env MUSL_REFERENCE_LIBDIR=/opt/musl-1.2.6/lib \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/opt/cargo" \
        "${rustix_mount[@]}" \
        "$IMAGE" "$@"
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
    os-test)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/os-test/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    pthread-stress)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/pthread-stress/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    static-pthread-tls)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/static-pthread-tls/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    signal-process)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/signal-process/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    resolver-network)
        ensure_image
        run_in_resolver_container cargo build --workspace
        run_in_resolver_container python3 scripts/collect_environment.py
        run_in_resolver_container python3 compat/resolver-network/run.py "$@"
        run_in_resolver_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    ldso)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/ldso/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    corpus)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/corpus/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    rust-std)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/rust-std/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    rust-std-dependent)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/rust-std/run.py \
            --fixture compat/rust-std/dependent-fixture/src/main.rs \
            --report compat/reports/rust-std-dependent/latest.json "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    lto)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/lto/run.py "$@"
        run_in_container python3 scripts/generate_compatibility_dashboard.py
        ;;
    crabc-rs)
        ensure_image
        if [ "$#" -ne 0 ]; then
            usage >&2
            exit 2
        fi
        # M9 retains M0-M8 and validates the complete, hash-pinned semantic
        # export ledger. M8 adds three deliberately narrow semantic seams:
        # direct AArch64 fenv state, shared byte-oriented fnmatch, and a
        # private-runtime CFile memory stream. Keep all native and C-regression
        # evidence together so a later facade change cannot add a C/errno hop.
        # Keep no-std, native, source-compatibility, and assembly evidence
        # together so a later facade change cannot add a C/errno hop.
        run_in_container cargo check -p crabc-rs --no-default-features
        run_in_container cargo check -p crabc-rs --no-default-features --features alloc
        run_in_container cargo check -p crabc-rs --no-default-features --features runtime-thread
        run_in_container cargo check -p crabc-rs --no-default-features --features runtime-thread-alloc
        run_in_container cargo check -p crabc-rs --no-default-features --features runtime-stdio
        run_in_container cargo test -p crabc-core --lib
        run_in_container cargo test -p crabc-rs --test m0_direct --test m1_foundation --test m2_filesystem --test m3_core_os --test m4_process_system --test m5_fs_io --test m5_event_time --test m5_file_mapping --test m5_descriptor_stdio --test m6_signal_process --test m7_sync --test m7_resolver_netdb --test m8_fenv --test m8_fnmatch --test m10_text --test m10_text_stateful --test m10_ctype --test m10_format --test m10_number --test m10_numeric_legacy --test m10_random --test m10_memory_special --test m10_memory_vm --test m10_fs_metadata --test m10_statx --test m10_positioned --test m10_vectored --test m10_positioned_vectored --test m10_preadv2 --test m10_directory --test m10_memfd --test m10_fallocate --test m10_fadvise --test m10_sendfile --test m10_syncfs --test m10_ppoll --test m10_readiness --test m10_msync --test m10_mincore --test m10_mlock --test m10_mremap --test m10_madvise --test m10_identity --test m10_rusage --test m10_getgroups --test m10_priority --test m10_setpriority --test m10_rlimit --test m10_sleep --test m10_clock_nanosleep --test m10_time --test m10_time_dynamic --test m10_getitimer --test m10_time_timers --test m10_calendar_utc --test m10_readahead --test m10_copy_file_range --test m10_sync_file_range --test m10_network_address --test m10_ethernet_address --test m10_ethers --test m10_network_socket --test m10_network_socket_options --test m10_network_messages --test m10_network_mmsg --test m10_network_connect --test m10_network_bind_getsockname --test m10_network_getpeername --test m10_network_listen_accept --test m10_network_datagram --test m10_descriptor --test m10_subsumed
        run_in_container cargo test -p crabc-rs --test m8_cfile --features runtime-stdio
        run_in_container cargo test -p crabc-rs --test m10_directory_position
        run_in_container cargo test -p crabc-rs --test m10_network_socket_type
        run_in_container cargo test -p crabc-rs --test m10_network_socket_protocol
        run_in_container cargo test -p crabc-rs --test m10_network_socket_cookie
        run_in_container cargo test -p crabc-rs --test m10_network_socket_domain
        run_in_container cargo test -p crabc-rs --test m10_network_socket_acceptconn
        run_in_container cargo test -p crabc-rs --test m10_network_socket_oobinline
        run_in_container cargo test -p crabc-rs --test m10_network_socket_broadcast
        run_in_container cargo test -p crabc-rs --test m10_pipe_tee
        run_in_container cargo test -p crabc-rs --test m10_descriptor
        run_in_container cargo test -p crabc-rs --test m10_readiness
        run_in_container cargo test -p crabc-rs --test m10_pipe_size
        run_in_container cargo test -p crabc-rs --test m10_fcntl_seals
        run_in_container cargo test -p crabc-rs --test m10_fcntl_getlk
        run_in_container cargo test -p crabc-rs --test m10_getcwd --test m10_current_dir_name --test m10_eventfd --test m10_times
        run_in_container cargo test -p crabc-rs --test m10_setpriority
        run_in_container cargo test -p crabc-rs --test m10_scheduler_priority_bounds
        run_in_container cargo test -p crabc-rs --test m10_sched_rr_interval
        run_in_container cargo test -p crabc-rs --test m10_sched_getaffinity
        run_in_container cargo test -p crabc-rs --test m10_sched_setaffinity
        run_in_container cargo test -p crabc-rs --test m10_pidfd_open
        run_in_container cargo test -p crabc-rs --test m10_session_observation --test m10_thread_identity
        run_in_container cargo test -p crabc-rs --test m10_access --test m10_truncate --test m10_process_identity
        run_in_container cargo test -p crabc-rs --test m10_accessat
        run_in_container cargo test -p crabc-rs --test m10_process_cwd --test m10_fs_canonicalize --test m10_fs_tempdir --test m10_sync
        run_in_container cargo test -p crabc-rs --test m10_process_chroot
        run_in_container cargo test -p crabc-rs --test m10_process_clock_id --test m10_time_settime --test m10_time_timespec_get --test m10_param_auxv
        run_in_container cargo test -p crabc-rs --test m10_network_interface_index --test m10_network_interface_index_name --test m10_interface_names --test m10_interface_addresses
        run_in_container cargo test -p crabc-rs --test m10_network_ipaddr --test m10_ipv4_legacy --test m10_pause --test m10_ttyname --test m10_termios_exclusive --test m10_termios_special_codes --test m10_termios_queue --test m10_terminal_control --test m10_futex --test m10_thread_credentials --test m10_fs_credentials
        run_in_container cargo test -p crabc-rs --test m10_sched_cpu
        run_in_container cargo test -p crabc-rs --test m10_ownership
        run_in_container cargo test -p crabc-rs --test m10_special_nodes
        run_in_container cargo test -p crabc-rs --test m10_system_names
        run_in_container cargo test -p crabc-rs --test m10_load_average
        run_in_container cargo test -p crabc-rs --test m10_process_cpu_time
        run_in_container cargo test -p crabc-rs --test m10_getentropy --test m10_create
        run_in_container cargo test -p crabc-rs --test m10_fcntl_flags
        run_in_container cargo test -p crabc-rs --test m10_futimes
        run_in_container cargo test -p crabc-rs --test m10_lutimes
        run_in_container cargo test -p crabc-rs --test m10_futimesat
        run_in_container cargo test -p crabc-rs --test m10_utimes
        run_in_container cargo test -p crabc-rs --test m10_utime
        run_in_container cargo build -p crabc-rs --example m10_ipv4_classful_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_ethernet_address_direct_probe --example m10_ethers_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m0_direct_probe --example m2_direct_probe --example m3_direct_probe --example m4_direct_probe --example m5_direct_probe --example m6_direct_probe --example m7_sync_direct_probe --example m8_fenv_direct_probe --example m8_fnmatch_direct_probe --example m10_text_direct_probe --example m10_text_stateful_direct_probe --example m10_ctype_direct_probe --example m10_format_direct_probe --example m10_number_direct_probe --example m10_numeric_legacy_direct_probe --example m10_random_direct_probe --example m10_memory_special_direct_probe --example m10_fs_metadata_direct_probe --example m10_statx_direct_probe --example m10_positioned_direct_probe --example m10_vectored_direct_probe --example m10_positioned_vectored_direct_probe --example m10_preadv2_direct_probe --example m10_directory_direct_probe --example m10_memfd_direct_probe --example m10_fallocate_direct_probe --example m10_fadvise_direct_probe --example m10_sendfile_direct_probe --example m10_syncfs_direct_probe --example m10_ppoll_direct_probe --example m10_readiness_direct_probe --example m10_msync_direct_probe --example m10_mincore_direct_probe --example m10_mlock_direct_probe --example m10_mremap_direct_probe --example m10_madvise_direct_probe --example m10_identity_direct_probe --example m10_rusage_direct_probe --example m10_getgroups_direct_probe --example m10_priority_direct_probe --example m10_setpriority_direct_probe --example m10_rlimit_direct_probe --example m10_rlimit_for_direct_probe --example m10_sleep_direct_probe --example m10_clock_nanosleep_direct_probe --example m10_time_direct_probe --example m10_time_dynamic_direct_probe --example m10_getitimer_direct_probe --example m10_readahead_direct_probe --example m10_copy_file_range_direct_probe --example m10_sync_file_range_direct_probe --example m10_network_address_direct_probe --example m10_network_ipaddr_direct_probe --example m10_ipv4_legacy_direct_probe --example m10_network_socket_direct_probe --example m10_network_socket_options_direct_probe --example m10_network_messages_direct_probe --example m10_network_connect_direct_probe --example m10_network_bind_getsockname_direct_probe --example m10_network_getpeername_direct_probe --example m10_network_listen_accept_direct_probe --example m10_network_datagram_direct_probe --example m10_descriptor_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_memory_vm_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_mmsg_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_time_timers_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_calendar_utc_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_process_limits_umask_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_process_chroot_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_fs_canonicalize_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_fs_tempdir_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_process_clock_id_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_time_settime_direct_probe --example m10_time_timespec_get_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_param_auxv_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_interface_index_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_interface_index_name_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_interface_names_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_interface_names_alloc_direct_probe --release --no-default-features --features alloc
        run_in_container cargo build -p crabc-rs --example m10_interface_addresses_direct_probe --release --no-default-features --features alloc
        run_in_container cargo build -p crabc-rs --example m10_pause_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_ttyname_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_termios_exclusive_direct_probe --example m10_termios_special_codes_direct_probe --example m10_termios_queue_direct_probe --example m10_terminal_control_direct_probe --example m10_futex_direct_probe --example m10_thread_credentials_direct_probe --example m10_fs_credentials_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_readiness_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_setpriority_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_scheduler_priority_bounds_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_sched_rr_interval_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_sched_getaffinity_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_sched_setaffinity_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_pidfd_open_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_directory_position_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_socket_type_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_socket_protocol_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_socket_cookie_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_socket_domain_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_socket_acceptconn_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_socket_oobinline_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_network_socket_broadcast_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_pipe_tee_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_pipe_size_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_fcntl_seals_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_fcntl_add_seals_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_fcntl_getlk_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_getcwd_direct_probe --example m10_current_dir_name_direct_probe --example m10_eventfd_direct_probe --example m10_times_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_session_observation_direct_probe --example m10_thread_identity_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_access_direct_probe --example m10_truncate_direct_probe --example m10_process_identity_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_accessat_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_process_cwd_direct_probe --example m10_sync_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_sched_cpu_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_ownership_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_special_nodes_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_system_names_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_load_average_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_process_cpu_time_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_getentropy_direct_probe --example m10_create_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_fcntl_flags_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_futimes_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_lutimes_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_futimesat_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_utimes_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m10_utime_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m7_resolver_direct_probe --release --no-default-features --features alloc
        run_in_container cargo build -p crabc-rs --example m7_loader_runtime_probe --release --no-default-features --features runtime-loader
        run_in_container cargo build -p crabc-rs --example m7_runtime_thread_probe --release --no-default-features --features runtime-thread
        run_in_container cargo build -p crabc-rs --example m8_cfile_direct_probe --release --no-default-features --features runtime-stdio
        run_in_container cargo build -p crabc-libc
        run_in_container cargo test -p crabc --test m7_loader_runtime --test m7_runtime_thread --test m8_cfile_runtime --test m8_fclose_lifecycle --test fenv --test fnmatch --test iconv --test iconv_error_progress --test stdio_full --test m4_stdio_exports --test m4_stdio_extensions_exports --test m4_cookie_stream_exports --test m4_wmemstream_exports --test m4_select --test m4_break_exports --test m4_memory_vm_exports --test m4_host_process_exports --test m4_filesystem_paths_exports
        run_in_container python3 compat/rustix/run.py --check
        run_in_container python3 -m unittest discover -s compat/rustix/tests -p 'test_*.py'
        run_in_container python3 -m unittest discover -s compat/crabc-rs/tests -p 'test_*.py'
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/m1_foundation.rs
        run_in_container python3 compat/crabc-rs/verify_m0.py --target-dir target
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/m2_statat.rs \
            --fixture compat/rustix/source/m2_links.rs \
            --fixture compat/rustix/source/m2_metadata.rs \
            --fixture compat/rustix/source/m2_raw_dir.rs \
            --fixture compat/rustix/source/m2_locks.rs \
            --fixture compat/rustix/source/m2_openat2.rs \
            --fixture compat/rustix/source/m2_xattr.rs
        run_in_container python3 compat/crabc-rs/verify_m2.py --target-dir target
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/m3_time_pipe_random.rs \
            --fixture compat/rustix/source/m3_event.rs \
            --fixture compat/rustix/source/m3_net_mm.rs
        run_in_container python3 compat/crabc-rs/verify_m3.py --target-dir target
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/m4_process_system.rs
        run_in_container python3 compat/crabc-rs/verify_m4.py --target-dir target
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/m6_process.rs
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/m10_time_dynamic.rs
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/m10_accessat.rs \
            --fixture compat/rustix/source/m10_sched_getaffinity.rs \
            --fixture compat/rustix/source/m10_pidfd_open.rs \
            --fixture compat/rustix/source/m10_socket_type.rs \
            --fixture compat/rustix/source/m10_socket_cookie.rs \
            --fixture compat/rustix/source/m10_socket_domain.rs \
            --fixture compat/rustix/source/m10_socket_acceptconn.rs \
            --fixture compat/rustix/source/m10_socket_oobinline.rs \
            --fixture compat/rustix/source/m10_socket_broadcast.rs \
            --fixture compat/rustix/source/m10_pipe_tee.rs \
            --fixture compat/rustix/source/m10_pipe_splice.rs \
            --fixture compat/rustix/source/m10_readiness.rs \
            --fixture compat/rustix/source/m10_pipe_size.rs \
            --fixture compat/rustix/source/m10_fcntl_seals.rs \
            --fixture compat/rustix/source/m10_fcntl_add_seals.rs \
            --fixture compat/rustix/source/m10_fcntl_getlk.rs \
            --fixture compat/rustix/source/m10_socket_protocol.rs \
            --fixture compat/rustix/source/m10_memory_vm.rs \
            --fixture compat/rustix/source/m10_process_chroot.rs \
            --fixture compat/rustix/source/m10_process_umask.rs \
            --fixture compat/rustix/source/m10_process_setrlimit.rs \
            --fixture compat/rustix/source/m10_posix_fallocate.rs \
            --fixture compat/rustix/source/m10_time_settime.rs \
            --fixture compat/rustix/source/m10_param_auxv.rs \
            --fixture compat/rustix/source/m10_network_interface_index.rs \
            --fixture compat/rustix/source/m10_network_interface_index_name.rs \
            --fixture compat/rustix/source/m10_pause.rs \
            --fixture compat/rustix/source/m10_ttyname.rs \
            --fixture compat/rustix/source/m10_termios_exclusive.rs \
            --fixture compat/rustix/source/m10_futex.rs \
            --fixture compat/rustix/source/m10_network_ipaddr.rs \
            --fixture compat/rustix/source/m10_termios_special_codes.rs \
            --fixture compat/rustix/source/m10_termios_queue.rs \
            --fixture compat/rustix/source/m10_thread_credentials.rs \
            --fixture compat/rustix/source/m10_fs_tempdir.rs
        run_in_container python3 compat/rustix/run.py source-compare --timeout 60 \
            --fixture compat/rustix/source/m5_fs_io.rs \
            --fixture compat/rustix/source/m5_event_time.rs \
            --fixture compat/rustix/source/m5_file_mapping.rs \
            --fixture compat/rustix/source/m5_descriptor_stdio.rs
        run_in_container python3 compat/crabc-rs/verify_m5.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m6.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m7.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m7_resolver.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m7_loader.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m7_runtime_thread.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m8_fenv.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m8_fnmatch.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m8_cfile.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_text.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_text_stateful.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_ctype.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_memory_special.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_format.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_number.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_numeric_legacy.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_random.py --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fs-metadata --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fs-canonicalize --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fs-tempdir --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py positioned --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py vectored --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py positioned-vectored --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py directory --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py directory-position --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py pipe-tee --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py descriptor --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py pipe-size --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fcntl-seals --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fcntl-add-seals --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fcntl-getlk --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py memfd --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fallocate --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py syncfs --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py rlimit --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py rlimit-for --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py process-limits-umask --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py process-chroot --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py calendar-utc --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py process-clock-id --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py param-auxv --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-interface-index --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-interface-index-name --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py interface-names --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py interface-names-alloc --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py interface-addresses --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py pause --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py ttyname --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py termios-exclusive --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py futex --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py clock-set --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py timespec-get --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py realtime-millis --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py ppoll --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py readiness --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py sleep --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py clock-sleep --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py madvise --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py identity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py wall-clock --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py process-cpu-time --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py time-dynamic --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-socket --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-connect --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py preadv2 --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fadvise --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fcntl-flags --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py futimes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py lutimes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py futimesat --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py utimes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py utime --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-bind-getsockname --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py msync --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py sendfile --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-getpeername --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py mincore --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py rusage --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py getgroups --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py mlock --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-listen-accept --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-datagram --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py priority --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py scheduler-priority-bounds --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py sched-rr-interval --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py sched-getaffinity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py sched-setaffinity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py pidfd-open --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py setpriority --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py mremap --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py getitimer --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py readahead --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-socket-options --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-socket-type --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-socket-protocol --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-socket-cookie --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-socket-domain --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py copy-file-range --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py sync-file-range --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-messages --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py network-multimessage --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py memory-vm --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py time-timers --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py getcwd --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py current-dir-name --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py eventfd --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py times --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py session-observation --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py thread-identity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py access --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py accessat --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py truncate --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py process-identity --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py process-cwd --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py sync --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py sched-cpu --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py ownership --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py special-nodes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py system-names --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py load-average --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py getentropy --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py create --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py termios-special-codes --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py termios-queue --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py terminal-control --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py thread-credentials --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_kernel.py fs-credentials --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_network_address.py network-address --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_network_address.py ipaddr --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_network_address.py ipv4-legacy --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_network_address.py ipv4-classful --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_network_address.py ethernet-address --target-dir target
        run_in_container python3 compat/crabc-rs/verify_m10_network_address.py ethers --target-dir target
        ;;
    abi-probe)
        ensure_image
        run_in_container cargo build --workspace
        run_in_container python3 scripts/collect_environment.py
        run_in_container python3 compat/scripts/probe_aarch64_abi.py "$@"
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
