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
        run_in_container cargo test -p crabc-rs --test m0_direct --test m1_foundation --test m2_filesystem --test m3_core_os --test m4_process_system --test m5_fs_io --test m5_event_time --test m5_file_mapping --test m5_descriptor_stdio --test m6_signal_process --test m7_sync --test m7_resolver_netdb --test m8_fenv --test m8_fnmatch
        run_in_container cargo test -p crabc-rs --test m8_cfile --features runtime-stdio
        run_in_container cargo build -p crabc-rs --example m0_direct_probe --example m2_direct_probe --example m3_direct_probe --example m4_direct_probe --example m5_direct_probe --example m6_direct_probe --example m7_sync_direct_probe --example m8_fenv_direct_probe --example m8_fnmatch_direct_probe --release --no-default-features
        run_in_container cargo build -p crabc-rs --example m7_resolver_direct_probe --release --no-default-features --features alloc
        run_in_container cargo build -p crabc-rs --example m7_loader_runtime_probe --release --no-default-features --features runtime-loader
        run_in_container cargo build -p crabc-rs --example m7_runtime_thread_probe --release --no-default-features --features runtime-thread
        run_in_container cargo build -p crabc-rs --example m8_cfile_direct_probe --release --no-default-features --features runtime-stdio
        run_in_container cargo test -p crabc --test m7_loader_runtime --test m7_runtime_thread --test m8_cfile_runtime --test m8_fclose_lifecycle --test fenv --test fnmatch --test stdio_full --test m4_stdio_exports --test m4_stdio_extensions_exports --test m4_cookie_stream_exports --test m4_wmemstream_exports
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
