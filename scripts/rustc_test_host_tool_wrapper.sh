#!/usr/bin/env bash
# Keep host-side Cargo tools loadable while the native runtime uses
# `-Ztls-model=initial-exec`.
#
# The supported Docker path is native Linux/AArch64, so Cargo applies the
# target rustflags to proc-macros and build scripts too. Those tools are loaded
# dynamically by Cargo; forcing initial-exec onto a proc-macro such as
# `rustversion` prevents its build-script client from loading it. This wrapper
# is test-only and removes exactly that one flag for host tools. Target runtime
# crates still receive the configured model, which the sealed sysroot audits.
# Remove this once rustc/Cargo can scope TLS-model rustflags to target runtime
# crates without applying them to dynamically loaded host tools.

set -euo pipefail

rustc="$1"
shift

host_tool=0
previous=""
for argument in "$@"; do
    case "$argument" in
        --crate-name=build_script_build|--crate-type=proc-macro)
            host_tool=1
            ;;
        --crate-name|--crate-type)
            previous="$argument"
            continue
            ;;
        build_script_build)
            if [[ "$previous" == "--crate-name" ]]; then
                host_tool=1
            fi
            ;;
        proc-macro)
            if [[ "$previous" == "--crate-type" ]]; then
                host_tool=1
            fi
            ;;
    esac
    previous=""
done

if [[ "$host_tool" == 0 ]]; then
    exec "$rustc" "$@"
fi

filtered=()
for argument in "$@"; do
    if [[ "$argument" != "-Ztls-model=initial-exec" ]]; then
        filtered+=("$argument")
    fi
done
exec "$rustc" "${filtered[@]}"
