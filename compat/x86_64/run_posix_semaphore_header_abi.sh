#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ <semaphore.h> ABI gate.
#
# Pinned musl 1.2.6 owns the public declaration, volatile 32-byte sem_t, and
# C++ C-linkage contract.  The selected static archive proves only the
# unnamed no-timeout subset separately; this header gate intentionally keeps
# named and timed declarations visible without claiming their runtime paths.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/posix_semaphore_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/posix_semaphore_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 POSIX semaphore headers: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_probe() {
    local profile="$1" variant="$2" language="$3" output="$4"
    local -a language_args=( -std=c11 )
    local -a include_args=()
    if [ "$language" = cxx ]; then
        language_args=( -std=c++17 -x c++ -fno-exceptions -fno-rtti -nostdinc++ )
    fi
    if [ "$variant" = project ]; then
        include_args=( -I "$ROOT_DIR/include" )
    fi
    "$ORACLE_CC" "${language_args[@]}" -U_GNU_SOURCE -D"$profile" \
        "${include_args[@]}" -c \
        "$([ "$language" = c ] && printf '%s' "$C_PROBE" || printf '%s' "$CXX_PROBE")" \
        -o "$output"
}

require_native_linux_x86_64
for tool in grep nm sed; do command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-posix-semaphore-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/project-header-trace"
oracle_cxx="$work_dir/oracle-cxx.o"
project_cxx="$work_dir/project-cxx.o"

# semaphore.h is unconditional in musl's C and C++ namespaces.  Compile both
# strict and POSIX profiles to prevent a latent feature-selector dependency.
for profile in __STRICT_ANSI__ _POSIX_C_SOURCE=200809L; do
    for language in c cxx; do
        compile_probe "$profile" oracle "$language" \
            "$work_dir/oracle-${profile//[^[:alnum:]]/_}-${language}.o"
        compile_probe "$profile" project "$language" \
            "$work_dir/project-${profile//[^[:alnum:]]/_}-${language}.o"
    done
done

if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$C_PROBE" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project POSIX semaphore C header contract drifted"
fi
for header in semaphore.h fcntl.h features.h bits/alltypes.h time.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "C probe did not use the project <$header>"
done

compile_probe _POSIX_C_SOURCE=200809L oracle cxx "$oracle_cxx"
compile_probe _POSIX_C_SOURCE=200809L project cxx "$project_cxx"
for object in "$oracle_cxx" "$project_cxx"; do
    undefined="$(nm --undefined-only "$object")"
    for symbol in sem_close sem_destroy sem_getvalue sem_init sem_open sem_post \
        sem_timedwait sem_trywait sem_unlink sem_wait; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" \
            || fail "C++ probe does not retain C linkage for ${symbol}"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*sem_(close|destroy|getvalue|init|open|post|timedwait|trywait|unlink|wait)'; then
        fail "C++ probe retained a mangled POSIX semaphore reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ POSIX semaphore headers: PASS\n'
