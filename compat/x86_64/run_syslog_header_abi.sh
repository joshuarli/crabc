#!/usr/bin/env bash
# libc.headers-layouts: direct syslog profiles, macro forms, C linkage, and
# GNU/BSD SYSLOG_NAMES consumers against pinned musl 1.2.6. Compile-only.
set -euo pipefail
export LC_ALL=C
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PROBE="$ROOT_DIR/compat/x86_64/syslog_header_probe.c"
readonly MUSL=/opt/musl-1.2.6/include
fail() { printf 'ERROR: syslog header ABI: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 0 ] || fail "takes no arguments"
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || fail "requires native Linux/x86-64"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-syslog-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
run_cc() {
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$@"
}
builtin="$(run_cc /usr/bin/gcc -print-file-name=include)"
for language in c c++; do
    if [ "$language" = c ]; then
        language_args=(-x c -std=c11)
    else
        language_args=(-x c++ -std=c++17 -nostdinc++)
    fi
    for profile in strict posix xopen gnu bsd lfs; do
        feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -U_LARGEFILE64_SOURCE)
        case "$profile" in
            strict) ;;
            posix) feature_args+=(-D_POSIX_C_SOURCE=200809L) ;;
            xopen) feature_args+=(-D_XOPEN_SOURCE=700) ;;
            gnu) feature_args+=(-D_GNU_SOURCE) ;;
            bsd) feature_args+=(-D_BSD_SOURCE) ;;
            lfs) feature_args+=(-D_LARGEFILE64_SOURCE) ;;
        esac
        for header in syslog.h sys/syslog.h; do
            for names in absent requested; do
                names_args=()
                [ "$names" = absent ] || names_args=(-DSYSLOG_NAMES)
                for tree in reference candidate; do
                    if [ "$tree" = reference ]; then
                        compiler=/usr/local/bin/crabc-x86_64-musl-gcc
                        root="$MUSL"
                    else
                        compiler=/usr/bin/gcc
                        root="$ROOT_DIR/include"
                    fi
                    args=("${language_args[@]}" "${feature_args[@]}" "${names_args[@]}"
                        -nostdinc -I "$root" -isystem "$builtin")
                    if ! run_cc "$compiler" "${args[@]}" "-DCRABC_SYSLOG_HEADER=<$header>" \
                        -H -c "$PROBE" -o "$work_dir/$tree.o" 2> "$work_dir/trace"; then
                        sed -n '1,60p' "$work_dir/trace" >&2
                        fail "$language/$profile/$header/$names/$tree consumer failed"
                    fi
                    while IFS= read -r path; do
                        case "$path" in
                            "$root"/*|"$builtin"/*) ;;
                            *) fail "include escaped declared roots: $path" ;;
                        esac
                    done < <(sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$work_dir/trace")
                    grep -Fq "$root/$header" "$work_dir/trace" || fail "direct header missing"
                    for symbol in closelog openlog setlogmask syslog; do
                        nm --undefined-only "$work_dir/$tree.o" | grep -Eq "[[:space:]]${symbol}$" ||
                            fail "$tree/$language lost C linkage for $symbol"
                    done
                    run_cc "$compiler" "${args[@]}" -E -dM -include "$header" - < /dev/null |
                        awk '/^#define (LOG_|_PATH_LOG|INTERNAL_|prioritynames|facilitynames)/' |
                        sort > "$work_dir/$tree.macros"
                    if [ "$names" = absent ] || { [ "$profile" != gnu ] && [ "$profile" != bsd ]; }; then
                        if run_cc "$compiler" "${args[@]}" "-DCRABC_SYSLOG_HEADER=<$header>" \
                            -DCRABC_REQUIRE_NAMES_HIDDEN -fsyntax-only "$PROBE" 2> "$work_dir/hidden"; then
                            fail "$tree/$profile leaked CODE"
                        fi
                        grep -q CODE "$work_dir/hidden" || fail "hidden-name failure omitted CODE"
                    fi
                done
                diff -u "$work_dir/reference.macros" "$work_dir/candidate.macros" ||
                    fail "$language/$profile/$header/$names macro form mismatch"
            done
        done
    done
done
printf 'x86 syslog header ABI: PASS (12 C/C++ profiles, two paths, SYSLOG_NAMES present/absent)\n'
