#!/usr/bin/env bash
# Installed POSIX AIO behavior against pinned musl 1.2.6.
#
# One installed-header C object is linked by pinned musl, static/static-PIE,
# and dynamic PIE/non-PIE products.  The latter are exercised by both the
# kernel interpreter path and the installed interpreter directly.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_aio_probe.c"
readonly BEHAVIOR_PROBE="$ROOT/compat/x86_64/owned_aio_behavior_probe.c"
readonly FD_REUSE_PROBE="$ROOT/compat/x86_64/owned_aio_fd_reuse_probe.c"
readonly LIO_CREATE_FAILURE_PROBE="$ROOT/compat/x86_64/owned_aio_lio_create_failure_probe.c"
readonly SUSPEND_WAKE_PROBE="$ROOT/compat/x86_64/owned_aio_suspend_wake_probe.c"
readonly CANCEL_DEFECT_PROBE="$ROOT/compat/x86_64/owned_aio_cancel_defect_probe.c"
readonly CANCEL_CURSOR_PROBE="$ROOT/compat/x86_64/owned_aio_cancel_cursor_probe.c"
readonly SUBMIT_CANCEL_PROBE="$ROOT/compat/x86_64/owned_aio_submit_cancel_probe.c"
readonly FRESH_SIGNAL_PROBE="$ROOT/compat/x86_64/owned_aio_fresh_signal_probe.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
# Queue cleanup races descriptor reuse after terminal aiocb publication. A
# repeated bounded witness makes that source window observable without
# turning a successful scheduling outcome into a false oracle mismatch.
readonly FD_REUSE_ATTEMPTS=512

usage() {
	printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
	exit 2
}

fail() {
	printf 'owned aio: %s\n' "$*" >&2
	exit 1
}

static_product=''
dynamic_product=''
supplied_static=0
supplied_dynamic=0
while [ "$#" -gt 0 ]; do
	case "$1" in
		--static-sysroot)
			[ "$#" -ge 2 ] && [ "$supplied_static" -eq 0 ] && [ -n "$2" ] || usage
			case "$2" in -*) usage ;; esac
			static_product="$(realpath -e -- "$2")"
			supplied_static=1
			shift 2
			;;
		-*|'') usage ;;
		*)
			[ "$supplied_dynamic" -eq 0 ] || usage
			dynamic_product="$(realpath -e -- "$1")"
			supplied_dynamic=1
			shift
			;;
	esac
done

python3 -B - "$ROOT" "${TMPDIR:-}" "$static_product" "$dynamic_product" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned aio TMPDIR must be a physical checkout .work directory')
for raw, family in ((sys.argv[3], 'static'), (sys.argv[4], 'dynamic')):
    if raw:
        product = Path(raw)
        if not product.is_dir() or not product.is_relative_to(root / '.work'):
            raise SystemExit(f'owned aio {family} product must be a checkout .work directory')
PY

readonly WORK="$(mktemp -d "$TMPDIR/owned-aio.XXXXXX")"
chmod a+rx "$WORK"
printf 'owned aio evidence: %s\n' "$WORK"

validate_product() {
	local product="$1" family="$2"
	python3 -B - "$ROOT" "$product" "$family" <<'PY'
from pathlib import Path
import sys

root, product, family = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import ProductEvidenceError, _validate_dynamic_product, _validate_static_product
try:
    (_validate_static_product if family == 'static' else _validate_dynamic_product)(product)
except ProductEvidenceError as error:
    raise SystemExit(f'owned aio {family} product is invalid: {error}') from error
PY
}

validate_link() {
	local product="$1" object="$2" executable="$3" receipt="$4" mode="$5"
	python3 -B - "$ROOT" "$product" "$object" "$executable" "$receipt" "$mode" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import ProductEvidenceError, validate_link
try:
    validate_link(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6])
except ProductEvidenceError as error:
    raise SystemExit(f'owned aio sealed link evidence: {error}') from error
PY
}

assert_symbols() {
	local artifact="$1" kind="$2" output="$3" symbol count
	if [ "$kind" = static ]; then
		nm -g --defined-only "$artifact" >"$output"
		for symbol in aio_read aio_write aio_error aio_return aio_cancel aio_suspend aio_fsync lio_listio; do
			count="$(awk -v name="$symbol" '$2 == "T" && $3 == name { count++ } END { print count + 0 }' "$output")"
			[ "$count" -eq 1 ] || fail "static archive does not provide exactly one strong ${symbol}"
		done
	else
		readelf --dyn-syms -W "$artifact" >"$output"
		for symbol in aio_read aio_write aio_error aio_return aio_cancel aio_suspend aio_fsync lio_listio; do
			count="$(awk -v name="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$output")"
			[ "$count" -eq 1 ] || fail "shared libc does not provide exactly one global-default ${symbol}"
		done
	fi
}

prepare_root() {
	local root="$1"
	mkdir -p "$root/state" "$root/dev"
	[ -e "$root/dev/null" ] || mknod "$root/dev/null" c 1 3
}

run_capture() {
	local output="$1" status=0
	shift
	timeout 30 env -i PATH="$PATH" "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
	printf '%s\n' "$status" >"${output%.stdout}.status"
	[ "$status" -eq 0 ] || fail "expected success, got ${status}: $*"
}

# Capture the source-known descriptor-incarnation race without conflating its
# raw transcript with a normal pinned-musl behavior oracle. A scheduling run
# may either complete all attempts or reach the stale positioned-I/O witness;
# both transcripts are preserved, while any other failure is rejected.
run_fd_reuse_source_observation() {
	local output="$1" status=0
	shift
	timeout 30 env -i PATH="$PATH" "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
	printf '%s\n' "$status" >"${output%.stdout}.status"
	case "$status" in
		0)
			grep -Fxq 'fd-reuse-regular-to-pipe=ok' "$output" ||
				fail "pinned musl fd-reuse success transcript is incomplete"
			;;
		1)
			grep -Eq '^fd-reuse-failure .*pipe-submit=0 .*pipe-error=29 .*pipe-return=-1 ' "${output%.stdout}.stderr" ||
				fail "pinned musl fd-reuse failure was not the stale seekable-queue ESPIPE witness"
			;;
		*) fail "pinned musl fd-reuse probe exited ${status}: $*" ;;
	esac
}

run_fd_reuse_owned() {
	local output="$1"
	shift
	run_capture "$output" "$@"
	grep -Fxq 'fd-reuse-regular-to-pipe=ok' "$output" ||
		fail "owned fd-reuse product did not complete its detached-queue witness"
}

# This is intentionally candidate-only. The separate direct-inclusion source
# witness records the exact musl restore-with-q-locked order; this public
# product workload only requires that a finite fresh-descriptor signal/close
# campaign never leaves its handler pending.
run_fresh_signal_owned() {
	local output="$1"
	shift
	run_capture "$output" "$@"
	grep -Fxq 'fresh-signal-handler-close-pending=not-observed' "$output" ||
		fail "owned fresh-queue signal handler close remained pending"
}

compare_transcript() {
	local oracle="$1" candidate="$2"
	for suffix in stdout stderr status; do
		cmp "$WORK/$oracle.$suffix" "$WORK/$candidate.$suffix" ||
			fail "${suffix} differs from pinned musl for ${candidate}"
	done
}

compare_oracle() {
	compare_transcript oracle "$1"
}

# The two source cancellation cases are deliberately expected to time out.
# Keep their raw status/logs beside the normal oracle transcript so the owned
# correction never turns a known source deadlock into a silent comparison
# mismatch.
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$CANCEL_DEFECT_PROBE" -o "$WORK/oracle-queued-cancel"
for cancel_case in target all; do
	cancel_status=0
	timeout -k 1 5 "$WORK/oracle-queued-cancel" "$cancel_case" \
		>"$WORK/oracle-queued-cancel-$cancel_case.stdout" \
		2>"$WORK/oracle-queued-cancel-$cancel_case.stderr" || cancel_status=$?
	printf '%s\n' "$cancel_status" >"$WORK/oracle-queued-cancel-$cancel_case.status"
	case "$cancel_status" in
		124|137) ;;
		*) fail "pinned musl queued $cancel_case cancellation did not reproduce its deadlock (status $cancel_status)" ;;
	esac
done

"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$SUBMIT_CANCEL_PROBE" -o "$WORK/oracle-submit-cancel"
submit_cancel_status=0
timeout 60 "$WORK/oracle-submit-cancel" s >"$WORK/oracle-submit-cancel.stdout" \
	2>"$WORK/oracle-submit-cancel.stderr" || submit_cancel_status=$?
printf '%s\n' "$submit_cancel_status" >"$WORK/oracle-submit-cancel.status"
[ "$submit_cancel_status" -eq 0 ] || fail "pinned musl submit handoff cancellation probe exited ${submit_cancel_status}"
grep -Fxq 'submit-handoff-cancellation=observed' "$WORK/oracle-submit-cancel.stdout" ||
	fail "pinned musl did not reproduce submit handoff cancellation"

if [ "$supplied_dynamic" -eq 0 ]; then
	python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
		--output "$WORK/dynamic-sysroot" >"$WORK/dynamic-build.json"
	dynamic_product="$WORK/dynamic-sysroot"
fi
validate_product "$dynamic_product" dynamic

"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$PROBE" -o "$WORK/workload.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$BEHAVIOR_PROBE" -o "$WORK/behavior-workload.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$FD_REUSE_PROBE" -o "$WORK/fd-reuse-workload.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$LIO_CREATE_FAILURE_PROBE" -o "$WORK/lio-create-failure-workload.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$SUSPEND_WAKE_PROBE" -o "$WORK/suspend-wake-workload.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$CANCEL_DEFECT_PROBE" -o "$WORK/queued-cancel-workload.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$CANCEL_CURSOR_PROBE" -o "$WORK/cancel-cursor-workload.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$SUBMIT_CANCEL_PROBE" -o "$WORK/submit-cancel-workload.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
	-c "$FRESH_SIGNAL_PROBE" -o "$WORK/fresh-signal-workload.o"
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$WORK/workload.o" -o "$WORK/oracle"
prepare_root "$WORK/oracle-root"
cp "$WORK/oracle" "$WORK/oracle-root/consumer"
run_capture "$WORK/oracle.stdout" chroot "$WORK/oracle-root" /consumer
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$WORK/behavior-workload.o" -o "$WORK/oracle-behavior"
cp "$WORK/oracle-behavior" "$WORK/oracle-root/behavior"
run_capture "$WORK/oracle-behavior.stdout" chroot "$WORK/oracle-root" /behavior
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$WORK/fd-reuse-workload.o" -o "$WORK/oracle-fd-reuse"
cp "$WORK/oracle-fd-reuse" "$WORK/oracle-root/fd-reuse"
run_fd_reuse_source_observation "$WORK/oracle-fd-reuse.stdout" chroot "$WORK/oracle-root" /fd-reuse "$FD_REUSE_ATTEMPTS"
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$WORK/lio-create-failure-workload.o" -o "$WORK/oracle-lio-create-failure"
cp "$WORK/oracle-lio-create-failure" "$WORK/oracle-root/lio-create-failure"
run_capture "$WORK/oracle-lio-create-failure.stdout" chroot "$WORK/oracle-root" /lio-create-failure
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$WORK/suspend-wake-workload.o" -o "$WORK/oracle-suspend-wake"
cp "$WORK/oracle-suspend-wake" "$WORK/oracle-root/suspend-wake"
run_capture "$WORK/oracle-suspend-wake.stdout" chroot "$WORK/oracle-root" /suspend-wake

if [ "$supplied_static" -eq 0 ] && [ "$supplied_dynamic" -eq 0 ]; then
	python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
		--output "$WORK/static-sysroot" >"$WORK/static-build.json"
	static_product="$WORK/static-sysroot"
fi
executed_products='dynamic PIE/non-PIE kernel/direct'
if [ -n "$static_product" ]; then
	executed_products='static/static-PIE and dynamic PIE/non-PIE kernel/direct'
	validate_product "$static_product" static
	assert_symbols "$static_product/usr/lib/libc.a" static "$WORK/static-symbols.txt"
	for mode in static static-pie; do
		candidate="$WORK/$mode"
		receipt="$candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
				"$WORK/workload.o" -o "$candidate"
		)
		validate_link "$static_product" "$WORK/workload.o" "$candidate" "$receipt" "$mode"
		root="$WORK/$mode-root"
		prepare_root "$root"
		cp "$candidate" "$root/consumer"
		run_capture "$WORK/$mode.stdout" chroot "$root" /consumer
		compare_oracle "$mode"

		behavior_candidate="$WORK/$mode-behavior"
		behavior_receipt="$behavior_candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$behavior_receipt")" \
				"$WORK/behavior-workload.o" -o "$behavior_candidate"
		)
		validate_link "$static_product" "$WORK/behavior-workload.o" "$behavior_candidate" "$behavior_receipt" "$mode"
		cp "$behavior_candidate" "$root/behavior"
		run_capture "$WORK/$mode-behavior.stdout" chroot "$root" /behavior
		compare_transcript oracle-behavior "$mode-behavior"

		fd_reuse_candidate="$WORK/$mode-fd-reuse"
		fd_reuse_receipt="$fd_reuse_candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$fd_reuse_receipt")" \
				"$WORK/fd-reuse-workload.o" -o "$fd_reuse_candidate"
		)
		validate_link "$static_product" "$WORK/fd-reuse-workload.o" "$fd_reuse_candidate" "$fd_reuse_receipt" "$mode"
		cp "$fd_reuse_candidate" "$root/fd-reuse"
		run_fd_reuse_owned "$WORK/$mode-fd-reuse.stdout" chroot "$root" /fd-reuse "$FD_REUSE_ATTEMPTS"

		lio_create_failure_candidate="$WORK/$mode-lio-create-failure"
		lio_create_failure_receipt="$lio_create_failure_candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$lio_create_failure_receipt")" \
				"$WORK/lio-create-failure-workload.o" -o "$lio_create_failure_candidate"
		)
		validate_link "$static_product" "$WORK/lio-create-failure-workload.o" "$lio_create_failure_candidate" "$lio_create_failure_receipt" "$mode"
		cp "$lio_create_failure_candidate" "$root/lio-create-failure"
		run_capture "$WORK/$mode-lio-create-failure.stdout" chroot "$root" /lio-create-failure
		compare_transcript oracle-lio-create-failure "$mode-lio-create-failure"

		suspend_wake_candidate="$WORK/$mode-suspend-wake"
		suspend_wake_receipt="$suspend_wake_candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$suspend_wake_receipt")" \
				"$WORK/suspend-wake-workload.o" -o "$suspend_wake_candidate"
		)
		validate_link "$static_product" "$WORK/suspend-wake-workload.o" "$suspend_wake_candidate" "$suspend_wake_receipt" "$mode"
		cp "$suspend_wake_candidate" "$root/suspend-wake"
		run_capture "$WORK/$mode-suspend-wake.stdout" chroot "$root" /suspend-wake
		compare_transcript oracle-suspend-wake "$mode-suspend-wake"

		queued_candidate="$WORK/$mode-queued-cancel"
		queued_receipt="$queued_candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$queued_receipt")" \
				"$WORK/queued-cancel-workload.o" -o "$queued_candidate"
		)
		validate_link "$static_product" "$WORK/queued-cancel-workload.o" "$queued_candidate" "$queued_receipt" "$mode"
		cp "$queued_candidate" "$root/queued-cancel"
		for cancel_case in target all; do
			run_capture "$WORK/$mode-queued-cancel-$cancel_case.stdout" \
				chroot "$root" /queued-cancel "$cancel_case"
			grep -Fxq "queued-cancel-$cancel_case=ok" "$WORK/$mode-queued-cancel-$cancel_case.stdout" ||
				fail "owned $mode queued $cancel_case cancellation did not complete"
		done

		cursor_candidate="$WORK/$mode-cancel-cursor"
		cursor_receipt="$cursor_candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$cursor_receipt")" \
				"$WORK/cancel-cursor-workload.o" -o "$cursor_candidate"
		)
		validate_link "$static_product" "$WORK/cancel-cursor-workload.o" "$cursor_candidate" "$cursor_receipt" "$mode"
		cp "$cursor_candidate" "$root/cancel-cursor"
		for cursor_case in target-target all-target late; do
			run_capture "$WORK/$mode-cancel-cursor-$cursor_case.stdout" \
				chroot "$root" /cancel-cursor "$cursor_case"
			grep -Fxq "cancel-cursor-$cursor_case=ok" "$WORK/$mode-cancel-cursor-$cursor_case.stdout" ||
				fail "owned $mode cancel cursor $cursor_case regression did not complete"
		done

		submit_cancel_candidate="$WORK/$mode-submit-cancel"
		submit_cancel_receipt="$submit_cancel_candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$submit_cancel_receipt")" \
				"$WORK/submit-cancel-workload.o" -o "$submit_cancel_candidate"
		)
		validate_link "$static_product" "$WORK/submit-cancel-workload.o" "$submit_cancel_candidate" "$submit_cancel_receipt" "$mode"
		cp "$submit_cancel_candidate" "$root/submit-cancel"
		run_capture "$WORK/$mode-submit-cancel.stdout" chroot "$root" /submit-cancel c 128
		grep -Fxq 'submit-handoff-cancellation=deferred' "$WORK/$mode-submit-cancel.stdout" ||
			fail "owned $mode submit handoff did not defer cancellation until pthread_testcancel"

		fresh_signal_candidate="$WORK/$mode-fresh-signal"
		fresh_signal_receipt="$fresh_signal_candidate.receipt.json"
		(
			cd "$WORK"
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$fresh_signal_receipt")" \
				"$WORK/fresh-signal-workload.o" -o "$fresh_signal_candidate"
		)
		validate_link "$static_product" "$WORK/fresh-signal-workload.o" "$fresh_signal_candidate" "$fresh_signal_receipt" "$mode"
		cp "$fresh_signal_candidate" "$root/fresh-signal"
		run_fresh_signal_owned "$WORK/$mode-fresh-signal.stdout" \
			chroot "$root" /fresh-signal
	done
fi

assert_symbols "$dynamic_product/usr/lib/libc.so" dynamic "$WORK/dynamic-symbols.txt"
for mode in pie non-pie; do
	candidate="$WORK/dynamic-$mode"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/workload.o" -o "$candidate"
	validate_link "$dynamic_product" "$WORK/workload.o" "$candidate" "$candidate.crabc-link.json" "$mode"
	root="$WORK/dynamic-$mode-root"
	mkdir -p "$root"
	cp -a "$dynamic_product/." "$root/"
	prepare_root "$root"
	cp "$candidate" "$root/consumer"
	behavior_candidate="$WORK/dynamic-$mode-behavior"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/behavior-workload.o" -o "$behavior_candidate"
	validate_link "$dynamic_product" "$WORK/behavior-workload.o" "$behavior_candidate" "$behavior_candidate.crabc-link.json" "$mode"
	cp "$behavior_candidate" "$root/behavior"
	fd_reuse_candidate="$WORK/dynamic-$mode-fd-reuse"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/fd-reuse-workload.o" -o "$fd_reuse_candidate"
	validate_link "$dynamic_product" "$WORK/fd-reuse-workload.o" "$fd_reuse_candidate" "$fd_reuse_candidate.crabc-link.json" "$mode"
	cp "$fd_reuse_candidate" "$root/fd-reuse"
	lio_create_failure_candidate="$WORK/dynamic-$mode-lio-create-failure"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/lio-create-failure-workload.o" -o "$lio_create_failure_candidate"
	validate_link "$dynamic_product" "$WORK/lio-create-failure-workload.o" "$lio_create_failure_candidate" "$lio_create_failure_candidate.crabc-link.json" "$mode"
	cp "$lio_create_failure_candidate" "$root/lio-create-failure"
	suspend_wake_candidate="$WORK/dynamic-$mode-suspend-wake"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/suspend-wake-workload.o" -o "$suspend_wake_candidate"
	validate_link "$dynamic_product" "$WORK/suspend-wake-workload.o" "$suspend_wake_candidate" "$suspend_wake_candidate.crabc-link.json" "$mode"
	cp "$suspend_wake_candidate" "$root/suspend-wake"
	queued_candidate="$WORK/dynamic-$mode-queued-cancel"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/queued-cancel-workload.o" -o "$queued_candidate"
	validate_link "$dynamic_product" "$WORK/queued-cancel-workload.o" "$queued_candidate" "$queued_candidate.crabc-link.json" "$mode"
	cp "$queued_candidate" "$root/queued-cancel"
	cursor_candidate="$WORK/dynamic-$mode-cancel-cursor"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/cancel-cursor-workload.o" -o "$cursor_candidate"
	validate_link "$dynamic_product" "$WORK/cancel-cursor-workload.o" "$cursor_candidate" "$cursor_candidate.crabc-link.json" "$mode"
	cp "$cursor_candidate" "$root/cancel-cursor"
	submit_cancel_candidate="$WORK/dynamic-$mode-submit-cancel"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/submit-cancel-workload.o" -o "$submit_cancel_candidate"
	validate_link "$dynamic_product" "$WORK/submit-cancel-workload.o" "$submit_cancel_candidate" "$submit_cancel_candidate.crabc-link.json" "$mode"
	cp "$submit_cancel_candidate" "$root/submit-cancel"
	fresh_signal_candidate="$WORK/dynamic-$mode-fresh-signal"
	"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/fresh-signal-workload.o" -o "$fresh_signal_candidate"
	validate_link "$dynamic_product" "$WORK/fresh-signal-workload.o" "$fresh_signal_candidate" "$fresh_signal_candidate.crabc-link.json" "$mode"
	cp "$fresh_signal_candidate" "$root/fresh-signal"
	for route in kernel direct; do
		if [ "$route" = kernel ]; then
			run_capture "$WORK/dynamic-$mode-$route.stdout" chroot "$root" /consumer
		else
			run_capture "$WORK/dynamic-$mode-$route.stdout" chroot "$root" "$INTERPRETER" /consumer
		fi
		compare_oracle "dynamic-$mode-$route"

		if [ "$route" = kernel ]; then
			run_capture "$WORK/dynamic-$mode-$route-behavior.stdout" chroot "$root" /behavior
		else
			run_capture "$WORK/dynamic-$mode-$route-behavior.stdout" chroot "$root" "$INTERPRETER" /behavior
		fi
		compare_transcript oracle-behavior "dynamic-$mode-$route-behavior"

		if [ "$route" = kernel ]; then
			run_fd_reuse_owned "$WORK/dynamic-$mode-$route-fd-reuse.stdout" chroot "$root" /fd-reuse "$FD_REUSE_ATTEMPTS"
		else
			run_fd_reuse_owned "$WORK/dynamic-$mode-$route-fd-reuse.stdout" chroot "$root" "$INTERPRETER" /fd-reuse "$FD_REUSE_ATTEMPTS"
		fi

		if [ "$route" = kernel ]; then
			run_capture "$WORK/dynamic-$mode-$route-lio-create-failure.stdout" chroot "$root" /lio-create-failure
		else
			run_capture "$WORK/dynamic-$mode-$route-lio-create-failure.stdout" chroot "$root" "$INTERPRETER" /lio-create-failure
		fi
		compare_transcript oracle-lio-create-failure "dynamic-$mode-$route-lio-create-failure"

		if [ "$route" = kernel ]; then
			run_capture "$WORK/dynamic-$mode-$route-suspend-wake.stdout" chroot "$root" /suspend-wake
		else
			run_capture "$WORK/dynamic-$mode-$route-suspend-wake.stdout" chroot "$root" "$INTERPRETER" /suspend-wake
		fi
		compare_transcript oracle-suspend-wake "dynamic-$mode-$route-suspend-wake"

		for cancel_case in target all; do
			if [ "$route" = kernel ]; then
				run_capture "$WORK/dynamic-$mode-$route-queued-cancel-$cancel_case.stdout" \
					chroot "$root" /queued-cancel "$cancel_case"
			else
				run_capture "$WORK/dynamic-$mode-$route-queued-cancel-$cancel_case.stdout" \
					chroot "$root" "$INTERPRETER" /queued-cancel "$cancel_case"
			fi
			grep -Fxq "queued-cancel-$cancel_case=ok" "$WORK/dynamic-$mode-$route-queued-cancel-$cancel_case.stdout" ||
				fail "owned dynamic-$mode-$route queued $cancel_case cancellation did not complete"
		done

		for cursor_case in target-target all-target late; do
			if [ "$route" = kernel ]; then
				run_capture "$WORK/dynamic-$mode-$route-cancel-cursor-$cursor_case.stdout" \
					chroot "$root" /cancel-cursor "$cursor_case"
			else
				run_capture "$WORK/dynamic-$mode-$route-cancel-cursor-$cursor_case.stdout" \
					chroot "$root" "$INTERPRETER" /cancel-cursor "$cursor_case"
			fi
			grep -Fxq "cancel-cursor-$cursor_case=ok" "$WORK/dynamic-$mode-$route-cancel-cursor-$cursor_case.stdout" ||
				fail "owned dynamic-$mode-$route cancel cursor $cursor_case regression did not complete"
		done

		if [ "$route" = kernel ]; then
			run_capture "$WORK/dynamic-$mode-$route-submit-cancel.stdout" \
				chroot "$root" /submit-cancel c 128
		else
			run_capture "$WORK/dynamic-$mode-$route-submit-cancel.stdout" \
				chroot "$root" "$INTERPRETER" /submit-cancel c 128
		fi
		grep -Fxq 'submit-handoff-cancellation=deferred' "$WORK/dynamic-$mode-$route-submit-cancel.stdout" ||
			fail "owned dynamic-$mode-$route submit handoff did not defer cancellation until pthread_testcancel"

		if [ "$route" = kernel ]; then
			run_fresh_signal_owned "$WORK/dynamic-$mode-$route-fresh-signal.stdout" \
				chroot "$root" /fresh-signal
		else
			run_fresh_signal_owned "$WORK/dynamic-$mode-$route-fresh-signal.stdout" \
				chroot "$root" "$INTERPRETER" /fresh-signal
		fi
	done
done

printf 'owned aio: PASS (installed-header object, pinned-musl oracle, %s); evidence: %s\n' \
	"$executed_products" "$WORK"
