#!/usr/bin/env bash
# Installed POSIX AIO behavior against pinned musl 1.2.6.
#
# One installed-header C object is linked by pinned musl, static/static-PIE,
# and dynamic PIE/non-PIE products.  The latter are exercised by both the
# kernel interpreter path and the installed interpreter directly.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly EVIDENCE="$ROOT/compat/x86_64/owned_aio_evidence.py"
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
			static_product="$(python3 -B "$EVIDENCE" supplied-product --root "$ROOT" --family static "$2")"
			supplied_static=1
			shift 2
			;;
		-*|'') usage ;;
		*)
			[ "$supplied_dynamic" -eq 0 ] || usage
			dynamic_product="$(python3 -B "$EVIDENCE" supplied-product --root "$ROOT" --family dynamic "$1")"
			supplied_dynamic=1
			shift
			;;
	esac
done

[ "$supplied_static" -eq 0 ] || [ "$supplied_dynamic" -eq 1 ] || usage

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
	local output="$1" label status=0
	shift
	label="$(basename "${output%.stdout}")"
	env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
		/usr/bin/timeout 30 "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
	printf '%s\n' "$status" >"${output%.stdout}.status"
	python3 -B "$EVIDENCE" record-command --root "$ROOT" --work "$WORK" --label "$label" \
		--stdout "$output" --stderr "${output%.stdout}.stderr" --status "${output%.stdout}.status" -- \
		/usr/bin/timeout 30 "$@" >/dev/null
	[ "$status" -eq 0 ] || fail "expected success, got ${status}: $*"
}

# Capture the source-known descriptor-incarnation race without conflating its
# raw transcript with a normal pinned-musl behavior oracle. A scheduling run
# may either complete all attempts or reach the stale positioned-I/O witness;
# both transcripts are preserved, while any other failure is rejected.
run_fd_reuse_source_observation() {
	local output="$1" label status=0
	shift
	label="$(basename "${output%.stdout}")"
	env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
		/usr/bin/timeout 30 "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
	printf '%s\n' "$status" >"${output%.stdout}.status"
	python3 -B "$EVIDENCE" record-command --root "$ROOT" --work "$WORK" --label "$label" \
		--stdout "$output" --stderr "${output%.stdout}.stderr" --status "${output%.stdout}.status" -- \
		/usr/bin/timeout 30 "$@" >/dev/null
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

record_raw() {
	local label="$1" output="$2" status="$3"
	shift 3
	python3 -B "$EVIDENCE" record-command --root "$ROOT" --work "$WORK" --label "$label" \
		--stdout "$output" --stderr "${output%.stdout}.stderr" --status "$status" -- "$@" >/dev/null
}

run_compile() {
	local key="$1" source="$2" object="$3" label="compile-$1" status=0
	env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
		"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
		-c "$source" -o "$object" >"$WORK/$label.stdout" 2>"$WORK/$label.stderr" || status=$?
	printf '%s\n' "$status" >"$WORK/$label.status"
	record_raw "$label" "$WORK/$label.stdout" "$WORK/$label.status" \
		"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
		-c "$source" -o "$object"
	[ "$status" -eq 0 ] || fail "installed header compilation failed for $key"
}

run_link() {
	local family="$1" mode="$2" key="$3" output="$4" status=0 label
	label="link-$mode-$key"
	local object="$WORK/${key/workload/workload}-workload.o"
	[ "$key" = workload ] && object="$WORK/workload.o"
	if [ "$family" = static ]; then
		(
			cd "$WORK"
			env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
				"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$output").receipt.json" \
				"$object" -o "$output"
		) >"$WORK/$label.stdout" 2>"$WORK/$label.stderr" || status=$?
		printf '%s\n' "$status" >"$WORK/$label.status"
		record_raw "$label" "$WORK/$label.stdout" "$WORK/$label.status" \
			"$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$output").receipt.json" "$object" -o "$output"
	else
		(
			cd "$WORK"
			env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
				"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-${mode#dynamic-}" "$object" -o "$output"
		) >"$WORK/$label.stdout" 2>"$WORK/$label.stderr" || status=$?
		printf '%s\n' "$status" >"$WORK/$label.status"
		record_raw "$label" "$WORK/$label.stdout" "$WORK/$label.status" \
			"$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-${mode#dynamic-}" "$object" -o "$output"
	fi
	[ "$status" -eq 0 ] || fail "installed $mode link failed for $key"
}

run_oracle_link() {
	local label="$1" input="$2" output="$3" status=0
	env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
		"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$input" -o "$output" \
		>"$WORK/$label.stdout" 2>"$WORK/$label.stderr" || status=$?
	printf '%s\n' "$status" >"$WORK/$label.status"
	record_raw "$label" "$WORK/$label.stdout" "$WORK/$label.status" \
		"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$input" -o "$output"
	[ "$status" -eq 0 ] || fail "pinned musl link failed for $label"
}

if [ "$supplied_dynamic" -eq 0 ]; then
	python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
		--output "$WORK/dynamic-sysroot" >"$WORK/dynamic-build.json"
	dynamic_product="$WORK/dynamic-sysroot"
fi
validate_product "$dynamic_product" dynamic
if [ "$supplied_static" -eq 0 ] && [ "$supplied_dynamic" -eq 0 ]; then
	python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
		--output "$WORK/static-sysroot" >"$WORK/static-build.json"
	static_product="$WORK/static-sysroot"
fi
if [ -n "$static_product" ]; then
	validate_product "$static_product" static
fi
input_seal_args=(seal-inputs --root "$ROOT" --work "$WORK" --dynamic "$dynamic_product")
if [ -n "$static_product" ]; then
	input_seal_args+=(--static "$static_product")
fi
EXPECTED_INPUTS="$(python3 -B "$EVIDENCE" "${input_seal_args[@]}")"
readonly EXPECTED_INPUTS

# The two source cancellation cases are deliberately expected to time out.
# Keep their raw status/logs beside the normal oracle transcript so the owned
# correction never turns a known source deadlock into a silent comparison
# mismatch.
run_oracle_link source-link-queued-cancel "$CANCEL_DEFECT_PROBE" "$WORK/oracle-queued-cancel"
for cancel_case in target all; do
	cancel_status=0
	env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
		/usr/bin/timeout -k 1 5 "$WORK/oracle-queued-cancel" "$cancel_case" \
		>"$WORK/oracle-queued-cancel-$cancel_case.stdout" \
		2>"$WORK/oracle-queued-cancel-$cancel_case.stderr" || cancel_status=$?
	printf '%s\n' "$cancel_status" >"$WORK/oracle-queued-cancel-$cancel_case.status"
	record_raw "oracle-queued-cancel-$cancel_case" "$WORK/oracle-queued-cancel-$cancel_case.stdout" \
		"$WORK/oracle-queued-cancel-$cancel_case.status" /usr/bin/timeout -k 1 5 "$WORK/oracle-queued-cancel" "$cancel_case"
	case "$cancel_status" in
		124|137) ;;
		*) fail "pinned musl queued $cancel_case cancellation did not reproduce its deadlock (status $cancel_status)" ;;
	esac
done

run_oracle_link source-link-submit-cancel "$SUBMIT_CANCEL_PROBE" "$WORK/oracle-submit-cancel"
submit_cancel_status=0
env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
	/usr/bin/timeout 60 "$WORK/oracle-submit-cancel" s >"$WORK/oracle-submit-cancel.stdout" \
	2>"$WORK/oracle-submit-cancel.stderr" || submit_cancel_status=$?
printf '%s\n' "$submit_cancel_status" >"$WORK/oracle-submit-cancel.status"
record_raw oracle-submit-cancel "$WORK/oracle-submit-cancel.stdout" "$WORK/oracle-submit-cancel.status" \
	/usr/bin/timeout 60 "$WORK/oracle-submit-cancel" s
[ "$submit_cancel_status" -eq 0 ] || fail "pinned musl submit handoff cancellation probe exited ${submit_cancel_status}"
grep -Fxq 'submit-handoff-cancellation=observed' "$WORK/oracle-submit-cancel.stdout" ||
	fail "pinned musl did not reproduce submit handoff cancellation"

header_status=0
compiler_path="$(python3 -B "$EVIDENCE" tool-path --dynamic "$dynamic_product" --name compiler)"
env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC TMPDIR="$WORK" \
	"$compiler_path" -nostdinc -isystem "$dynamic_product/usr/include" -ffreestanding -fno-builtin \
	-fstack-protector-strong -fPIE -std=c11 -D_GNU_SOURCE -E -H "$PROBE" \
	>"$WORK/installed-header-trace.stdout" 2>"$WORK/installed-header-trace.stderr" || header_status=$?
printf '%s\n' "$header_status" >"$WORK/installed-header-trace.status"
record_raw installed-header-trace "$WORK/installed-header-trace.stdout" "$WORK/installed-header-trace.status" \
	"$compiler_path" -nostdinc -isystem "$dynamic_product/usr/include" -ffreestanding -fno-builtin \
	-fstack-protector-strong -fPIE -std=c11 -D_GNU_SOURCE -E -H "$PROBE"
[ "$header_status" -eq 0 ] || fail 'installed-header trace failed'
run_compile workload "$PROBE" "$WORK/workload.o"
run_compile behavior "$BEHAVIOR_PROBE" "$WORK/behavior-workload.o"
run_compile fd-reuse "$FD_REUSE_PROBE" "$WORK/fd-reuse-workload.o"
run_compile lio-create-failure "$LIO_CREATE_FAILURE_PROBE" "$WORK/lio-create-failure-workload.o"
run_compile suspend-wake "$SUSPEND_WAKE_PROBE" "$WORK/suspend-wake-workload.o"
run_compile queued-cancel "$CANCEL_DEFECT_PROBE" "$WORK/queued-cancel-workload.o"
run_compile cancel-cursor "$CANCEL_CURSOR_PROBE" "$WORK/cancel-cursor-workload.o"
run_compile submit-cancel "$SUBMIT_CANCEL_PROBE" "$WORK/submit-cancel-workload.o"
run_compile fresh-signal "$FRESH_SIGNAL_PROBE" "$WORK/fresh-signal-workload.o"
run_oracle_link source-link-workload "$WORK/workload.o" "$WORK/oracle"
prepare_root "$WORK/oracle-root"
cp "$WORK/oracle" "$WORK/oracle-root/consumer"
run_capture "$WORK/oracle.stdout" /usr/sbin/chroot "$WORK/oracle-root" /consumer
run_oracle_link source-link-behavior "$WORK/behavior-workload.o" "$WORK/oracle-behavior"
cp "$WORK/oracle-behavior" "$WORK/oracle-root/behavior"
run_capture "$WORK/oracle-behavior.stdout" /usr/sbin/chroot "$WORK/oracle-root" /behavior
run_oracle_link source-link-fd-reuse "$WORK/fd-reuse-workload.o" "$WORK/oracle-fd-reuse"
cp "$WORK/oracle-fd-reuse" "$WORK/oracle-root/fd-reuse"
run_fd_reuse_source_observation "$WORK/oracle-fd-reuse.stdout" /usr/sbin/chroot "$WORK/oracle-root" /fd-reuse "$FD_REUSE_ATTEMPTS"
run_oracle_link source-link-lio-create-failure "$WORK/lio-create-failure-workload.o" "$WORK/oracle-lio-create-failure"
cp "$WORK/oracle-lio-create-failure" "$WORK/oracle-root/lio-create-failure"
run_capture "$WORK/oracle-lio-create-failure.stdout" /usr/sbin/chroot "$WORK/oracle-root" /lio-create-failure
run_oracle_link source-link-suspend-wake "$WORK/suspend-wake-workload.o" "$WORK/oracle-suspend-wake"
cp "$WORK/oracle-suspend-wake" "$WORK/oracle-root/suspend-wake"
run_capture "$WORK/oracle-suspend-wake.stdout" /usr/sbin/chroot "$WORK/oracle-root" /suspend-wake

executed_products='dynamic PIE/non-PIE kernel/direct'
if [ -n "$static_product" ]; then
	executed_products='static/static-PIE and dynamic PIE/non-PIE kernel/direct'
	assert_symbols "$static_product/usr/lib/libc.a" static "$WORK/static-symbols.txt"
	for mode in static static-pie; do
		root="$WORK/$mode-root"
		prepare_root "$root"
		for key in workload behavior fd-reuse lio-create-failure suspend-wake queued-cancel cancel-cursor submit-cancel fresh-signal; do
			candidate="$WORK/$mode"
			[ "$key" = workload ] || candidate="$WORK/$mode-$key"
			object="$WORK/$key-workload.o"
			[ "$key" = workload ] && object="$WORK/workload.o"
			run_link static "$mode" "$key" "$candidate"
			validate_link "$static_product" "$object" "$candidate" "$candidate.receipt.json" "$mode"
			cp "$candidate" "$root/${key/workload/consumer}"
		done
		run_capture "$WORK/$mode.stdout" /usr/sbin/chroot "$root" /consumer
		compare_oracle "$mode"
		run_capture "$WORK/$mode-behavior.stdout" /usr/sbin/chroot "$root" /behavior
		compare_transcript oracle-behavior "$mode-behavior"
		run_fd_reuse_owned "$WORK/$mode-fd-reuse.stdout" /usr/sbin/chroot "$root" /fd-reuse "$FD_REUSE_ATTEMPTS"
		run_capture "$WORK/$mode-lio-create-failure.stdout" /usr/sbin/chroot "$root" /lio-create-failure
		compare_transcript oracle-lio-create-failure "$mode-lio-create-failure"
		run_capture "$WORK/$mode-suspend-wake.stdout" /usr/sbin/chroot "$root" /suspend-wake
		compare_transcript oracle-suspend-wake "$mode-suspend-wake"
		for cancel_case in target all; do
			run_capture "$WORK/$mode-queued-cancel-$cancel_case.stdout" /usr/sbin/chroot "$root" /queued-cancel "$cancel_case"
			grep -Fxq "queued-cancel-$cancel_case=ok" "$WORK/$mode-queued-cancel-$cancel_case.stdout" || fail "owned $mode queued $cancel_case cancellation did not complete"
		done
		for cursor_case in target-target all-target late; do
			run_capture "$WORK/$mode-cancel-cursor-$cursor_case.stdout" /usr/sbin/chroot "$root" /cancel-cursor "$cursor_case"
			grep -Fxq "cancel-cursor-$cursor_case=ok" "$WORK/$mode-cancel-cursor-$cursor_case.stdout" || fail "owned $mode cancel cursor $cursor_case regression did not complete"
		done
		run_capture "$WORK/$mode-submit-cancel.stdout" /usr/sbin/chroot "$root" /submit-cancel c 128
		grep -Fxq 'submit-handoff-cancellation=deferred' "$WORK/$mode-submit-cancel.stdout" || fail "owned $mode submit handoff did not defer cancellation until pthread_testcancel"
		run_fresh_signal_owned "$WORK/$mode-fresh-signal.stdout" /usr/sbin/chroot "$root" /fresh-signal
	done
fi

assert_symbols "$dynamic_product/usr/lib/libc.so" dynamic "$WORK/dynamic-symbols.txt"
for mode in pie non-pie; do
	root="$WORK/dynamic-$mode-root"
	mkdir -p "$root"
	cp -a "$dynamic_product/." "$root/"
	prepare_root "$root"
	for key in workload behavior fd-reuse lio-create-failure suspend-wake queued-cancel cancel-cursor submit-cancel fresh-signal; do
		candidate="$WORK/dynamic-$mode"
		[ "$key" = workload ] || candidate="$WORK/dynamic-$mode-$key"
		object="$WORK/$key-workload.o"
		[ "$key" = workload ] && object="$WORK/workload.o"
		run_link dynamic "dynamic-$mode" "$key" "$candidate"
		validate_link "$dynamic_product" "$object" "$candidate" "$candidate.crabc-link.json" "$mode"
		cp "$candidate" "$root/${key/workload/consumer}"
	done
	for route in kernel direct; do
		if [ "$route" = kernel ]; then
			prefix=(/usr/sbin/chroot "$root")
		else
			prefix=(/usr/sbin/chroot "$root" "$INTERPRETER")
		fi
		run_capture "$WORK/dynamic-$mode-$route.stdout" "${prefix[@]}" /consumer
		compare_oracle "dynamic-$mode-$route"
		run_capture "$WORK/dynamic-$mode-$route-behavior.stdout" "${prefix[@]}" /behavior
		compare_transcript oracle-behavior "dynamic-$mode-$route-behavior"
		run_fd_reuse_owned "$WORK/dynamic-$mode-$route-fd-reuse.stdout" "${prefix[@]}" /fd-reuse "$FD_REUSE_ATTEMPTS"
		run_capture "$WORK/dynamic-$mode-$route-lio-create-failure.stdout" "${prefix[@]}" /lio-create-failure
		compare_transcript oracle-lio-create-failure "dynamic-$mode-$route-lio-create-failure"
		run_capture "$WORK/dynamic-$mode-$route-suspend-wake.stdout" "${prefix[@]}" /suspend-wake
		compare_transcript oracle-suspend-wake "dynamic-$mode-$route-suspend-wake"
		for cancel_case in target all; do
			run_capture "$WORK/dynamic-$mode-$route-queued-cancel-$cancel_case.stdout" "${prefix[@]}" /queued-cancel "$cancel_case"
			grep -Fxq "queued-cancel-$cancel_case=ok" "$WORK/dynamic-$mode-$route-queued-cancel-$cancel_case.stdout" || fail "owned dynamic-$mode-$route queued $cancel_case cancellation did not complete"
		done
		for cursor_case in target-target all-target late; do
			run_capture "$WORK/dynamic-$mode-$route-cancel-cursor-$cursor_case.stdout" "${prefix[@]}" /cancel-cursor "$cursor_case"
			grep -Fxq "cancel-cursor-$cursor_case=ok" "$WORK/dynamic-$mode-$route-cancel-cursor-$cursor_case.stdout" || fail "owned dynamic-$mode-$route cancel cursor $cursor_case regression did not complete"
		done
		run_capture "$WORK/dynamic-$mode-$route-submit-cancel.stdout" "${prefix[@]}" /submit-cancel c 128
		grep -Fxq 'submit-handoff-cancellation=deferred' "$WORK/dynamic-$mode-$route-submit-cancel.stdout" || fail "owned dynamic-$mode-$route submit handoff did not defer cancellation until pthread_testcancel"
		run_fresh_signal_owned "$WORK/dynamic-$mode-$route-fresh-signal.stdout" "${prefix[@]}" /fresh-signal
	done
done

report="$(python3 -B "$EVIDENCE" finalize --root "$ROOT" --work "$WORK" --expected-inputs "$EXPECTED_INPUTS")"

printf 'owned aio: PASS (installed-header object, pinned-musl oracle, %s); evidence: %s\n' \
	"$executed_products" "$report"
