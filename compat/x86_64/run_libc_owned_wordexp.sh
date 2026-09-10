#!/usr/bin/env bash
# Pinned-musl differential and installed-link gate for owned x86 wordexp.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py"
readonly PROBE="$ROOT_DIR/compat/x86_64/owned_wordexp_probe.c"
readonly POSIX_PROBE="$ROOT_DIR/compat/x86_64/owned_wordexp_posix_probe.c"
readonly SYMBOLS=(wordexp wordfree)

fail() { printf 'ERROR: x86 owned wordexp: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in awk cargo chroot chmod cmp cp env find grep id ldd mkdir mktemp mknod nm python3 \
	readelf realpath rustup sha256sum stat timeout; do
	require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$BUILDER" ] || fail "missing owned-static sysroot builder"
[ "$(id -u)" -eq 0 ] || fail "requires root for the private shell execution roots"
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail "requires repository-local TMPDIR"
checkout_physical="$(realpath -e "$ROOT_DIR")" || fail "cannot resolve checkout root"
tmpdir_physical="$(realpath -e "$TMPDIR")" || fail "cannot resolve TMPDIR"
case "$tmpdir_physical" in
	"$checkout_physical"/.work/*) ;;
	*) fail "TMPDIR physically escapes checkout .work: $tmpdir_physical" ;;
esac
ulimit -c 0

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-owned-wordexp.XXXXXX")"
cleanup() {
	local status=$?
	trap - EXIT HUP INT TERM
	if [ "$status" -eq 0 ]; then
		rm -rf -- "$work_dir"
	else
		printf 'x86 owned wordexp: retained failure evidence at %s\n' "$work_dir" >&2
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

target_dir="$work_dir/cargo-target"
default_target_dir="$work_dir/default-cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
default_archive="$default_target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-static-et-exec"
trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
default_symbols="$work_dir/default-archive-symbols"
sysroot="$work_dir/owned-static-sysroot"
controlled_shell_source="$(realpath -e /bin/sh)" || fail "cannot resolve controlled /bin/sh"
[ -f "$controlled_shell_source" ] && [ -x "$controlled_shell_source" ] ||
	fail "controlled /bin/sh is not an executable regular file"
chroot_command="$(command -v chroot)"
case "$chroot_command" in
	/*) ;;
	*) fail "cannot resolve an absolute chroot command" ;;
esac

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H "$PROBE" \
	>/dev/null 2>"$trace"
for header in errno.h wordexp.h stdio.h stdlib.h string.h unistd.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
		fail "fixture did not use project $header"
done
grep -Fq "$POSIX_PROBE" "$trace" ||
	fail "fixture did not include the POSIX correction cells"

# This deliberately pins the semantic oracle to a separately linked musl
# static ET_EXEC. Pinned-musl static PIE is a known wrapper diagnostic, while
# each crabc candidate below independently proves its requested ELF mode.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -fno-builtin \
	-static -fno-pie -no-pie "$PROBE" -o "$reference"
readelf --file-header --wide "$reference" >"$work_dir/reference-file-header"
grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$work_dir/reference-file-header" ||
	fail "pinned-musl wordexp oracle is not static ET_EXEC"

# The frozen default archive remains free of both public entries.
CARGO_TARGET_DIR="$default_target_dir" cargo rustc --locked -p crabc-libc --lib \
	--target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$default_archive" ] || fail "cargo did not emit default x86 static libc archive"
nm -A -g --defined-only "$default_archive" >"$default_symbols"
for symbol in "${SYMBOLS[@]}"; do
	if grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$default_symbols"; then
		fail "frozen default archive unexpectedly exports ${symbol}"
	fi
done

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
	--features x86-owned-static-runtime --target x86_64-unknown-linux-musl -- \
	-C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit feature-selected x86 static libc archive"
nm -A -g --defined-only "$archive" >"$archive_symbols"
for symbol in "${SYMBOLS[@]}"; do
	grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" ||
		fail "feature archive does not provide strong crabc-owned ${symbol}"
done

audit_receipt_and_elf() {
	local mode="$1"
	local label="$2"
	local mode_root="$work_dir/installed-${label}"
	local application="${3:-$mode_root/probe.o}"
	local candidate="${4:-$mode_root/candidate}"
	local receipt="${5:-$mode_root/link.receipt.json}"
	local audit_root="$(dirname "$candidate")"
	local file_header="$audit_root/${label}.file-header"
	local programs="$audit_root/${label}.programs"
	local dynamic="$audit_root/${label}.dynamic"
	local symbols="$audit_root/${label}.symbols"
	local relocations="$audit_root/${label}.relocations"

	python3 - "$ROOT_DIR" "$sysroot" "$mode" "$application" "$candidate" "$receipt" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

checkout_text, sysroot_text, mode, application_text, candidate_text, receipt_text = sys.argv[1:]
checkout = Path(checkout_text).resolve()
sysroot = Path(sysroot_text).resolve()
application = Path(application_text).resolve()
candidate = Path(candidate_text).resolve()
receipt_path = Path(receipt_text).resolve()
expected = {
    "-static": ("static-et-exec", "ET_EXEC", "crt1.o"),
    "-static-pie": ("static-pie", "ET_DYN", "rcrt1.o"),
}[mode]

def fail(message: str) -> None:
    raise SystemExit(f"owned wordexp receipt: {message}")

def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    fail(f"unreadable receipt: {error}")
if not isinstance(receipt, dict):
    fail("receipt is not an object")
if receipt.get("schema") != 1 or receipt.get("format") != "crabc-x86-64-sealed-static-driver-v1":
    fail("schema or format drifted")
if receipt.get("target") != "x86_64-unknown-linux-musl":
    fail("target drifted")
selected = receipt.get("mode")
if not isinstance(selected, dict) or (
    selected.get("id"), selected.get("elf_type"), selected.get("crt_object"), selected.get("interpreter")
) != (*expected, "absent"):
    fail("selected mode drifted")
library = sysroot / "usr" / "lib"
expected_runtime = [
    ("crt-entry", library / expected[2]),
    ("crt-prologue", library / "crti.o"),
    ("libc", library / "libc.a"),
    ("builtins", library / "libcrabc-builtins.a"),
    ("crt-epilogue", library / "crtn.o"),
]
expected_records = [
    {"role": role, "path": str(path.relative_to(sysroot)), "sha256": digest(path)}
    for role, path in expected_runtime
]
expected_records.append(
    {"role": "application", "path": str(application), "sha256": digest(application)}
)
if receipt.get("input_receipts") != expected_records:
    fail("runtime allowlist or exact application-object receipt drifted")
for field, path in (("output", candidate), ("map", receipt_path.with_suffix(".map")),
                    ("trace", receipt_path.with_suffix(".trace"))):
    record = receipt.get(field)
    if not isinstance(record, dict) or record.get("path") != path.name or record.get("sha256") != digest(path):
        fail(f"{field} receipt drifted")

# The exact receipt admits only this object plus the selected installed
# runtime. Reuse the sysroot trace auditor for the resolved linker inputs so
# a foreign archive cannot hide behind a role-shaped receipt record.
sys.path.insert(0, str(checkout / "scripts"))
from crabc_sysroot import audit_linker_trace
trace_audit = audit_linker_trace(
    receipt_path.with_suffix(".trace").read_bytes(),
    sysroot,
    application_paths=(application,),
)
if trace_audit.get("status") != "passed":
    fail(f"resolved trace escapes the installed runtime allowlist: {trace_audit}")
if str(application) not in trace_audit.get("trace_paths", []):
    fail("resolved trace omitted the exact application object")
PY
	readelf --file-header --wide "$candidate" >"$file_header"
	readelf --program-headers --wide "$candidate" >"$programs"
	readelf --dynamic --wide "$candidate" >"$dynamic" || true
	readelf --symbols --wide "$candidate" >"$symbols"
	readelf --relocs --wide "$candidate" >"$relocations"
	grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' "$file_header" ||
		fail "${label} installed candidate is not EM_X86_64"
	case "$mode" in
		-static)
			grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$file_header" ||
				fail "${label} installed candidate is not ET_EXEC"
			;;
		-static-pie)
			grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' "$file_header" ||
				fail "${label} installed candidate is not ET_DYN"
			awk '$1 == "PHDR" { found = 1 } END { exit !found }' "$programs" ||
				fail "${label} installed candidate lacks PT_PHDR"
			;;
	esac
	if grep -Eq 'Requesting program interpreter|INTERP' "$programs" ||
		grep -Eq 'NEEDED|JMPREL|PLTGOT' "$dynamic"; then
		fail "${label} installed candidate selected dynamic runtime state"
	fi
	if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
		fail "${label} installed candidate has unresolved symbols"
	fi
	if grep -Eq 'R_X86_64_(GLOB_DAT|JUMP_SLOT|TLSGD|TLSLD|TLSDESC|DTPMOD|DTPOFF)' \
		"$relocations" "$symbols"; then
		fail "${label} installed candidate retains dynamic relocation or TLS form"
	fi
	if [ "$mode" = -static-pie ]; then
		if grep -Eq 'R_X86_64_GOTTPOFF|__tls_get_addr' "$relocations" "$symbols"; then
			fail "${label} installed candidate retains unrelaxed initial TLS"
		fi
		awk '$3 ~ /^R_X86_64_/ && $3 != "R_X86_64_RELATIVE" { exit 1 }' "$relocations" ||
			fail "${label} installed candidate retains a non-relative relocation"
	fi
}

copy_controlled_shell_dependency() {
	local execution_root="$1"
	local dependency="$2"
	local resolved
	local destination

	case "$dependency" in
		/*) ;;
		*) fail "controlled shell dependency is not absolute: $dependency" ;;
	esac
	resolved="$(realpath -e "$dependency")" ||
		fail "cannot resolve controlled shell dependency: $dependency"
	[ -f "$resolved" ] || fail "controlled shell dependency is not a regular file: $resolved"
	destination="$execution_root$dependency"
	mkdir -p "${destination%/*}"
	cp -L --preserve=mode "$dependency" "$destination"
	cmp -s "$resolved" "$destination" ||
		fail "controlled shell dependency copy drifted: $dependency"
}

# The test root contains the sole `/bin/sh` image seen by both the pinned-musl
# oracle and candidate. Copy its loader closure as ordinary files, reject
# symlinks, and provide only a private writable Linux char device 1:3 at
# `/dev/null` for musl's `WRDE_SHOWERR`-off shell redirection. No candidate link input comes
# from this execution fixture; receipt/trace auditing remains separate.
make_private_shell_root() {
	local execution_root="$1"
	local dependency
	local physical_root

	case "$execution_root" in
		"$work_dir"/execution-*) ;;
		*) fail "private shell root escapes invocation work directory: $execution_root" ;;
	esac
	mkdir -p "$execution_root/bin" "$execution_root/dev"
	physical_root="$(realpath -e "$execution_root")" ||
		fail "cannot resolve private shell root: $execution_root"
	[ "$physical_root" = "$execution_root" ] ||
		fail "private shell root is not physical: $execution_root"
	cp -L --preserve=mode "$controlled_shell_source" "$execution_root/bin/sh"
	cmp -s "$controlled_shell_source" "$execution_root/bin/sh" ||
		fail "private /bin/sh differs from the controlled shell source"
	mknod "$execution_root/dev/null" c 1 3
	chmod 666 "$execution_root/dev/null"
	[ -c "$execution_root/dev/null" ] &&
		[ "$(stat -c '%t:%T:%a' "$execution_root/dev/null")" = '1:3:666' ] ||
		fail "private /dev/null is not character device 1:3 mode 666"
	while IFS= read -r dependency; do
		[ -n "$dependency" ] || continue
		copy_controlled_shell_dependency "$execution_root" "$dependency"
	done < <(LC_ALL=C ldd "$controlled_shell_source" |
		awk '$1 ~ /^\// { print $1; next } $2 == "=>" && $3 ~ /^\// { print $3 }')
	if find "$execution_root" -type l -print -quit | grep -q .; then
		fail "private shell root retains a symlink"
	fi
	sha256sum "$controlled_shell_source" "$execution_root/bin/sh" \
		>"$execution_root/controlled-shell.sha256"
}

prepare_private_shell_case() {
	local execution_root="$1"
	local shell_case="$2"
	local candidate="$3"

	make_private_shell_root "$execution_root"
	cp -L --preserve=mode "$reference" "$execution_root/reference"
	cp -L --preserve=mode "$candidate" "$execution_root/candidate"
	case "$shell_case" in
		normal) ;;
		missing) rm -f -- "$execution_root/bin/sh" ;;
		inaccessible) chmod 644 "$execution_root/bin/sh" ;;
		invalid)
			printf 'not an executable shell image\n' >"$execution_root/bin/sh"
			chmod 755 "$execution_root/bin/sh"
			;;
		*) fail "unknown controlled shell case: $shell_case" ;;
	esac
	if find "$execution_root" -type l -print -quit | grep -q .; then
		fail "private shell case retains a symlink"
	fi
}

run_private_shell_probe() {
	local execution_root="$1"
	local program="$2"
	local shell_case="$3"
	local stdout="$4"
	local stderr="$5"

	if [ "$shell_case" = normal ]; then
		timeout 20 env -i CRABC_WORDEXP='bar baz' FOO=field X=left Y=right SET=1 "$chroot_command" "$execution_root" \
			"/$program" >"$stdout" 2>"$stderr" ||
			fail "$shell_case private shell $program probe failed"
	else
		timeout 20 env -i CRABC_WORDEXP='bar baz' FOO=field X=left Y=right SET=1 "$chroot_command" "$execution_root" \
			"/$program" --shell-unavailable >"$stdout" 2>"$stderr" ||
			fail "$shell_case private shell $program probe failed"
	fi
}

run_controlled_shell_cases() {
	local label="$1"
	local candidate="$2"
	local shell_case
	local execution_root
	local expected

	for shell_case in normal missing inaccessible invalid; do
		execution_root="$work_dir/execution-${label}-${shell_case}"
		prepare_private_shell_case "$execution_root" "$shell_case" "$candidate"
		run_private_shell_probe "$execution_root" reference "$shell_case" \
			"$execution_root/reference.stdout" "$execution_root/reference.stderr"
		run_private_shell_probe "$execution_root" candidate "$shell_case" \
			"$execution_root/candidate.stdout" "$execution_root/candidate.stderr"
		cmp -s "$execution_root/reference.stdout" "$execution_root/candidate.stdout" ||
			fail "$label $shell_case private-shell output differs from pinned musl"
		if [ "$shell_case" = normal ]; then
			# The unchanged source workload deliberately sends `one )` through
			# a non-SHOWERR call. Pinned musl's `$2` redirection occurs too late
			# for that parse diagnostic; the POSIX correction must leave the
			# pinned source bytes observable while retaining no candidate bytes.
			[ -s "$execution_root/reference.stderr" ] ||
				fail "$label normal pinned-musl quiet source control did not write stderr"
			[ ! -s "$execution_root/candidate.stderr" ] ||
				fail "$label normal candidate did not suppress quiet shell stderr"
		else
			cmp -s "$execution_root/reference.stderr" "$execution_root/candidate.stderr" ||
				fail "$label $shell_case private-shell stderr differs from pinned musl"
		fi
		case "$shell_case" in
			normal) expected='owned-wordexp: PASS' ;;
			*) expected='owned-wordexp-shell-unavailable: PASS' ;;
		esac
		printf '%s\n' "$expected" >"$execution_root/expected.stdout"
		cmp -s "$execution_root/expected.stdout" "$execution_root/reference.stdout" ||
			fail "$shell_case private-shell oracle did not exercise its intended result"
	done
}

run_installed_mode() {
	local mode="$1"
	local label="$2"
	local mode_root="$work_dir/installed-${label}"

	mkdir "$mode_root"
	(
		cd "$mode_root"
		"$sysroot/bin/crabc-cc" "$mode" -std=c11 -D_GNU_SOURCE -fno-builtin \
			-c "$PROBE" -o probe.o
		"$sysroot/bin/crabc-cc" "$mode" --link-receipt link.receipt.json probe.o -o candidate
	)
	audit_receipt_and_elf "$mode" "$label"
	run_controlled_shell_cases "$label" "$mode_root/candidate"
}

# Compile the ordinary C probe once with the installed static-PIE translation
# contract. Its exact bytes then link into the pinned-musl ET_EXEC oracle and
# both selected crabc static modes. The source scanner control, POSIX quiet
# diagnostic, frame-context NOCMD controls, and non-qualifying UNDEF
# observation all reuse that one installed-header object under the same
# private shell fixture.
run_same_object_wordexp_cases() {
	local same_root="$work_dir/same-object-wordexp"
	local application="$same_root/probe.o"
	local oracle="$same_root/musl-static-et-exec"
	local static_candidate="$same_root/crabc-static-et-exec"
	local static_receipt="$same_root/crabc-static-et-exec.receipt.json"
	local pie_candidate="$same_root/crabc-static-pie"
	local pie_receipt="$same_root/crabc-static-pie.receipt.json"
	local program selector
	local output
	local stderr
	local execution_root
	local status
	local failures=0

	mkdir "$same_root"
	(
		cd "$same_root"
		"$sysroot/bin/crabc-cc" -static-pie -std=c11 -D_GNU_SOURCE -fno-builtin \
			-c "$PROBE" -o probe.o
		"$ORACLE_CC" -static -fno-pie -no-pie probe.o -o "$(basename "$oracle")"
		"$sysroot/bin/crabc-cc" -static --link-receipt "$(basename "$static_receipt")" \
			probe.o -o "$(basename "$static_candidate")"
		"$sysroot/bin/crabc-cc" -static-pie --link-receipt "$(basename "$pie_receipt")" \
			probe.o -o "$(basename "$pie_candidate")"
	)
	audit_receipt_and_elf -static same-object-static "$application" "$static_candidate" "$static_receipt"
	audit_receipt_and_elf -static-pie same-object-static-pie "$application" "$pie_candidate" "$pie_receipt"
	sha256sum "$application" >"$same_root/workload.sha256"
	for selector in --nocmd-source --posix-quiet --posix-nocmd \
		--posix-nocmd-escaped-control --posix-nocmd-arithmetic-control \
		--posix-nocmd-pattern-control --posix-nocmd-arithmetic-delimiter-control \
		--posix-nocmd-continuation-control --posix-nocmd-dollar-single-control \
		--undef-source-observation; do
		for program in "$oracle" "$static_candidate" "$pie_candidate"; do
			execution_root="$work_dir/execution-same-object-$(basename "$program")-${selector#--}"
			make_private_shell_root "$execution_root"
			cp -L --preserve=mode "$program" "$execution_root/consumer"
			if timeout 20 env -i CRABC_WORDEXP='bar baz' FOO=field X=left Y=right SET=1 \
				"$chroot_command" "$execution_root" /consumer "$selector" \
				>"$same_root/$(basename "$program")-${selector#--}.stdout" \
				2>"$same_root/$(basename "$program")-${selector#--}.stderr"; then
				status=0
			else
				status=$?
			fi
			printf '%s\n' "$status" >"$same_root/$(basename "$program")-${selector#--}.status"
			output="$same_root/$(basename "$program")-${selector#--}.stdout"
			stderr="$same_root/$(basename "$program")-${selector#--}.stderr"
			case "$selector:$(basename "$program")" in
				--nocmd-source:*)
					printf 'owned-wordexp-nocmd-source: PASS\n' >"$same_root/expected.stdout"
					if [ "$status" -ne 0 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'same-object source NOCMD control drifted: %s\n' "$(basename "$program")" >&2
						failures=1
					fi
					;;
				--posix-quiet:musl-static-et-exec)
					printf 'owned-wordexp-posix-quiet: SOURCE-RED diagnostic-present\n' >"$same_root/expected.stdout"
					if [ "$status" -ne 84 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'pinned-musl quiet source RED drifted\n' >&2
						failures=1
					fi
					;;
				--posix-nocmd:musl-static-et-exec)
					printf 'owned-wordexp-posix-nocmd: SOURCE-RED parameter-brace-rejected\n' >"$same_root/expected.stdout"
					if [ "$status" -ne 113 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'pinned-musl parameter-brace source RED drifted\n' >&2
						failures=1
					fi
					;;
				--posix-nocmd-arithmetic-control:musl-static-et-exec)
					printf 'owned-wordexp-posix-nocmd-arithmetic-control: SOURCE-RED parameter-brace-rejected\n' >"$same_root/expected.stdout"
					if [ "$status" -ne 162 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'pinned-musl arithmetic parameter source RED drifted\n' >&2
						failures=1
					fi
					;;
				--posix-nocmd-arithmetic-delimiter-control:musl-static-et-exec)
					printf 'owned-wordexp-posix-nocmd-arithmetic-delimiter-control: SOURCE-RED command-marker-created\n' >"$same_root/expected.stdout"
					if [ "$status" -ne 196 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'pinned-musl arithmetic delimiter source RED drifted\n' >&2
						failures=1
					fi
					;;
				--posix-nocmd-continuation-control:musl-static-et-exec)
					printf 'owned-wordexp-posix-nocmd-continuation-control: SOURCE-RED command-marker-created\n' >"$same_root/expected.stdout"
					if [ "$status" -ne 212 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'pinned-musl continuation source RED drifted\n' >&2
						failures=1
					fi
					;;
				--posix-nocmd-dollar-single-control:musl-static-et-exec)
					printf 'owned-wordexp-posix-nocmd-dollar-single-control: SOURCE-RED command-marker-created\n' >"$same_root/expected.stdout"
					if [ "$status" -ne 228 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'pinned-musl dollar-single source RED drifted\n' >&2
						failures=1
					fi
					;;
				--posix-nocmd-escaped-control:*|--posix-nocmd-pattern-control:*)
					if [ "$selector" = --posix-nocmd-escaped-control ]; then
						printf 'owned-wordexp-posix-nocmd-escaped-control: PASS\n' >"$same_root/expected.stdout"
					else
						printf 'owned-wordexp-posix-nocmd-pattern-control: PASS\n' >"$same_root/expected.stdout"
					fi
					if [ "$status" -ne 0 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'same-object lexical NOCMD control failed: %s %s\n' "$selector" "$(basename "$program")" >&2
						failures=1
					fi
					;;
				--posix-quiet:*|--posix-nocmd:*|--posix-nocmd-arithmetic-control:*|\
				--posix-nocmd-arithmetic-delimiter-control:*|--posix-nocmd-continuation-control:*|\
				--posix-nocmd-dollar-single-control:*)
					if [ "$status" -ne 0 ] || [ -s "$stderr" ]; then
						printf 'owned POSIX wordexp cell failed: %s %s\n' "$selector" "$(basename "$program")" >&2
						failures=1
					elif [ "$selector" = --posix-quiet ]; then
						printf 'owned-wordexp-posix-quiet: PASS\n' >"$same_root/expected.stdout"
						cmp -s "$same_root/expected.stdout" "$output" || failures=1
					elif [ "$selector" = --posix-nocmd ]; then
						printf 'owned-wordexp-posix-nocmd: PASS\n' >"$same_root/expected.stdout"
						cmp -s "$same_root/expected.stdout" "$output" || failures=1
					elif [ "$selector" = --posix-nocmd-arithmetic-control ]; then
						printf 'owned-wordexp-posix-nocmd-arithmetic-control: PASS\n' >"$same_root/expected.stdout"
						cmp -s "$same_root/expected.stdout" "$output" || failures=1
					elif [ "$selector" = --posix-nocmd-arithmetic-delimiter-control ]; then
						printf 'owned-wordexp-posix-nocmd-arithmetic-delimiter-control: PASS\n' >"$same_root/expected.stdout"
						cmp -s "$same_root/expected.stdout" "$output" || failures=1
					elif [ "$selector" = --posix-nocmd-continuation-control ]; then
						printf 'owned-wordexp-posix-nocmd-continuation-control: PASS\n' >"$same_root/expected.stdout"
						cmp -s "$same_root/expected.stdout" "$output" || failures=1
					else
						printf 'owned-wordexp-posix-nocmd-dollar-single-control: PASS\n' >"$same_root/expected.stdout"
						cmp -s "$same_root/expected.stdout" "$output" || failures=1
					fi
					;;
				--undef-source-observation:*)
					printf 'owned-wordexp-undef-source-observation: SOURCE-RED\n' >"$same_root/expected.stdout"
					if [ "$status" -ne 0 ] || ! cmp -s "$same_root/expected.stdout" "$output" || [ -s "$stderr" ]; then
						printf 'non-qualifying WRDE_UNDEF source observation drifted: %s\n' "$(basename "$program")" >&2
						failures=1
					fi
					;;
			esac
		done
	done
	[ "$failures" -eq 0 ] || fail "same-object POSIX wordexp cells failed; raw status/stdout/stderr retained"
}

python3 "$BUILDER" --output "$sysroot" >"$work_dir/sysroot-build.json"
run_same_object_wordexp_cases
run_installed_mode -static et-exec
run_installed_mode -static-pie static-pie

printf 'x86 owned wordexp: PASS (pinned static ET_EXEC source controls and explicit POSIX source REDs; installed ET_EXEC/static PIE shell, source scanner, ownership, cleanup)\n'
