# Installed public-data declaration runtime receipt

`owned_public_data_variable_runtime.py` owns one finite native x86-64 C-ABI
receipt for the nineteen installed variables that the declaration companion
otherwise leaves unresolved. Its source contract is
`owned_public_data_variable_runtime.toml`; it has seven fixed runtime groups:
immutable network data, environment, getdate, getopt/program names, `signgam`,
permanent standard-stream slots, and timezone globals.

The receipt is deliberately narrower than an export or family audit. It records
exact source Git inputs, pinned musl 1.2.6 oracle inputs, installed static and
dynamic product inputs, C probe objects, sealed link receipts, command argv,
raw stdout/stderr/status streams, and execution roots. Every group must execute
through candidate static, static PIE, dynamic PIE, and dynamic non-PIE products.
Both dynamic modes retain kernel and direct-interpreter entries. The reader
reconstructs those fixed source and product inputs from retained bytes without
running a compiler, linker, or target executable.

An execution-root record is not self-authentication. Static roots contain only
the exact sealed consumer and any named empty fixture directory. Dynamic roots
contain the current admitted dynamic-product tree plus that consumer and the
same finite fixtures. Oracle roots contain only the retained musl interpreter
copy at its fixed executable mode, the `libc.so` alias, the sealed oracle
consumer, and fixtures. Replay compares every path, node kind, mode, bytes and
symlink target, then re-admits current source, products, companions, tools and
oracle inputs before it accepts the unchanged report bytes.

The immutable group reads all sixteen `_ns_flagdata` records and both IPv6
values. Environment retains caller-serialized initial publication, exact
same-storage dependencies, replacement/removal/clear behavior and its borrowed
pointer boundary. Getdate preserves the existing source/template/error rows.
The getopt group covers startup program-name publication, public parser changes
and both same-storage reset paths. Its ordinary-main probe is separate from
`libc_process_globals_getopt_probe.c`: that legacy freestanding static fixture
retains the ABI-only `__optpos` cursor assertion. Pinned musl dynamic execution
leaves the executable-visible `__optpos` storage unchanged while the selected
public `getopt` result, `optind`, `optarg`, `opterr`, `optopt`, `optreset`, and
program-name aliases update correctly. This receipt therefore checks those
seven installed variables and its named reset/program-name dependencies, while
the static runner retains the private cursor proof. The boundary control uses
`/usr/local/bin/crabc-x86_64-musl-gcc` (SHA-256
`9b28cac06b7a1f35331ca06e23a1fc3fa7be9a6f85d9c6006363e8185001c90a`)
and its dynamic interpreter
`/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1` resolving to pinned runtime
`libc.so` (SHA-256
`8aea1cf45942b85b9d20bfcc4fbe78dcd6748f7d7c615513b38d3f9a897bdb65`);
it never uses Alpine's bootstrap musl as an oracle. The narrow signgam probe checks only that `lgamma` updates
`signgam`, `lgamma_r` writes its explicit sign without updating it, and
`__signgam` is the same storage. It does not make a math-family claim. The
standard-stream group observes three distinct initialized slots and descriptor
behavior without selecting a `FILE` layout. Timezone retains its existing TZif
fixture as a source-specific known-difference observation and adds the direct
POSIX-TZ `timezone`, `daylight`, `tzname` refresh and same-storage dependency
probe. For `TZ=UTC0`, it requires a non-null `tzname[0]` of `UTC` and the
non-null empty daylight-name slot which pinned musl's POSIX parser and
`owned_timezone.rs` both publish when the input contains no DST abbreviation.
The subsequent EST/EDT refresh proves the daylight-bearing case. This ordinary
POSIX-TZ publication check is separate from the source-specific TZif
known-difference observation and does not bless a raw candidate/oracle TZif
transcript difference.

`h_errno` is not collected here. The declaration selector composes the installed
`netdb.h` object-like macro and exact C/C++ accessor declaration with the current
`owned_errno_storage_lifecycle.py` receipt's selected `h_errno` static/shared
metadata and its existing main, worker, and loaded-DSO observations. A report
that merely names the errno receipt cannot satisfy that composed owner join.

A valid receipt can complete only the fixed nineteen installed-variable and one
accessor-macro declaration obligations. It does not select a provider; prove
strong overrides, interposition, COPY relocations, FILE layout, broad TLS/TCB,
timezone database behavior, family completion, promotion, qualification, or
public support. ABI-only data names remain outside this predicate.

`run_owned_public_data_variable_runtime.sh check-contract` is the source-only
preflight. `collect` requires the selected static preparation and static/dynamic
products plus the four current public companions: header declarations, ordinary
declaration ABI, public-data ordinary link, and errno storage lifecycle. It
first admits and snapshots that exact cohort, then records the ordinary C
commands. Every probe compile calls the selected dynamic driver with only
`--dynamic-pie -std=c11 -D_GNU_SOURCE=1 -fno-builtin
-fno-stack-protector -c SOURCE -o OBJECT`. The installed driver itself fixes
the installed header root and selected PIE code generation; a caller cannot
pass `-nostdinc`, `-isystem`, or an explicit PIC/PIE mode into this receipt.
Each static link runs in its executable directory and passes only the basename
of its `.crabc-link.json` receipt. The sealed static driver records map and
trace sidecars relative to that receipt, and the retained product reader
resolves them from the receipt parent. Dynamic links derive their own sidecars
from `-o` and retain the collection directory as their command working
directory. The shared ordinary command recorder receives exactly twenty-two
label-to-directory admissions from this source's eleven-scenario plan: static
and static PIE for each scenario. It preserves its root and receipt-root
defaults and rejects any other label, scenario directory, or symlink before a
command starts.
`validate-report REPORT` takes the same supplied cohort and companion
paths; it replays retained source, objects, link receipts, transcripts, roots,
and source-specific expected streams without running a compiler, linker, target
executable, or host oracle.

Several probe sources also support historical freestanding runners. This runner
does not invoke those starts: it compiles the ordinary `main` entry through the
selected installed product drivers, so a legacy fixture does not transfer its
startup or product assumptions into this receipt.
