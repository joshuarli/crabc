# Resolver/network differential harness

This harness is the deterministic resolver/network contract. It compiles
[`workload.c`](workload.c) exactly once using the headers in the pinned musl
tree, links that object once to musl and once to crabc, and runs both binaries
against the same local-only DNS server. The runner compares complete exit
status, stdout, and stderr byte-for-byte. There is no normalization: loader
diagnostics, application diagnostics, signal exits, and timeout results remain
visible. A successful run publishes one JSON document by atomic replacement.
Because legacy musl resolver entry points may reload `/etc/resolv.conf`, the
runner uses a private resolver file only inside an explicitly marked,
network-isolated environment; see [Isolated resolver configuration](#isolated-resolver-configuration).

## Files and responsibilities

| File | Contract |
| --- | --- |
| [`dns_server.py`](dns_server.py) | Python-stdlib DNS server. Binds UDP and TCP on fixed private loopback role addresses at port 53: `valid`=`127.0.0.1`, `drop`=`127.0.0.2`, and `fallback`=`127.0.0.3`; it serves deterministic A/AAAA/CNAME/NXDOMAIN/NODATA and TC→TCP cases. It never reads or contacts public DNS. |
| [`workload.c`](workload.c) | One C source/object for both links. Installs the same DNS servers and search state through public `_res`/`__res_state`; it does not write `/etc/resolv.conf`. |
| [`run.py`](run.py) | Compiles once, links/runs both variants, compares raw observations, checks the server event contract, and atomically publishes JSON. |
| [`prepare_x86_64.py`](prepare_x86_64.py) | Materializes the exact static and dynamic installed x86 products in the ordinary pinned container before network isolation. |
| [`run_x86_64.py`](run_x86_64.py) | Native x86 differential: compiles one pinned-musl-header object, links the pinned-musl static reference plus four owned product artifacts, and runs the reference and six owned entry modes in private chroots. |
| [`test_x86_64.py`](test_x86_64.py) | Stdlib contract tests for the native runner's product, ELF, report, fixture, and DNS-event boundaries. |
| `dns-events.json` (temporary) | Server-side query evidence. The runner embeds it in the report and removes the temporary directory after the run. |
| `compat/reports/resolver-network.json` (default) | Atomic report destination; override with `--report` or `CRABC_RESOLVER_NETWORK_REPORT`. |

`run.py` is intentionally native-AArch64-only, matching the repository's
other historical musl differential runner. Its default inputs are `MUSL_ROOT` or
`/opt/musl-1.2.6`, `MUSL_CC` or `musl-gcc`, and
`target/debug/{libc.so,libldso.so}`. Input validation requires the exact
`musl-1.2.6` directory name, `include/`, `lib/ld-musl-aarch64.so.1`, and
`lib/libc.so`. Override paths explicitly only when retaining that pinned tree
and architecture in the native development image.

## Native x86-64 owned-product differential

The native x86 gate separates product preparation from resolver execution.
`prepare_x86_64.py` runs in the ordinary pinned container and creates a fresh
directory below `.work/x86_64`. It invokes the fixed static and dynamic product
builders, packages each exact installed tree twice through its owned package
tool, requires the two archive byte streams to match, and safely extracts one
validated archive of each product. `run_x86_64.py` requires all four explicit
installed/extracted directories. It validates each manifest and requires the
installed and extracted trees to have the same complete payload identity before
it compiles one `workload.c` object with the pinned musl 1.2.6 headers.

That unchanged object links into a pinned-musl static ET_EXEC reference and,
for each product arm, the owned static ET_EXEC/static-PIE plus dynamic
PIE/non-PIE artifacts. The runner audits every driver's receipt, link trace,
ELF type, interpreter, and runtime inputs.

The dispatcher runs only the second phase in a native Linux/x86-64 Docker
container with `--network none` and `SYS_CHROOT`. The runner rejects any
network namespace that has an interface other than `lo` or a default route.
Each reference/candidate invocation receives a disposable chroot containing
only runner-written `etc/hosts` and `etc/resolv.conf`; dynamic chroots also
contain the validated owned dynamic sysroot. The fixture server remains on the
same loopback-only namespace. No runner path reads, writes, snapshots, or
restores the container's `/etc` files.

The reference plus all twelve product executions must produce the same raw
exit status, stdout, and stderr: static ET_EXEC, static PIE, dynamic PIE
ordinary entry, dynamic PIE direct interpreter entry, dynamic non-PIE ordinary
entry, and dynamic non-PIE direct interpreter entry through both the installed
and extracted trees. The DNS event evidence requires every transition from all
thirteen processes. The report is published under
`compat/reports/resolver-network/x86_64/` only on a complete pass. This is an
evidence gate for the named products and resolver/network workload; it does
not complete or promote the `compat.resolver-network` family.

Run the two phases through the pinned dispatcher:

```sh
./scripts/dev-x86_64.sh owned-resolver-network
```

The separate [owned classic netdb slice](../x86_64/owned-classic-netdb.md)
reuses this DNS fixture for installed host/service APIs and the owned modern
lookup backends. Its additional named records cover PTR and mixed-family
error precedence without changing this workload's existing records. DNS
transport cancellation and cancellation-driven descriptor cleanup remain an
explicit resolver-family closure obligation for both owned paths.

## Subcases

The stdout contract is fixed and is listed in `run.py` as
`EXPECTED_STDOUT`/`EXPECTED_SUBCASES`. Resolver cases cover:

* A and AAAA records;
* NXDOMAIN (`HOST_NOT_FOUND`) and NOERROR/NODATA (`NO_DATA`);
* a malformed datagram followed by a valid answer with the wrong transaction
  ID, followed by the matching valid answer;
* an alias with a CNAME RR and its target A RR; and
* a UDP response with the TC bit, requiring a retry over TCP for the complete
  A answer;
* `res_search("searchhost", ...)` with an explicitly installed
  `search.test` domain; and
* a bounded fallback where the valid first endpoint drops this name, the
  dedicated drop endpoint also drops it, and the third nameserver answers.

Network cases cover loopback TCP and UDP for IPv4 and IPv6, UNIX
`socketpair`, `sendmsg`/`recvmsg` over two iovecs, `SCM_RIGHTS` ancillary data,
`epoll` and `poll`/`select` readiness, a half-close with `shutdown`, bounded
nonblocking partial writes, `SO_RCVTIMEO`, EINTR from a deterministic alarm,
and nonblocking receive with `EAGAIN`. The IPv6 cases are intentional
requirements; an environment without IPv6 is a failed workload, not silently
skipped coverage.

The added waits are bounded: epoll waits at most one second, the receive
timeout is 100 ms, and the EINTR case uses a one-second `SIGALRM`; no case
uses an external host or public network.

The DNS server exposes a fixed-address manifest on its first stdout line. The
C process takes no resolver endpoint arguments: both binaries read the private
configuration, while the C fixture independently sets the public resolver
state to the same addresses. For `fallback.example.test.`, the valid endpoint
intentionally drops the query, the drop endpoint also drops it, and the third
endpoint answers. The event contract requires at least two observations of
that drop-and-fallback path (one for musl and one for crabc), in addition to
every named DNS case, the malformed sequence, CNAME, and both sides of the
TC-to-TCP retry. DNS packet IDs are not included in event logs so reports do
not contain random resolver state.

## Isolated resolver configuration

This harness is valid only in an explicitly isolated network environment. The
runner refuses to start unless `CRABC_RESOLVER_NETWORK_ISOLATED=1` is set. The
marker is an assertion supplied by the surrounding network-none container or
development runner; it is not a general permission to edit a host resolver
configuration. Before running the binaries, `run.py` requires `/etc/resolv.conf`
to be a regular non-symlink file, saves it, writes this deterministic content,
and restores the original bytes and mode before publishing the report:

```text
nameserver 127.0.0.1
nameserver 127.0.0.2
nameserver 127.0.0.3
search search.test
options ndots:1 timeout:1 attempts:1
```

The fixed port and role addresses are part of the report contract. A host
invocation without the marker, a symlinked resolver file, or a non-private
server manifest fails as a setup error before any resolver-file write.

## Running

Build crabc first, then from the repository root in the pinned native
AArch64 Linux/musl environment:

```sh
cargo build --workspace
CRABC_RESOLVER_NETWORK_ISOLATED=1 \
python3 compat/resolver-network/run.py
```

The helper tests need only the Python standard library and do not require a
musl tree or crabc build:

```sh
PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s compat/resolver-network -p 'test_*.py'
```

Useful overrides:

```sh
CRABC_RESOLVER_NETWORK_ISOLATED=1 \
MUSL_ROOT=/opt/musl-1.2.6 \
CRABC_TARGET_DIR=/workspace/target/debug \
python3 compat/resolver-network/run.py \
  --report /tmp/resolver-network.json
```

The command exits `0` only when both binaries exit `0`, both exact streams
match the fixed contract, and the local DNS event contract is satisfied. It
exits `1` for a differential/contract failure and `2` for setup errors. The
runner does not run Docker, `dev.sh`, formatters, linters, or pre-commit
hooks.

A failure is intentionally retained as evidence: the report keeps the raw
streams and server events, including a missing TCP retry or an incomplete
resolver run. This allows the current resolver implementation's malformed-
packet/TC behavior to be observed without changing libc as part of the
harness.

## Report contract

The JSON report has `schema_version: 1` and includes:

* `reference` and `candidate` exit statuses plus byte length, SHA-256, and
  decoded text for stdout/stderr;
* `comparisons` for status/stdout/stderr equality and each fixed workload
  contract;
* `dns_server.ready`, the server `event_contract`, and the complete event
  list (including `tc_udp_truncated_seen` and `tc_tcp_retry_seen`); and
* `contract` text naming resolver configuration, DNS behavior, and network
  behavior.

The network assertions are part of the exact stdout contract: ancillary-data
receipt, epoll readiness, shutdown EOF, short writes, receive timeout, and
EINTR each have a fixed output line. A discrepancy remains visible in the raw
reference/candidate streams and status instead of being normalized away.

The report is written to a same-directory temporary file, flushed and fsynced,
then published with `os.replace`, so readers never observe a partial JSON
document.
