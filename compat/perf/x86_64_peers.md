# Native performance loopback peers

`compat/perf/x86_64_peers.py` owns the fixed loopback infrastructure for the
seven network rows in `x86_64-profile.toml`. It is deliberately separate from
`run_x86_64.py`: it neither executes a client nor measures it, creates a
cgroup, changes caller affinity, or changes ambient `/etc` files.

The adapter calls `start_context(root, row_id, mode, invocation_work,
client_root, cpu, allowed_affinity, iterations=...)` once for a fresh client
invocation. `invocation_work` and `client_root` must be disjoint physical
subtrees below `.work/x86_64`. The returned context supplies the fixed argv
suffix, resolver-file bytes, peer PIDs, raw `events` destinations, and
`stage_resolver_files()`. Staging writes only `client_root/etc/resolv.conf` and `client_root/etc/hosts`; the
caller chooses how to enter that private root. `stop()` terminates, kills if
necessary, and reaps only its own peer children within finite deadlines. It
returns a retained record, which `validate_context(root, record)` replays
without starting a peer or client.

| Row kind | Fixed peer and retained result |
| --- | --- |
| TCP IPv4, TCP IPv6 | Echo peer at `127.0.0.1:39041` or `[::1]:39042`; one connection and every 4096-byte sequence-checked echo. |
| UDP IPv4, UDP IPv6 | Echo peer at `127.0.0.1:39043` or `[::1]:39044`; every 4096-byte sequence-checked datagram echo. |
| `resolver_hosts` | Existing DNS server on the three private loopback nameservers; exactly zero raw DNS events. |
| `resolver_dns_dual` | Existing DNS server; each server role retains one A-to-AAAA route pair for each lookup. |
| `resolver_dns_tcp` | Existing DNS server; each lookup retains valid/drop/fallback UDP routes and one TCP answer from the valid or fallback responder. |

The DNS replay receives the selected invocation iteration count. It requires
exactly six dual-family events or four TCP-fallback events per iteration and
projects the raw log by server role. Each dual role must retain ordered
A-to-AAAA pairs, and all three role projections must carry the same ordered
query-ID pairs. TCP requires one ordered UDP event per role with the shared
query ID, plus one valid or fallback TCP answer after that answer role's
truncating UDP event. The fixed server selects independent UDP sockets and TCP
workers, so cross-role log interleaving is not itself a client property.
Missing, extra, reversed-within-route, or mismatched-ID events cannot qualify a
reduced or full sample. The hosts row still starts the DNS observer even though
its profile flag does not require a loopback peer, so zero queries are evidence
rather than an assumption.

A retained context binds helper/profile/fixture/DNS source identities, child
PID and raw `/proc/<pid>/status` affinity, readiness, stdout, stderr, event
files, and exit status. Peer artifacts must remain under the invocation work
directory outside the client root. Resolver staging records must name the exact
private `etc` paths, not equivalent bytes elsewhere below the root.

Run the focused reader/lifecycle tests and the reduced native smoke with the
pinned image:

```bash
docker run --rm --init --platform linux/amd64 --network none --cap-add=SYS_CHROOT \
  --workdir /workspace --env PYTHONDONTWRITEBYTECODE=1 \
  --env TMPDIR=/workspace/.work/x86_64/tmp --volume "$PWD:/workspace" \
  crabc-core-evidence:x86_64 python3 -B compat/perf/tests/test_x86_64_peers.py

docker run --rm --init --platform linux/amd64 --network none --cap-add=SYS_CHROOT \
  --workdir /workspace --env PYTHONDONTWRITEBYTECODE=1 \
  --env TMPDIR=/workspace/.work/x86_64/tmp --volume "$PWD:/workspace" \
  crabc-core-evidence:x86_64 python3 -B compat/perf/tests/run_x86_64_peers_smoke.py
```

The smoke compiles only the existing network fixture with the pinned musl
compiler, runs two iterations per row in private chroots, and validates peer
lifecycle evidence. It does not collect benchmark scores.
