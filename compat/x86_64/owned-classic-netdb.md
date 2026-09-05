# Owned classic host and service lookup

The owned native Linux/x86-64 products provide `gethostbyname`,
`gethostbyname2`, `gethostbyaddr` and their `_r` variants, `getservbyname`,
`getservbyport` and their `_r` variants, `gethostent`, `getnetent`,
`getnetbyname`, `getnetbyaddr`, and `herror`. Owned `getaddrinfo` and
`getnameinfo` share their allocation-free name/service backends. The private
archive implementations, Rust facade snapshots and public AArch64 boundary
retain their existing contracts.

These are conventional Unix/C ABI interfaces. Host lookup reads `/etc/hosts`
and fresh `/etc/resolv.conf` state; service lookup reads `/etc/services`.
No NSS, nscd, provider plugins, general network database, global DNS cache,
locale database, or new dependency is introduced. As in musl, the four
host/network enumeration and network-name/address entries return null without
reading arguments or changing errno/h_errno. Existing setter/terminator
providers retain their no-op behavior.

The fixed source is musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT license. Its release
archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`;
`compat/upstreams.toml` owns the repository pin and license provenance.

| Musl source/function | Owned source target |
| --- | --- |
| `src/network/lookup_ipliteral.c`: `__lookup_ipliteral` | `owned_netdb_lookup.rs::numeric` and existing inet/interface/integer owners |
| `src/network/lookup_name.c`: null, numeric, hosts, DNS/search backends and destination policy | `owned_netdb_lookup.rs::{names,hosts,dns,dns_search,sort_addresses}` |
| `src/network/lookup_serv.c`: `__lookup_serv` | `owned_netdb_lookup.rs::services` |
| `src/network/resolvconf.c`: `__get_resolv_conf` | `owned_netdb_lookup.rs::configuration` |
| `src/stdio/{__fopen_rb_ca,__fclose_ca}.c` | `owned_static_stdio.rs::with_readonly_file`, existing non-canceling FILE reader |
| `src/network/gethostby{name,name2,addr}{,_r}.c` | Corresponding entries and `static_host` in `owned_classic_netdb.rs` |
| `src/network/getservby{name,port}{,_r}.c` | Corresponding entries in `owned_classic_netdb.rs` |
| `src/network/{ent,netname,herror}.c` | Empty lookup entries and `herror` in `owned_classic_netdb.rs` |
| `src/network/getnameinfo.c`: reverse files, PTR, numeric scope and output sizing | `owned_classic_netdb.rs::{getnameinfo,reverse_hosts,reverse_services,reverse_question}` |
| `src/network/getaddrinfo.c`: hints, ADDRCONFIG, lookup ordering, output assembly | `owned_classic_netdb.rs::getaddrinfo`, `numeric_netdb.rs::{append_node,set_owned_scope,freeaddrinfo}` |

Forward lookup preserves historical IPv4 literal spelling, IPv6 scope parsing,
case-sensitive hosts matching, the first valid canonical spelling even on a
wrong-family matching line, source-order addresses capped at 48, and wrong
family NO_DATA. DNS search stops on any nonzero result, including NODATA;
only NXDOMAIN permits another suffix or the bare name. Dotted names at or
above ndots do not enter search. A and AAAA outcomes are interpreted in source
family order: an earlier A NXDOMAIN wins over a later AAAA timeout, whereas an
A timeout wins over an AAAA NXDOMAIN. The fixed scalar source destination
policy orders mixed/IPv6 results through route observations. Reentrant lookup
uses caller storage and leaves h_errno untouched unless the caller explicitly
passes that slot as its error output.

Host `_r` wrappers preserve the source's conservative exact buffer thresholds,
alignment, result-null behavior, partial record writes on ERANGE, aliases,
address-list layout, and errno/error-output precedence. Forward and reverse
non-reentrant host calls have separate heap owners. Each starts allocation at
127 bytes and doubles-plus-one on ERANGE, freeing the previous owner before
the next allocation, as musl does. Callers serialize each owner and borrow its
results only until the next call, including failed calls. Independent `_r`
lookups do not use either owner.

Service lookup preserves source file order, protocol-prefix parsing and
numeric-name rejection precedence. `getservbyname_r` borrows the requested
name pointer, whereas `getservbyport_r` borrows the requested protocol pointer
and places its name in the caller buffer. Null-protocol reverse lookup tries
TCP before UDP. The non-reentrant name and port owners are separate; the
source's 32-byte port buffer can reject names that a larger `_r` buffer accepts.
Reverse host lookup compares mapped IPv4/IPv6 addresses and scope, tries PTR
when needed, then emits numeric output unless NI_NAMEREQD forbids it.

The stack FILE adapter initializes self-referential buffers only after the
record reaches its final stack frame. Its callback cannot retain, move or
publicly close the FILE. It uses usable capacities of 1024 bytes for databases
and 248 bytes for resolv.conf (source buffer length minus UNGET), bypasses
internal stream locks with the source's private lock=-1 sentinel, never
registers a stream or allocates, and closes the descriptor on normal return.
The redundant raw F_SETFD operation ignores both its result and errno; close
uses the source's errno-publishing syscall path.

Two established transport/ownership adaptations remain explicit. DNS framing,
query encoding, bounded retry/failover and TCP fallback use the shared
`crabc-core::resolver` transport. Family queries run sequentially rather than
musl's parallel msend; their outcomes retain source interpretation order.
The existing `DnsResponse::rdata_at` interface extracts address records by
type and then CNAME records. Normal CNAME/address behavior and malformed
transport framing are proved, but musl's callback interleaving after a
malformed address RDLENGTH is not qualified: the source can stop parsing
before a later CNAME, whereas grouped extraction can still inspect it. This
exact parser-order gap remains a resolver-family qualification obligation.
The owned adapter distinguishes local socket-creation errno from exhausted
transport attempts without creating probe sockets. Existing native
`exchange` keeps its prior timeout behavior. Owned C callers now use the
separate [resolver cancellation owner](owned-resolver-cancellation.md): real
send/receive/poll cancellation points, explicit descriptor cleanup, MASKED
state transitions, and source TCP-start ordering. Native Rust and the private
archive retain raw transport behavior. Source masks around destination sorting
and AI_ADDRCONFIG are retained; complete resolver-family source parity remains
unclaimed. Addrinfo allocation/free retains the existing opaque
page-per-node owner, including IPv6 scope; all nodes share the first node's
canonical-name pointer as in musl. It does not import musl's private aibuf
layout or replace freeaddrinfo.

Run `./scripts/dev-x86_64.sh owned-classic-netdb [DYNAMIC_SYSROOT]`. Without an
argument, pinned product preparation precedes network isolation. One ordinary
installed-header application object links to pinned musl and owned static,
static-PIE, dynamic PIE and dynamic non-PIE; both dynamic artifacts run through
kernel and direct interpreter entry. Twenty cases run in disposable private
chroots with fixture-owned `/etc`, in a loopback-only network namespace. They
cover numeric/local/DNS lookup, buffer bounds, large host records, search and
mixed-family failure precedence, reverse files/PTR, services and pointer
identity, file/read/access/socket/fcntl errors, empty providers and herror,
modern addrinfo behavior, `_r` concurrency, fork owner isolation and heap
exhaustion. Every process exit, raw stdout/stderr comparison, ELF provider,
DNS event and ordinary installed-driver receipt is retained. Standalone
execution requires Docker network-none plus SYS_CHROOT.

The `classic-netdb` dynamic qualification case accepts a supplied installed,
relocated or extracted product. Its exact command alone is prefixed with
`unshare --user --map-root-user --net`, then the fixed
`classic_netdb_namespace.py` helper brings `lo` up and execs the leaf. It
records the command, exact private TMPDIR, and live loopback/namespace proof.
Before unshare, the invoking container creates a fresh per-case scratch
directory under the prepared work; namespace root can write it without
changing the shared host-owned TMPDIR or any of its permissions. It uses the enclosing
materialization runner's existing namespace authority; no NET_ADMIN grant or
other qualification case changes. Product building and dependency fetching
never occur in that isolated supplied-product phase. This case registration
is a required evidence obligation, not a completed three-product qualification
or resolver-family/public-support claim.

Provider accounting adds the fifteen names to the owned-static feature,
records the two modern replacements, removes the deferred names, and refreshes
the callable inventory/disposition/visibility and derived ledger digest.
The frozen AArch64 source baseline is neither executed nor changed.
