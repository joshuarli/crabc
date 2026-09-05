# Owned resolver cancellation

This slice makes the existing DNS transport a deferred C cancellation point
for owned x86-64 resolver and netdb callers. It does not change the native Rust
`crabc_core::resolver::exchange` contract, replace the DNS engine, or claim
general resolver source parity. The C owner covers `res_send`, `res_query`,
classic host lookup and modern forward/reverse lookup. Installed qualification
uses one application object for pinned musl and all owned entry modes.

## Source contract

The oracle is musl 1.2.6, release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT. Its release archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
Source mapping for the proposed adapter is:

| Source | Owned responsibility |
| --- | --- |
| `src/network/res_msend.c`, `__res_msend_rc`, `cleanup` | Disable cancellation before acquiring descriptors; install a C cleanup record before any cancellation point; close every live resolver descriptor on cancellation and normal retirement. |
| `src/network/sendto.c`, `sendmsg.c`, `recvmsg.c` | Nonblocking DNS sends and receives still cross the syscall cancellation window. A wait-only adapter misses pending cancellation before the first packet. |
| `src/select/poll.c` | Blocked DNS waits cross the syscall cancellation window, with the remaining deadline retained on retry. |
| `src/thread/pthread_cancel.c`, `__cancel`, `__syscall_cp_c` | Enabled pending cancellation retires the thread; MASKED cancellation returns `ECANCELED` and changes the state to DISABLE. |
| `src/network/res_send.c`, `res_query.c` | A MASKED initial send leaves `errno=ECANCELED` visible after the transport times out; `res_query` additionally maps absent answers to `h_errno=TRY_AGAIN`. |

Musl disables cancellation before initial socket creation/bind, registers its
cleanup, and restores the entry state. Its first cancellation point is the
initial UDP send. It ignores that send's negative result, then waits until the
retry deadline. Thus a pending MASKED request sends no packet, consumes the
request by changing state to DISABLE, and normally returns after the deadline.
The adapter must preserve this observable transition, not abort immediately
or repeatedly restore MASKED around later waits.

Musl treats canceled I/O according to the operation: a nonpositive poll result
continues the outer wait/retry loop; a negative UDP receive leaves its receive
loop and returns to polling; a negative TCP send or nonpositive TCP receive
retires the transport. These distinctions must not be hidden by translating
every `ECANCELED` to one generic transport error.

TCP setup is explicitly disabled in musl. On leaving `start_tcp`, musl restores
the original entry state, even if an earlier MASKED cancellation had changed
the running state. Normal function retirement does not restore the entry
state. Tests must distinguish these two restoration rules.

## Transport boundary

The DNS-specific transport boundary in `crabc-core/src/resolver.rs` is used by
an additional owned-C exchange entry. The existing native exchange entries
retain their raw syscall implementation and results. The owned implementation
lives in `libc/src/c_abi/x86_64/owned_resolver_transport.rs` and is compiled only
for the owned x86-64 products. The private archive keeps its existing path.

The boundary carries descriptor lifecycle notifications plus typed DNS wait,
send, and receive operations. It is not an arbitrary syscall hook or generic
platform interface. Each operation must execute the actual kernel operation
through `pthread_cancel::syscall_cp`; a separate `pthread_testcancel` before a
raw blocking syscall would leave a cancellation race and mishandle MASKED.
The operation result must distinguish a MASKED cancellation from an ordinary
I/O error so the shared transport can take the source-specific action above
without manufacturing a successful syscall result.

The lifecycle consists of these explicit transitions:

1. The C adapter disables cancellation and saves the entry state. Its stack
   storage includes separately pinned `MaybeUninit<CleanupNode>` and
   `CleanupDescriptor` allocations, with the descriptor Cell initialized to
   `-1`. It pushes the node at its final address before entering the shared
   transport. The callback borrows only the Cell, avoiding an alias to the
   mutable transport borrow live at a retiring syscall.
2. The shared transport creates sockets while cancellation is disabled and
   immediately reports each acquired descriptor. Existing core transport has
   at most one live socket and closes UDP before opening TCP. Retain this
   invariant rather than importing musl's parallel socket layout.
3. Immediately around each DNS cancellation-point syscall, the adapter
   restores its current resume state. After a returning syscall it disables
   cancellation again, captures the actual post-call state, and uses that
   state for the next ordinary operation. This captures MASKED → DISABLE.
4. TCP setup remains disabled. A distinct TCP-setup-complete transition resets
   the resume state to the original entry state, matching `start_tcp` above.
   This includes musl's initial `sendmsg(MSG_FASTOPEN)` attempt, not just
   socket creation and connect. Use the source-mapped `start_tcp` operation
   below; do not disable cancellation around arbitrary later frame sends.
5. Normal close occurs while disabled, clears the registered descriptor slot,
   and uses the existing raw close path. After exchange returns, pop the
   cleanup without executing it and restore the final resume state. Initial
   setup failure restores the original entry state.
6. Cancellation drains the registered C cleanup chain. The adapter callback
   takes its descriptor, marks it retired, and issues raw close. It does not
   touch errno, allocate, reenter DNS, or depend on Rust unwinding/destructors.

The node's callback argument points only to the pinned adapter storage. Core
buffers and sockaddr/iovec storage are stack-owned and valid through each
syscall. Review every caller before enabling this path: no held lock or
unregistered heap allocation may require Rust stack unwinding on cancellation.
Existing classic lookup backends are allocation-free before result building.

Route owned `resolver_runtime::__res_send` and `owned_netdb_lookup` transport
calls through this adapter. Preserve a consumed-MASKED marker and the actual
subsequent syscall errno through their existing timeout/error translation.
For pending initial cancellation this prevents overwriting `ECANCELED` with
`ETIMEDOUT` or lookup scratch errno. A later failed syscall can supersede
`ECANCELED`, so the marker must not unconditionally force errno 125 on every
return. This is a cancellation-specific rule; ordinary timeout errno
differences remain outside this slice.

`DnsTransport::syscall_failed` observes raw core socket creation, UDP connect,
and monotonic-clock failures. The owned TCP start records its socket-option,
fast-open-send and connect failures directly. `socket_error` is used only by
the unchanged native TCP path; raw close deliberately does not publish errno.
Thus a later real DNS syscall error is not lost merely because it occurs
outside an I/O callback. An arbitrary kernel/seccomp `ECANCELED` is not
classified as MASKED cancellation: the adapter also requires the actual
MASKED-to-DISABLE state transition around that syscall.

## Concrete operation signatures and TCP transition

The core entry is `exchange_with_transport(config, query, query_id,
answer, transport: &mut impl DnsTransport) -> Result<usize, ExchangeError>`.
The transport supplies these safe methods; all buffer lifetimes are ordinary
borrowed slices, and the destination is a core-built immutable
`DnsSocketAddress` with family and initialized sockaddr-byte accessors:

```rust
enum DnsIoResult<T> { Complete(T), Failed(Errno), MaskedCancellation }
enum DnsSocketKind { Datagram, Stream }
enum DnsWait { Readable, Writable }
struct DnsDatagram { length: usize, truncated: bool }
enum DnsTcpStart {
    // Native raw connect completed; retain its immediate-send behavior.
    Connected,
    // Source TCP-start queued this many bytes, including the length prefix.
    // If less than the frame size, wait for writable before the next send.
    Queued { frame_bytes: usize },
}
enum DnsTcpFailure { Immediate, WaitUntilDeadline }
trait DnsTransport {
    fn socket_opened(&mut self, fd: i32, kind: DnsSocketKind);
    fn close_socket(&mut self, fd: i32);
    fn syscall_failed(&mut self, error: Errno);
    fn stream_starting(&mut self) -> DnsTcpFailure;
    fn wait(&mut self, fd: i32, event: DnsWait, timeout_ms: u32)
        -> DnsIoResult<bool>;
    fn send(&mut self, fd: i32, bytes: &[u8], kind: DnsSocketKind)
        -> DnsIoResult<usize>;
    fn receive_stream(&mut self, fd: i32, bytes: &mut [u8])
        -> DnsIoResult<usize>;
    fn receive_datagram(&mut self, fd: i32, bytes: &mut [u8])
        -> DnsIoResult<DnsDatagram>;
    fn start_tcp(&mut self, fd: i32, target: &DnsSocketAddress,
        query: &[u8], deadline_ms: i64) -> Result<DnsTcpStart, Errno>;
}
```

The core checks `frame_bytes <= query.len()+2` and advances the existing
two-slice frame sender by this count. This is shared framing/progress logic,
not a second transport loop. UDP `MaskedCancellation` proceeds to the existing
response wait without claiming bytes were sent. Wait and UDP receive masked
results retry their existing deadline; stream send/receive masked results
retire that attempt. The owned adapter records consumed MASKED cancellation
separately for the caller's final state/error translation.

The native implementation of `start_tcp` retains the current raw connect,
writable wait, socket-error check, then returns `Connected`. Owned `start_tcp`
is the small straight-line translation of musl `start_tcp`: cancellation
remains disabled; try `setsockopt(IPPROTO_TCP,TCP_FASTOPEN_CONNECT,1)`; when
available issue the actual `sendmsg` with destination, two frame iovecs, and
`MSG_FASTOPEN|MSG_NOSIGNAL`; return queued bytes on nonnegative result or zero
on `EINPROGRESS`. Otherwise issue connect, returning zero queued bytes on
success or `EINPROGRESS`, and return its error otherwise. Restore the original
entry state as the next resume state after either result. Descriptor cleanup
stays in the shared caller so there is exactly one close owner.

`stream_starting` runs before TCP acquisition and records the original entry
state as the next resume state even if acquisition fails. The owned failed-start
continuation closes any acquired descriptor, then uses the existing deadline
poll with an ignored `-1` descriptor. This is the real CP corresponding to
musl's outer poll with TCP fd `-1` and UDP events zero. The typed native policy
remains an immediate failed attempt. It neither fabricates a successful I/O
result nor introduces a second DNS scheduler. Musl's parallel nameserver and
family scheduler remains distinct from the established configured sequential
core transport. Failed TCP acquisition's ordinary errno details likewise remain
separate; the next real MASKED CP still establishes the required ECANCELED.

`owned_resolver_tcp_transition_probe.c` provides a separate oracle-only
instrumented link. It wraps musl's socket option/connect/sendmsg references to
observe cancellation state, and can force only TCP_FASTOPEN_CONNECT to report
`ENOPROTOOPT`. It is never linked into an owned qualification consumer. On the
pinned native container, the observed sequences are:

```text
available: setsockopt state=DISABLE; fastopen sendmsg state=DISABLE;
           later sendmsg state=ENABLE
forced unavailable: setsockopt state=DISABLE; connect state=DISABLE;
                    later sendmsg state=ENABLE
```

Both paths then reach the witnessed blocked TCP receive wait and cancel with
the resolver descriptors already closed before caller cleanup. Evidence is
`oracle-fastopen-transition.*` and `oracle-connect-transition.*` in the focused
evidence directory. This establishes why the initial source-mapped fastopen
operation is disabled and subsequent shared frame progress remains a CP.

## Regression and installed evidence

`owned_resolver_cancellation_probe.c` is compiled once with installed crabc
headers and linked against both pinned musl and the existing owned static-PIE
product. Execution is in a disposable native x86-64 Docker container with
`--network none`, private chroot conventional files, and local UDP/TCP port 53.
No external DNS or host resolver files are used. Evidence is retained under
`.work/x86_64/tmp/owned-resolver-cancellation.*/` for the canonical gate; the
initial failure and focused implementation evidence used
`.work/x86_64/tmp/cancellation-regression/` and `cancellation-fixed/`.

The server withholds an answer after receiving the UDP request or complete TCP
query frame, then cancels the client. The caller's cleanup counts descriptors
before any user cleanup can close them, proving resolver cleanup ordering.
The descriptor limit is fixed at 512 to bound the complete descriptor scan.
After receiving the request the server observes the worker's blocked `poll`
or `ppoll` syscall through the existing inherited read-only proc descriptor,
then requests cancellation. Receipt alone is not treated as a blocked-wait
witness.
Pending-entry tests queue cancellation while disabled, set the requested
state, call the API, join, and inspect the UDP socket for a transmitted packet.
No client sleep or scheduler-sensitive delay determines cancellation timing.

| Initial same-object case (`res_query`) | Musl | Existing owned product |
| --- | --- | --- |
| Blocked UDP or TCP cancellation | Canceled; cleanup once; no live resolver fd | Normal timeout return; cleanup not invoked |
| Pending ENABLE | Canceled before first packet; cleanup once; no live resolver fd | Sends packet; normal timeout return |
| Pending DISABLE | Normal return; remains DISABLE; packet sent | Same lifecycle; ordinary timeout errno differs |
| Pending MASKED | Normal return; becomes DISABLE; no packet; errno 125 | Remains MASKED; packet sent; errno 110 |

The same blocked and pending-enabled failures reproduced through `res_send`,
`gethostbyname_r`, and `getaddrinfo`. The retained failed-TCP-acquisition test
then exposed immediate EMFILE return after earlier MASKED consumption, while
musl reentered its deadline poll and returned ECANCELED. Both regressions are
kept in `owned_resolver_cancellation_probe.c`.

Run `./scripts/dev-x86_64.sh owned-resolver-cancellation [DYNAMIC_SYSROOT]`.
Without an argument it constructs static and dynamic products before entering
a network-none container. With a product argument it compiles against that
supplied tree and does not build a replacement. The standalone matrix is 18
scenarios across five APIs and seven musl/owned entry arms (630 runs): static
ET_EXEC/static-PIE, and dynamic PIE/non-PIE through both kernel and direct
interpreter entry. The supplied dynamic matrix has five arms (450 runs).

Scenarios cover pending enabled/disabled/MASKED entry; witnessed blocked UDP
and TCP cancellation in all states; MASKED UDP-to-TCP restoration and failed
TCP acquisition; pending initial setup failure; ordinary injected ECANCELED;
successful UDP/TCP, retry, cancellation after retry, and a successful lookup
followed by cancellation on the next lookup. Every retirement checks the
descriptor set and the caller's cleanup order. Separate safe-core tests reject
oversized callback counts, advance every initial TCP frame boundary, and prove
close-before-failed-start-wait ordering.

Raw stdout/stderr, statuses, source/object/product hashes, installed-driver
receipts, ELF/provider audits and namespace proof are retained. Lifecycle and
success observations match musl. Ordinary errno differences for disabled waits,
unconsumed injected ECANCELED, and successful TCP are recorded separately in
`ordinary-errno-differences.json`; they do not waive any consumed-MASKED errno
assertion. The `resolver-cancellation` dynamic qualification leaf additionally
requires its exact newly created user/network namespace and supplied product
path. The fixed classic-netdb namespace entry remains supported through the
shared finite DNS helper. No resolver-family or public-support status changes.
