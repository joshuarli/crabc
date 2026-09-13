# Owned errno and h_errno storage lifecycle

`run_owned_errno_storage_lifecycle.sh` is the installed native x86 evidence
for the selected C `errno` and `h_errno` storage boundary. It consumes a
supplied static product and a supplied dynamic product; product authentication
remains the responsibility of `owned_posix_product_evidence.py`.

The workload is compiled through the supplied installed headers. Its static
object is linked unchanged with pinned musl and with the candidate static and
static-PIE products. Its dynamic object and loaded DSO object are each linked
unchanged with pinned musl and the supplied dynamic product, then run from
separate contained roots through kernel and direct-loader entry for PIE and
non-PIE applications.

The component checks four narrow facts.

- `__errno_location` locates independent zero-initialized main and live
  selected-worker slots. With `x86-allocator-runtime`,
  `___errno_location` is musl's archive-only weak hidden same-address alias;
  `owned_errno_private_aliases.list` is the exact shared-link-only LLD input
  that localizes it as `LOCAL DEFAULT` out of `.dynsym`. It remains separate
  from musl's public `owned_dynamic.list` interposition exceptions and the
  fixed-C mimalloc localization list.
- `h_errno` remains the link-visible four-byte main fallback object and
  `__h_errno_location` selects independent live-worker storage. The selected
  implementation intentionally does not claim musl's complete TCB layout or
  foreign-thread/dynamic-TLS parity.
- Repeated accessors return stable locations while the owning thread is live;
  the loaded DSO reaches those locations only through public accessors. The
  workload never dereferences a worker pointer after `pthread_join` may have
  released its storage.
- The selected `pthread_tryjoin_np` live-worker `EBUSY` path is a positive
  pthread error and leaves the caller's `errno` unchanged, as documented by
  `pthread_create_join.rs`.

Pinned musl's static-PIE toolchain is retained as an ELF/link input but is not
an execution oracle here: the pinned compiler's own zero-workload static-PIE
binary faults before `main` in the native evidence image. Candidate static-PIE
execution remains covered. This is a toolchain observation, not a claim about
errno storage.

The runner leaves its command, object seals, ELF symbols, link receipts, roots,
and transcripts below `.work/x86_64`. `owned_errno_storage_lifecycle.py`
collects and replays the closed receipt. It proves alias section/value identity
inside each independently linked artifact; musl and candidate addresses are
not compared across separate link layouts.
