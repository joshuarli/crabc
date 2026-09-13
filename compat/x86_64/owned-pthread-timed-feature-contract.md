# Owned pthread timed-feature receipt

`run_owned_pthread_timed_feature_contract.sh` collects one non-promoting native
receipt for these four public/implementation pairs:

- `pthread_cond_timedwait` → `__pthread_cond_timedwait`
- `pthread_mutex_timedlock` → `__pthread_mutex_timedlock`
- `pthread_timedjoin_np` → `__pthread_timedjoin_np`
- `pthread_tryjoin_np` → `__pthread_tryjoin_np`

The receipt is separate from `owned_pthread_alias_contract_reader.py`. That
older 17-alias receipt remains the authority for its roster and its historical
input identity; this component neither expands nor relabels it.

## Evidence boundary

The reader seals the current collector source identity, the supplied selected
product report, the exact supplied static and dynamic product bytes, pinned
musl archive/shared inputs, exact command arguments, a closed runner environment
and /dev/null standard input, linker maps and receipts, actual ELF symbol
tables, and the five executable modes: static,
static PIE, musl dynamic PIE/non-PIE, and crabc dynamic PIE/non-PIE. A finite
validator-owned pinned-image manifest seals every runner/oracle/compiler tool,
including the invoked LLD path, bytes, and mode. Static link receipts bind the
contract object, owned CRT objects, selected `libc.a`, builtins archive, linker
output, and extraction trace. The retained map is replayed against exact
contract, CRT, archive-member, and builtins inputs; the four public providers
keep their `WEAK DEFAULT` forms and the four owned providers must change from
`GLOBAL HIDDEN` inputs to `LOCAL HIDDEN` final definitions. Final dynamic
outputs must import each public `FUNC GLOBAL DEFAULT` name and must not expose
the private provider. `owned_pthread_timed_dynamic_authority.py` additionally
binds the complete finite contract probe implementation in each dynamic output:
the eleven function bodies, local data and constant geometry, and their
admitted PC-relative and PLT/GOT relocation forms.

`owned_pthread_timed_feature_contract_reader.py --collect-native` is the sole
receipt-producing entry point. Before Bash starts, it invokes the runner from
a Python `subprocess.run` call with one literal allowlisted environment and
`/dev/null` standard input. The sealed environment record includes the sole
Git `safe.directory` configuration for `/workspace` and the four values Bash
creates (`PWD`, `OLDPWD`, `SHLVL`, and `_` for the pinned Python interpreter).
Toolchain-routing variables and exported shell functions from a caller cannot
reach the runner. A direct shell invocation remains a diagnostic command; it
does not establish a retained receipt.

The static driver permits only relative receipt names. The runner changes into
the receipt work directory only for that driver invocation, so each receipt
records its map and trace as a sibling basename. The product validator resolves
those names from the receipt's physical parent and rejects a checkout-relative
path nested below that parent.

`owned_pthread_timed_feature_contract_reader.py` also checks the source feature
route: the `x86-owned-static-runtime` parity entry, `libc/Cargo.toml`, the
fixed builder argument pair `--features x86-owned-static-runtime`, and the four
source `.hidden`/`.weak`/`.set` forms. It retains the entire supplied
static-preparation cohort, including both source seals, all six successful step
sidecars, primary/reproduction/extracted product trees, and both package
archives. `owned_posix_static_products.validate_receipt` replays that cohort
against a physical selected source tree materialized solely from retained
selected Git commit/tree/blob objects. This binds the selected archive to the
actual successful `primary-build` outer invocation and source identity. The
replayed primary tree's static manifest, driver, two entry objects, prologue,
epilogue, builtins archive, and `libc.a` must exactly match the supplied static
inputs that the component then links. The nested feature argument remains a
source-derived builder contract rather than an independently recorded nested
argv; this receipt does not broaden that distinction.

The current native collection invokes
`owned_posix_product_evidence.validate_link` for the two static and two
dynamic output receipts. Its source-owned link-input mode projection fixes all
six static inputs to `0644`, and fixes six dynamic CRT/archive inputs to `0644` with
`usr/lib/libc.so` at `0755`. Replay compares the retained role modes to that
Git-bound projection; it never treats a copied product tree's own record as
mode authority. The component additionally fixes the two drivers and owned
loader at `0755`, keeps `contract.o` at `0644`, and requires each final
contract executable at `0755`. Before each chroot run, the runner materializes
the root and every directory at `0755`; dynamic payload files are `0644` apart
from its driver, loader, and `libc.so`, which are `0755`. The retained tree
record replays those root, directory, file-byte, and file-mode facts.

The installed-header probe checks only these ordinary outcomes:

- expired and successful `pthread_mutex_timedlock` calls;
- expired and signalled successful `pthread_cond_timedwait` calls, including a
  forced first spurious success while the mutex remains held and a predicate
  loop using the original absolute deadline;
- `pthread_tryjoin_np` busy result ownership and one released-target result
  delivery without a second join of the consumed handle;
- timed-join timeout/result preservation, successful result delivery, and a
  cancelled joining thread leaving its target joinable. The cancellation case
  establishes cancellation around `pthread_timedjoin_np`; it has no handshake
  that claims cleanup after a proven blocked wait.

The runner captures the collector source before and after collection. That
identity names the code that performed this collection; Git object bytes and
modes authenticate the retained reader, probe, runner, image manifest, and
their imported ELF/static authority. Separately, the report keeps the supplied
product anchor's selected fed source identity and copies the eight source leaves
directly from that selected revision before evaluating the feature route. The
two identities are intentionally distinct when a successor collector replays
frozen fed products; neither is relabelled as the other. Its retained v1
historical-input record is explicitly marked
`used_for_selected_products: false`; it supplies no current source or product
qualification.

## Limits

The receipt has `public_support`, `family_complete`, and `promotion_ready` set
to false. It does not qualify other pthread aliases, scheduler/fork/lifetime
semantics, every cancellation path, a general pthread family, an unrecorded
nested builder invocation, or a current selector cohort. The artifact only
supports a selector join after the selector independently binds its current
source, product, mode, and all other required feature obligations.
