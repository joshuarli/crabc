# Owned pthread alias contract

`owned_pthread_alias_contract_reader.py` replays one finite native x86 receipt
for the source-shaped weak public aliases in `libc.a` and `libc.so`. Its fixed
roster has 17 public aliases over 15 implementation-provider spellings. The
reader retains the static and shared same-definition observations separately,
checks the dynamic public surface, and proves that a strong application
`pthread_setcancelstate` override does not replace the internal provider.

The receipt also binds `owned_message_queues::notify_start` to its one public
`pthread_detach` relocation in the selected static archive. It does not turn
`__pthread_detach`, or any other implementation spelling, into an additional
installed ABI identity.

`native_abi_selection.py` may consume a current receipt only with the matching
public ELF/product cohort. It binds the receipt's selected source revision and
all static/dynamic product files to that cohort, then records alias and
`mq_notify` joins. The latter can discharge only the matching ordinary static
import reason. Pthread lifecycle, cancellation, scheduling, family closure,
promotion, and public-support status remain separate requirements.
