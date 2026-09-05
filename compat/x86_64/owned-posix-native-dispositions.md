# Finite native POSIX profile dispositions

The native aggregate distinguishes raw upstream success from qualification
under an existing compatibility profile. Original OS-test and libc-test
sources, reports, counts, exit statuses and diagnostic streams remain intact.
A qualified profile difference is never an upstream pass or an excluded unit.
`owned_posix_native_dispositions.py` owns the complete finite difference set;
`owned_posix_native_observations.py` still validates every source, object,
link, execution root, raw outcome and oracle observation.

Only these two source boundaries may have a profile disposition:

* OS-test `basic/unistd/{seteuid,setegid,setreuid,setregid}.out`: pinned musl
  reports `exit: 0`; the candidate reports the exact alias and `ENOTSUP`.
  The existing profile requires `-1/EOPNOTSUPP` without any ID mutation.
  The full family matrix is mandatory. All three source-identical
  `credentials-profile` replays must retain their direct-setter and alias
  observations in all six modes. The installed product's four dynamic entries
  are explicitly bound to the native aggregate's selected product.
* libc-test `functional/crypt`: all 32 active calls in the fixed pinned source
  remain present. Twelve legacy-format calls and sixteen unsupported SHA
  setting calls require an actual nonnull `*` result. Two invalid-bcrypt
  markers and the two supported SHA low-round vectors remain exact upstream
  matches. The original unit therefore retains its 28 exact diagnostics and
  raw failure. No additional failure, missing diagnostic, changed result,
  matched oracle failure, timeout, missing source entry or failed setup can
  acquire this disposition.

The bounded adapter parses decimal rounds and normalizes values below 1000 to
1000 before validating RustCrypto parameters. It rejects excessive or
unparseable round values. Empty salts, extra fields, noncanonical salt text
and overlong salts are distinct restrictions; low rounds are not classified
as unsupported. The fixed reference includes the upstream license and exact
source provenance. Qualification requires the fresh prepared `crypt.c` to
match those reference bytes. The observer is separately generated and never
substitutes for the original test.

`run_owned_crypt_runtime.sh` retains its existing canonical ABI fixture and
adds one independent same-object 32-vector observer. The observer records
actual pointer nullness and output bytes for every vector. Its pinned-musl
process and four owned dynamic entries have separate exact expected outputs,
and each must exit zero with no unexpected diagnostics. The existing ABI
fixture additionally proves canonical SHA-256/SHA-512 default and explicit
rounds, public/private symbol ownership, rejection boundaries, buffer guards,
null behavior and overlapping inputs. `owned_crypt_profile.py` reconstructs
`crypt-profile.json` from physical source/header/object/link/product-copy and
raw execution evidence; a success marker alone is insufficient.

The native coordinator requires both the complete family `execution.json`
and `--crypt-profile RECEIPT` before creating output. The crypt companion must
consume the identical installed product. Its raw source, product and receipt
identities join the before/after input seals.

The state transition is explicit:

1. An ordinary component has raw success and qualification `passed`.
2. Only OS-test or libc-test may retain raw exit 1 and raw failure while an
   independently reconstructed qualification is `profile-qualified`.
3. Missing or invalid companion evidence, an unexpected raw outcome or any
   other failure stops execution and retains `incomplete.json`.
4. Only the five fully checked component qualifications can establish
   `native_aggregate_complete`. Family, campaign and public-support flags
   remain false.

Host validation reconstructs these facts without executing a target, compiler,
or Docker. The existing family credentials transcript judge remains a source-owned
Python helper; it never invokes the target. No classification changes the frozen AArch64 baseline or
expands public x86 support.
