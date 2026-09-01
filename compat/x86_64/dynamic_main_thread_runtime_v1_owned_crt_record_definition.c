/* A deliberately recognizable owned-CRT record definition in a dependency.
 * The bridge must never reach ordinary lookup for Scrt1's exact optional
 * weak import, so this non-null definition cannot become its rtld_fini wire.
 */

typedef unsigned int u32;
typedef unsigned long long u64;

struct owned_crt_handoff_v1 {
	u64 magic;
	u32 version;
	u32 abi_size;
	void (*dependency_constructors)(void);
	void (*process_fini)(void);
};

static void definition_dependency_constructors(void) {}
static void definition_process_fini(void) {}

__attribute__((visibility("default")))
const struct owned_crt_handoff_v1 __crabc_x86_64_owned_crt_handoff = {
	.magic = 0x43524142435f4831ULL,
	.version = 1,
	.abi_size = sizeof(struct owned_crt_handoff_v1),
	.dependency_constructors = definition_dependency_constructors,
	.process_fini = definition_process_fini,
};
