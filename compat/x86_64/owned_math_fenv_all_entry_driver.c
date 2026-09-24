/*
 * Installed-product composition for the four complete C math/fenv capability
 * surfaces.  The existing probes remain their own source-oracle observations;
 * this driver fixes their order, captures one installed-header object set, and
 * restores a non-default caller environment around every probe.
 *
 * The scope includes elementary-long-double `sqrtl` and complex `csqrt*`.
 * It deliberately does not add the separate scalar sqrt/sqrtf fenv probe.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#pragma STDC FENV_ACCESS ON

typedef int (*probe_function)(void);
typedef int (*record_emitter)(void);
typedef const uint64_t *(*record_accessor)(size_t *length);

int crabc_x86_64_math_elementary_long_double_probe(void);
int crabc_x86_64_math_elementary_fenv_sensitive_aggregate_probe(void);
int crabc_x86_64_fenv_rounding_probe(void);
int crabc_x86_64_fdim_probe(void);
int crabc_x86_64_math_exp10_probe(void);
int crabc_x86_64_math_exp10f_probe(void);
int crabc_x86_64_math_long_double_completion_probe(void);
int crabc_x86_64_math_special_probe(void);
int crabc_x86_64_math_complex_complete_probe(void);
int crabc_x86_64_math_abi_boundary_probe(void);

/* The decimal probes retain ownership of their data and exact extents. */
const uint64_t *crabc_x86_64_math_exp10_record_data(size_t *length);
const uint64_t *crabc_x86_64_math_exp10f_record_data(size_t *length);

#define STAGE_MAGIC UINT32_C(0x4d464131) /* "MFA1" */

enum stage_id {
	STAGE_FENV_AGGREGATE = 1,
	STAGE_FENV_ROUNDING,
	STAGE_FDIM,
	STAGE_EXP10,
	STAGE_EXP10F,
	STAGE_LONG_DOUBLE_COMPLETION,
	STAGE_ELEMENTARY_LONG_DOUBLE,
	STAGE_SPECIAL,
	STAGE_COMPLEX,
	STAGE_ABI_BOUNDARY,
};

enum stage_phase { STAGE_BEGIN = 1, STAGE_END = 2 };

struct __attribute__((packed)) stage_record {
	uint32_t magic;
	uint16_t stage;
	uint16_t phase;
	int32_t status;
	uint32_t rounding;
	uint32_t exceptions;
};
_Static_assert(sizeof(struct stage_record) == 20, "stable installed math stage record");

static int write_all(const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length != 0) {
		ssize_t count = write(1, cursor, length);

		if (count <= 0)
			return -1;
		cursor += (size_t)count;
		length -= (size_t)count;
	}
	return 0;
}

static int emit_stage(enum stage_id stage, enum stage_phase phase, int status)
{
	struct stage_record record = {
		.magic = STAGE_MAGIC,
		.stage = (uint16_t)stage,
		.phase = (uint16_t)phase,
		.status = status,
		.rounding = (uint32_t)fegetround(),
		.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT),
	};

	return write_all(&record, sizeof(record));
}

static int emit_record_data(const uint64_t *records, size_t length)
{
	return records == (const uint64_t *)0 || length == 0 ? -1 :
		write_all(records, length);
}

static int emit_record_data_from_accessor(record_accessor accessor)
{
	size_t length = 0;
	const uint64_t *records = accessor(&length);

	return emit_record_data(records, length);
}

static int emit_exp10_records(void)
{
	return emit_record_data_from_accessor(crabc_x86_64_math_exp10_record_data);
}

static int emit_exp10f_records(void)
{
	return emit_record_data_from_accessor(crabc_x86_64_math_exp10f_record_data);
}

static int invoke_stage(enum stage_id stage, probe_function probe,
	record_emitter emitter, const fenv_t *caller, int caller_round,
	int caller_exceptions)
{
	int status;

	if (emit_stage(stage, STAGE_BEGIN, 0) != 0)
		return 1;
	status = probe();
	if (status == 0 && emitter != (record_emitter)0 && emitter() != 0)
		status = -1;
	if (fesetenv(caller) != 0 && status == 0)
		status = -2;
	if (status == 0 && (fegetround() != caller_round ||
		fetestexcept(FE_ALL_EXCEPT) != caller_exceptions))
		status = -3;
	if (emit_stage(stage, STAGE_END, status) != 0 && status == 0)
		status = -4;
	return status;
}

int main(void)
{
	fenv_t original;
	fenv_t caller;
	int caller_round;
	int caller_exceptions;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetround(FE_UPWARD) != 0 ||
		feclearexcept(FE_ALL_EXCEPT) != 0 ||
		feraiseexcept(FE_DIVBYZERO | FE_INEXACT) != 0)
		return 1;
	caller_round = fegetround();
	caller_exceptions = fetestexcept(FE_ALL_EXCEPT);
	if (caller_round != FE_UPWARD ||
		caller_exceptions != (FE_DIVBYZERO | FE_INEXACT) ||
		fegetenv(&caller) != 0) {
		(void)fesetenv(&original);
		return 2;
	}

	status = invoke_stage(STAGE_FENV_AGGREGATE,
		crabc_x86_64_math_elementary_fenv_sensitive_aggregate_probe,
		(record_emitter)0, &caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_FENV_ROUNDING,
			crabc_x86_64_fenv_rounding_probe, (record_emitter)0,
			&caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_FDIM, crabc_x86_64_fdim_probe,
			(record_emitter)0, &caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_EXP10, crabc_x86_64_math_exp10_probe,
			emit_exp10_records, &caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_EXP10F, crabc_x86_64_math_exp10f_probe,
			emit_exp10f_records, &caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_LONG_DOUBLE_COMPLETION,
			crabc_x86_64_math_long_double_completion_probe, (record_emitter)0,
			&caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_ELEMENTARY_LONG_DOUBLE,
			crabc_x86_64_math_elementary_long_double_probe, (record_emitter)0,
			&caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_SPECIAL, crabc_x86_64_math_special_probe,
			(record_emitter)0, &caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_COMPLEX,
			crabc_x86_64_math_complex_complete_probe, (record_emitter)0,
			&caller, caller_round, caller_exceptions);
	if (status == 0)
		status = invoke_stage(STAGE_ABI_BOUNDARY,
			crabc_x86_64_math_abi_boundary_probe, (record_emitter)0,
			&caller, caller_round, caller_exceptions);
	if (fesetenv(&original) != 0 && status == 0)
		status = 3;
	return status == 0 ? 0 : 64;
}
