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
#include <complex.h>
#include <math.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
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

/* Denormal-operand status is separate from the five ISO exception flags. */
#define ISO_EXCEPT (FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT)

struct worker_result {
	long double rounded;
	long double subnormal;
	float complex conjugate;
	double logarithms[4];
	float narrow_logarithms[4];
	int status;
};

static double (*volatile direct_log10)(double) = (log10);
static float (*volatile direct_log10f)(float) = (log10f);

static int decimal_logarithms_match(const struct worker_result *result)
{
	union { double value; uint64_t bits; } wide;
	union { float value; uint32_t bits; } narrow;

	wide.value = result->logarithms[0];
	narrow.value = result->narrow_logarithms[0];
	if (wide.bits != 0 || narrow.bits != 0)
		return 0;
	wide.value = result->logarithms[1];
	narrow.value = result->narrow_logarithms[1];
	if (wide.bits != UINT64_C(0xfff0000000000000) ||
		narrow.bits != UINT32_C(0xff800000))
		return 0;
	if (!(result->logarithms[3] > 0.3 && result->logarithms[3] < 0.31) ||
		!(result->narrow_logarithms[3] > 0.3f && result->narrow_logarithms[3] < 0.31f))
		return 0;
	wide.value = result->logarithms[2];
	narrow.value = result->narrow_logarithms[2];
	return (wide.bits & UINT64_C(0x7ff0000000000000)) == UINT64_C(0x7ff0000000000000) &&
		(wide.bits & UINT64_C(0x000fffffffffffff)) != 0 &&
		(narrow.bits & UINT32_C(0x7f800000)) == UINT32_C(0x7f800000) &&
		(narrow.bits & UINT32_C(0x007fffff)) != 0;
}

/* The two scalar widths must leave control modes and existing flags intact.
 * Clear only invalid between domain calls so each width must raise it itself. */
static int observe_decimal_logarithms(struct worker_result *result)
{
	fenv_t before, after;
	int flags = fetestexcept(ISO_EXCEPT);

	if ((flags & FE_INVALID) != 0 || fegetenv(&before) != 0)
		return 0;
	result->logarithms[0] = direct_log10(1.0);
	result->narrow_logarithms[0] = direct_log10f(1.0f);
	if (fetestexcept(ISO_EXCEPT) != flags)
		return 0;
	result->logarithms[3] = direct_log10(2.0);
	result->narrow_logarithms[3] = direct_log10f(2.0f);
	flags |= FE_INEXACT;
	if (fetestexcept(ISO_EXCEPT) != flags)
		return 0;
	result->logarithms[1] = direct_log10(-0.0);
	result->narrow_logarithms[1] = direct_log10f(-0.0f);
	flags |= FE_DIVBYZERO;
	if (fetestexcept(ISO_EXCEPT) != flags)
		return 0;
	result->logarithms[2] = direct_log10(-1.0);
	if (fetestexcept(ISO_EXCEPT) != (flags | FE_INVALID) ||
		feclearexcept(FE_INVALID) != 0 || fetestexcept(ISO_EXCEPT) != flags)
		return 0;
	result->narrow_logarithms[2] = direct_log10f(-1.0f);
	if (fetestexcept(ISO_EXCEPT) != (flags | FE_INVALID) ||
		fegetenv(&after) != 0 || after.__control_word != before.__control_word ||
		(after.__mxcsr & ~UINT32_C(0x3f)) != (before.__mxcsr & ~UINT32_C(0x3f)))
		return 0;
	return decimal_logarithms_match(result);
}

static void *math_worker(void *argument)
{
	struct worker_result *result = malloc(sizeof(*result));
	fenv_t environment;
	volatile long double input = 1.5L;
	volatile long double minimum = 0x1p-16382L;
	volatile float narrow = 1.5f;

	(void)argument;
	if (result == 0)
		return 0;
	result->status = 1;
	if (fegetenv(&environment) != 0 ||
		(environment.__control_word & 0x0c00) != FE_DOWNWARD ||
		((environment.__mxcsr >> 3) & 0x0c00) != FE_UPWARD ||
		fetestexcept(ISO_EXCEPT) != FE_DIVBYZERO)
		return result;
	result->rounded = rintl(input);
	if (nearbyintf(narrow) != 2.0f ||
		fetestexcept(ISO_EXCEPT) != (FE_DIVBYZERO | FE_INEXACT))
		return result;
	result->subnormal = fmal(minimum, 0.5L, 0.0L);
	result->conjugate = conjf(CMPLXF(-0.0f, 0.0f));
	if (fetestexcept(ISO_EXCEPT) != (FE_DIVBYZERO | FE_INEXACT))
		return result;
	if (!observe_decimal_logarithms(result))
		return result;
	result->status = 0;
	return result;
}

/* A joined worker's result belongs to its caller; its floating environment
 * remains private even when math calls set flags in the two execution units. */
static int check_worker_environment(void)
{
	fenv_t original;
	fenv_t split;
	fenv_t after;
	struct worker_result parent_result;
	int status = 0;

	if (fegetenv(&original) != 0)
		return 1;
	if (fesetenv(FE_DFL_ENV) != 0 || fegetenv(&split) != 0) {
		status = 2;
		goto restore;
	}
	split.__control_word = (split.__control_word & ~0x0c00) | FE_DOWNWARD;
	split.__mxcsr = (split.__mxcsr & ~0x6000) | (FE_UPWARD << 3);
	if (fesetenv(&split) != 0 || feraiseexcept(FE_DIVBYZERO) != 0) {
		status = 3;
		goto restore;
	}
	if (!observe_decimal_logarithms(&parent_result) ||
		feclearexcept(FE_INVALID | FE_INEXACT) != 0 ||
		fetestexcept(ISO_EXCEPT) != FE_DIVBYZERO) {
		status = 4;
		goto restore;
	}
	for (int iteration = 0; iteration != 2; ++iteration) {
		struct worker_result *result;
		pthread_t worker;
		void *returned = 0;
		union { float value; uint32_t bits; } real, imaginary;

		if (pthread_create(&worker, 0, math_worker, 0) != 0) {
			status = 5;
			break;
		}
		if (pthread_join(worker, &returned) != 0) {
			status = 6;
			break;
		}
		result = returned;
		if (result == 0) {
			status = 4;
			break;
		}
		if (result->status != 0 || !decimal_logarithms_match(result) ||
			result->logarithms[3] != parent_result.logarithms[3] ||
			result->narrow_logarithms[3] != parent_result.narrow_logarithms[3]) {
			free(result);
			status = 7;
			break;
		}
		real.value = crealf(result->conjugate);
		imaginary.value = cimagf(result->conjugate);
		if (result->rounded != 1.0L || result->subnormal != 0x1p-16383L ||
			real.bits != UINT32_C(0x80000000) ||
			imaginary.bits != UINT32_C(0x80000000) ||
			fegetenv(&after) != 0 ||
			(after.__control_word & 0x0c00) != FE_DOWNWARD ||
			((after.__mxcsr >> 3) & 0x0c00) != FE_UPWARD ||
			fetestexcept(ISO_EXCEPT) != FE_DIVBYZERO)
			status = 7;
		free(result);
		if (status != 0)
			break;
	}
restore:
	if (fesetenv(&original) != 0 && status == 0)
		status = 8;
	return status;
}

int main(void)
{
	fenv_t original;
	fenv_t caller;
	int caller_round;
	int caller_exceptions;
	int status = 0;

	if (check_worker_environment() != 0)
		return 4;

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
