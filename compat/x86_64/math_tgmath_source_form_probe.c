/* The source-form runner selects either <math.h> or <tgmath.h> directly. */

#ifndef CRABC_MATH_TGMATH_HEADER
#error "source-form runner must select a direct math header"
#endif
#include CRABC_MATH_TGMATH_HEADER

#ifndef math_errhandling
#error "math_errhandling must remain a public math-header macro"
#endif

_Static_assert(sizeof(float_t) >= sizeof(float), "float_t remains usable");
_Static_assert(sizeof(double_t) >= sizeof(double), "double_t remains usable");

#ifdef _TGMATH_H
_Static_assert(_Generic(sqrt(1.0f), float: 1, default: 0),
    "tgmath selects the binary32 sqrt form");
_Static_assert(_Generic(sqrt(1.0L), long double: 1, default: 0),
    "tgmath selects the long-double sqrt form");
#endif

int math_tgmath_source_form_c(double value)
{
    return isfinite(value) + isinf(value) + isnan(value) + isnormal(value);
}
