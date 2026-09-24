#!/usr/bin/env python3
"""Fixed behavior roster for the installed text/locale/numeric component.

The frozen capability ledger owns the full C ABI inventory.  This component
owns only the finite behavior rows below.  Each row names an existing focused
probe or one of the two differential transcripts.  The transcripts carry no
expected values: the runner requires their bytes to equal pinned musl's, so a
row cannot pass on a candidate-chosen value.
"""

from __future__ import annotations

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]
COVERAGE = Path("compat/crabc-rs/coverage.toml")

CAPABILITIES = (
    "numeric.parse-float-locale",
    "locale.core",
    "text.wide-multibyte",
    "text.iconv",
)

# Keep the source-to-row mapping as data rather than a prose-only claim.  The
# family coordinator consumes these exact literals and cannot infer a row from
# a provider symbol alone.
ROWS = (
    ("numeric.parse-float-locale", "float-parse", ("float-parse",)),
    ("locale.core", "ctype-locators", ("ctype-locators",)),
    ("locale.core", "narrow-ctype-collation", ("locale-narrow",)),
    ("locale.core", "object-wide", ("locale-object-wide",)),
    ("locale.core", "alias-contract", ("locale-alias-contract",)),
    ("locale.core", "strfmon", ("strfmon",)),
    ("text.wide-multibyte", "locale-object-wide", ("locale-object-wide",)),
    ("text.wide-multibyte", "multibyte", ("locale-multibyte",)),
    ("text.wide-multibyte", "wide-character", ("wide-character",)),
    ("text.wide-multibyte", "wide-conversion", ("wide-conversion",)),
    ("text.iconv", "utf16-32-iconv", ("locale-wide-iconv",)),
    # Rows below close the remaining frozen spellings of the four capabilities.
    ("numeric.parse-float-locale", "differential-transcript", ("text-locale-differential",)),
    ("locale.core", "error-strings", ("locale-error-strings",)),
    ("locale.core", "differential-transcript", ("text-locale-differential",)),
    ("text.wide-multibyte", "uchar", ("uchar-stateful", "c32rtomb")),
    ("text.wide-multibyte", "wcswcs", ("wcswcs",)),
    ("text.wide-multibyte", "differential-transcript", ("text-locale-differential",)),
    ("text.wide-multibyte", "wide-stream", ("wide-stream-differential",)),
    ("text.iconv", "differential-transcript", ("text-locale-differential",)),
)

# The public replacement definitions in locale_alias_contract_probe.c cannot
# share an executable with normal probes: it deliberately verifies that the
# application can replace public aliases while libc itself retains private
# providers.  Every other role combines behind the installed driver.
ALIAS_ROLE = "locale-alias-contract"
OBJECT_ROLES = (
    ("driver", "compat/x86_64/owned_text_locale_numeric_component_driver.c", None, "normal"),
    # Rename each legacy standalone entry point instead of defining its
    # candidate-only FREESTANDING selector.  The common role must have the
    # same bytes under musl and all supplied product links; three selectors
    # intentionally add candidate-only negative cases and therefore belong to
    # the separately retained source-specific supplement.
    ("float-parse", "compat/x86_64/libc_float_parse_probe.c", "main=crabc_text_locale_numeric_float_parse_private_main", "normal"),
    ("ctype-locators", "compat/x86_64/libc_locale_ctype_locators_probe.c", "main=crabc_text_locale_numeric_ctype_locators_private_main", "normal"),
    ("locale-narrow", "compat/x86_64/libc_locale_narrow_probe.c", "main=crabc_text_locale_numeric_locale_narrow_private_main", "normal"),
    ("locale-object-wide", "compat/x86_64/libc_locale_object_wide_probe.c", "main=crabc_text_locale_numeric_locale_object_wide_private_main", "normal"),
    ("locale-wide-iconv", "compat/x86_64/libc_locale_wide_iconv_probe.c", "main=crabc_text_locale_numeric_locale_wide_iconv_private_main", "normal"),
    ("locale-multibyte", "compat/x86_64/libc_locale_multibyte_probe.c", "main=crabc_text_locale_numeric_locale_multibyte_private_main", "normal"),
    ("wide-character", "compat/x86_64/libc_wide_character_probe.c", "main=crabc_text_locale_numeric_wide_character_private_main", "normal"),
    ("locale-alias-contract", "compat/x86_64/locale_alias_contract_probe.c", None, "alias"),
    ("strfmon", "compat/x86_64/owned_strfmon_probe.c", "main=crabc_text_locale_numeric_strfmon_private_main", "normal"),
    ("wide-conversion", "compat/x86_64/owned_wide_conversion_probe.c", "main=crabc_text_locale_numeric_wide_conversion_private_main", "normal"),
    ("uchar-stateful", "compat/x86_64/libc_uchar_stateful_probe.c", "main=crabc_text_locale_numeric_uchar_stateful_private_main", "normal"),
    ("c32rtomb", "compat/x86_64/libc_c32rtomb_probe.c", "main=crabc_text_locale_numeric_c32rtomb_private_main", "normal"),
    ("wcswcs", "compat/x86_64/libc_wcswcs_probe.c", "main=crabc_text_locale_numeric_wcswcs_private_main", "normal"),
    ("locale-error-strings", "compat/x86_64/libc_locale_error_strings_probe.c", "main=crabc_text_locale_numeric_locale_error_strings_private_main", "normal"),
    ("text-locale-differential", "compat/x86_64/owned_text_locale_differential_probe.c", "main=crabc_text_locale_numeric_text_locale_differential_private_main", "normal"),
    # Last: it reopens stdout around the stdout-only wide entries, so no later
    # role observes a stream whose orientation it changed.
    ("wide-stream-differential", "compat/x86_64/owned_wide_stream_differential_probe.c", "main=crabc_text_locale_numeric_wide_stream_differential_private_main", "normal"),
)

# These three source branches deliberately make candidate-specific assertions
# which cannot share a Musl oracle transcript.  Keep them in a different
# workload, with their own rows and raw candidate evidence, so they cannot be
# mistaken for additions to the eleven parity-credit rows above.  In
# particular, environment selection is checked in the separate owned locale
# v3 component; this supplement never substitutes for that differential proof.
SOURCE_SPECIFIC_OBJECT_ROLES = (
    ("source-specific-driver", "compat/x86_64/owned_text_locale_numeric_source_specific_driver.c", None,
     "source-specific"),
    ("candidate-locale-object-wide-profile", "compat/x86_64/libc_locale_object_wide_probe.c",
     ("CRABC_LOCALE_OBJECT_WIDE_FREESTANDING",
      "CRABC_OWNED_LOCALE_ENVIRONMENT",
      "main=crabc_text_locale_numeric_candidate_locale_object_wide_private_main"), "source-specific"),
    ("candidate-locale-wide-iconv-profile", "compat/x86_64/libc_locale_wide_iconv_probe.c",
     ("CRABC_LOCALE_WIDE_ICONV_FREESTANDING",
      "main=crabc_text_locale_numeric_candidate_locale_wide_iconv_private_main"), "source-specific"),
    ("candidate-locale-multibyte-profile", "compat/x86_64/libc_locale_multibyte_probe.c",
     ("CRABC_LOCALE_MULTIBYTE_FREESTANDING",
      "main=crabc_text_locale_numeric_candidate_locale_multibyte_private_main"), "source-specific"),
)

# These are deliberately not capability rows.  The receipt gives them a
# separate ``source_specific_evidence`` field whose ``credit`` value is false.
# That structure prevents a family consumer from confusing a candidate mode
# consistency observation with the fixed Musl-parity mapping in ``ROWS``.
SOURCE_SPECIFIC_ROWS = (
    (
        "candidate-locale-object-wide-profile",
        ("candidate-locale-object-wide-profile",),
        "candidate-mode-consistency",
        "The owned-runtime selector accepts empty-name environment requests and rejects unsupported names. This candidate consistency observation has no locale.core credit; the locale v3 differential remains required.",
    ),
    (
        "candidate-locale-wide-iconv-profile",
        ("candidate-locale-wide-iconv-profile",),
        "candidate-mode-consistency",
        "Generic ISO-8859-1, UTF-16, and UCS-2LE rejection is retained as a candidate-only profile observation; explicit UTF-16LE/BE and UTF-32 conversion remains in the separate parity row.",
    ),
    (
        "candidate-locale-multibyte-profile",
        ("candidate-locale-multibyte-profile",),
        "candidate-mode-consistency",
        "Only the rejection of an LC_ALL component list naming a non-profile locale is observed here; musl's component parser over profile names stays in the parity rows, and this row adds no text.wide-multibyte credit.",
    ),
)

SOURCE_SPECIFIC_EXECUTION_CELLS = (
    "candidate-static-run",
    "candidate-static-pie-run",
    "candidate-dynamic-pie-kernel",
    "candidate-dynamic-pie-direct",
    "candidate-dynamic-non-pie-kernel",
    "candidate-dynamic-non-pie-direct",
)

EXECUTION_CELLS = (
    "static-run",
    "static-pie-run",
    "dynamic-pie-kernel",
    "dynamic-pie-direct",
    "dynamic-non-pie-kernel",
    "dynamic-non-pie-direct",
)

# A row is never credited merely because its capability mentions a symbol.
# These are the literal public C entry points which the normal aggregate
# object's existing probes import through function pointers or direct calls.
# The binary reader requires all of them to remain unresolved in that ET_REL
# object and to have physical static and dynamic providers.  The locale alias
# role has different evidence because it intentionally supplies public
# definitions itself.
PROVIDER_SYMBOLS = (
    # numeric.parse-float-locale (all 23 frozen spellings)
    "atof", "ecvt", "fcvt", "gcvt", "getsubopt", "strtod", "strtod_l", "strtof",
    "strtof_l", "strtold", "strtold_l", "wcstod", "wcstof", "wcstoimax", "wcstol",
    "wcstold", "wcstoll", "wcstoul", "wcstoull", "wcstoumax", "__strtod_l",
    "__strtof_l", "__strtold_l",
    # locale.core observations.  The remaining frozen `__*` spellings are the
    # public/private alias pairs proved by the separate alias workload.
    "__ctype_b_loc", "__strerror_l", "__wcsftime_l", "__ctype_get_mb_cur_max", "__ctype_tolower_loc",
    "__ctype_toupper_loc", "duplocale", "freelocale", "isalnum_l", "isalpha_l",
    "isblank_l", "iscntrl_l", "isdigit_l", "isgraph_l", "islower_l", "isprint_l",
    "ispunct_l", "isspace_l", "isupper_l", "iswalnum_l", "iswalpha_l", "iswblank_l",
    "iswcntrl_l", "iswctype_l", "iswdigit_l", "iswgraph_l", "iswlower_l",
    "iswprint_l", "iswpunct_l", "iswspace_l", "iswupper_l", "iswxdigit_l",
    "isxdigit_l", "localeconv", "newlocale", "nl_langinfo", "nl_langinfo_l",
    "setlocale", "strcasecmp", "strcasecmp_l", "strcoll", "strcoll_l", "strerror_l", "strfmon",
    "strfmon_l", "strncasecmp", "strncasecmp_l", "strxfrm", "strxfrm_l", "tolower_l",
    "toupper_l", "towctrans_l", "towlower_l", "towupper_l", "uselocale", "wcscasecmp_l",
    "wcscoll", "wcscoll_l", "wcsftime_l", "wcsncasecmp_l", "wcsxfrm", "wcsxfrm_l", "wctrans_l",
    "wctype_l",
    # text.wide-multibyte observations.  The FILE-oriented entries are
    # observed here through the wide-stream transcript; their stream engine
    # remains separately owned and proved by the stdio FILE-engine component.
    "btowc", "c16rtomb", "c32rtomb", "iswalnum", "iswalpha", "iswblank", "iswcntrl", "iswctype", "iswdigit",
    "iswgraph", "iswlower", "iswprint", "iswpunct", "iswspace", "iswupper", "iswxdigit",
    "mblen", "mbrlen", "mbrtoc16", "mbrtoc32", "mbrtowc", "mbsinit", "mbsnrtowcs", "mbsrtowcs", "mbstowcs",
    "mbtowc", "towctrans", "towlower", "towupper", "wcrtomb", "wcpcpy", "wcpncpy",
    "wcscasecmp", "wcscat", "wcschr", "wcscmp", "wcscpy", "wcscspn", "wcsdup",
    "wcslen", "wcsncasecmp", "wcsncat", "wcsncmp", "wcsncpy", "wcsnlen", "wcsnrtombs",
    "wcspbrk", "wcsrchr", "wcsrtombs", "wcsspn", "wcsstr", "wcstok", "wcstombs",
    "wcswcs", "wcswidth", "wctob", "wctomb", "wctrans", "wctype", "wcwidth", "wmemchr",
    "wmemcmp", "wmemcpy", "wmemmove", "wmemset", "wcsftime",
    "fgetwc", "fgetwc_unlocked", "fgetws", "fgetws_unlocked", "fputwc",
    "fputwc_unlocked", "fputws", "fputws_unlocked", "fwide", "fwprintf", "fwscanf",
    "getwc", "getwc_unlocked", "getwchar", "getwchar_unlocked", "putwc",
    "putwc_unlocked", "putwchar", "putwchar_unlocked", "swprintf", "swscanf",
    "ungetwc", "vfwprintf", "vfwscanf", "vswprintf", "vswscanf", "vwprintf",
    "vwscanf", "wprintf", "wscanf",
    # text.iconv
    "iconv", "iconv_close", "iconv_open",
)

# These sentences are retained in the receipt and documentation so the ABI
# observations do not silently turn into a portability claim.
ABI_CONTRACT = (
    "Linux/x86-64 little-endian LP64; locale_t and iconv_t are pointer-sized opaque "
    "handles; wchar_t is four bytes; mbstate_t is eight bytes with alignof four; "
    "floating conversion retains SysV x87 binary80 long-double storage and return ABI."
)


class ContractError(ValueError):
    """The frozen capability ledger no longer matches this finite component."""


def _records(root: Path) -> dict[str, dict]:
    try:
        document = tomllib.loads((root / COVERAGE).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ContractError("cannot read frozen capability ledger") from error
    records = document.get("capability")
    if not isinstance(records, list):
        raise ContractError("capability ledger has no capability records")
    result = {record.get("id"): record for record in records if isinstance(record, dict)}
    if any(capability not in result for capability in CAPABILITIES):
        raise ContractError("component capability escaped the frozen ledger")
    return {capability: result[capability] for capability in CAPABILITIES}


def load_capability_roster(root: Path = ROOT) -> dict[str, tuple[str, ...]]:
    """Return the exact frozen inventories without treating them as row credit."""

    records = _records(root)
    result: dict[str, tuple[str, ...]] = {}
    for capability, record in records.items():
        symbols = record.get("symbols")
        if not isinstance(symbols, list) or not all(isinstance(symbol, str) for symbol in symbols):
            raise ContractError(f"{capability} has no literal symbol inventory")
        result[capability] = tuple(symbols)
    if len(result["numeric.parse-float-locale"]) != 23:
        raise ContractError("numeric float roster is no longer the frozen 23-entry boundary")
    if result["text.iconv"] != ("iconv", "iconv_close", "iconv_open"):
        raise ContractError("iconv roster differs from the fixed UTF row")
    if len(ROWS) != len({(capability, row) for capability, row, _roles in ROWS}) or \
            {row[0] for row in ROWS} != set(CAPABILITIES):
        raise ContractError("component row map is incomplete")
    role_names = {role for role, _source, _define, _group in OBJECT_ROLES}
    source_specific_role_names = {
        role for role, _source, _define, _group in SOURCE_SPECIFIC_OBJECT_ROLES
    }
    if len(role_names) != len(OBJECT_ROLES) or len(source_specific_role_names) != len(SOURCE_SPECIFIC_OBJECT_ROLES):
        raise ContractError("component object role roster repeats a name")
    if role_names & source_specific_role_names:
        raise ContractError("source-specific role overlaps a parity role")
    if any(not set(roles).issubset(role_names) for _capability, _row, roles in ROWS):
        raise ContractError("row map references an unknown installed object role")
    if len(SOURCE_SPECIFIC_ROWS) != 3 or any(
            not set(roles).issubset(source_specific_role_names)
            for _row, roles, _comparison, _limitation in SOURCE_SPECIFIC_ROWS):
        raise ContractError("source-specific row map references an unknown installed object role")
    if tuple(row[2] for row in SOURCE_SPECIFIC_ROWS) != (
            "candidate-mode-consistency", "candidate-mode-consistency", "candidate-mode-consistency"):
        raise ContractError("source-specific rows changed their non-oracle relation")
    if ALIAS_ROLE not in role_names:
        raise ContractError("alias object role disappeared")
    expected_provider_symbols = tuple(
        symbol for capability in CAPABILITIES for symbol in result[capability]
        if symbol in PROVIDER_SYMBOLS
    )
    if tuple(symbol for symbol in PROVIDER_SYMBOLS if symbol in expected_provider_symbols) != PROVIDER_SYMBOLS:
        raise ContractError("provider roster no longer belongs to the frozen capability inventory")
    if len(PROVIDER_SYMBOLS) != len(set(PROVIDER_SYMBOLS)):
        raise ContractError("provider roster repeats a selected symbol")
    return result


def normal_roles() -> tuple[tuple[str, str, str | None, str], ...]:
    """Return the roles that form the ordered normal executable."""

    return tuple(role for role in OBJECT_ROLES if role[3] == "normal")


def all_object_roles() -> tuple[tuple[str, str, str | tuple[str, ...] | None, str], ...]:
    """Return all installed-header objects, including non-credit supplement roles."""

    return (*OBJECT_ROLES, *SOURCE_SPECIFIC_OBJECT_ROLES)


def direct_sources() -> tuple[Path, ...]:
    """All tracked inputs whose identities the per-pair report seals."""

    role_sources = tuple(dict.fromkeys(
        Path(relative) for _role, relative, _define, _group in all_object_roles()
    ))
    return (
        *role_sources,
        Path("compat/x86_64/run_owned_text_locale_numeric_component.sh"),
        Path("compat/x86_64/owned_text_locale_numeric_component_contract.py"),
        Path("compat/x86_64/owned_text_locale_numeric_component_evidence.py"),
        Path("compat/x86_64/owned_text_locale_numeric_component_receipt.py"),
        Path("compat/x86_64/owned-text-locale-numeric-component.md"),
        Path("compat/x86_64/tests/test_owned_text_locale_numeric_component.py"),
        Path("compat/x86_64/tests/test_owned_text_locale_numeric_component_driver.py"),
        Path("compat/x86_64/locale_alias_contract.json"),
        Path("compat/x86_64/locale_alias_contract_symbols.py"),
        Path("compat/x86_64/owned_crypt_runtime_evidence.py"),
        Path("compat/x86_64/owned_posix_family_execution.py"),
        Path("compat/x86_64/owned_posix_product_evidence.py"),
        COVERAGE,
    )
