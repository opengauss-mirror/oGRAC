#!/usr/bin/env python3
"""Kernel parameter validation helpers for deployment config."""

import re


KERNEL_PARAMETER_WHITELIST = {
    "DATA_BUFFER_SIZE": {"type": "size", "range": "[64M,32T]"},
    "TEMP_BUFFER_SIZE": {"type": "size", "range": "[32M,4T]"},
    "SHARED_POOL_SIZE": {"type": "size", "range": "[82M,32T]"},
    "LOG_BUFFER_SIZE": {"type": "size", "range": "[1M,110M]"},
    "LOG_BUFFER_COUNT": {"type": "integer", "range": "(0,16]"},
    "CR_POOL_SIZE": {"type": "size", "range": "[16M,32T]"},
    "CR_POOL_COUNT": {"type": "integer", "range": "[1,256]"},
    "BUF_POOL_NUM": {"type": "integer", "range": "[1,128]"},
    "TEMP_POOL_NUM": {"type": "integer", "range": "[1,128]"},
    "LARGE_POOL_SIZE": {"type": "size", "range": "[4M,32T]"},
    "VARIANT_MEMORY_AREA_SIZE": {"type": "size", "range": "[4M,32T]"},
    "LARGE_VARIANT_MEMORY_AREA_SIZE": {"type": "size", "range": "[1M,32T]"},
    "PMA_BUFFER_SIZE": {"type": "size", "range": "[0,1T]"},
    "HASH_AREA_SIZE": {"type": "size", "range": "[0,1T]"},
    "_INDEX_BUFFER_SIZE": {"type": "size", "range": "[16K,32T]"},
    "_VARIANT_AREA_SIZE": {"type": "size", "range": "[256K,64M]"},
    "_AGENT_STACK_SIZE": {"type": "size", "range": "[512K,4G)"},
    "SESSIONS": {"type": "integer", "range": "[59,19380]"},
    "OPEN_CURSORS": {"type": "integer", "range": "[1,16384]"},
    "OPTIMIZED_WORKER_THREADS": {"type": "integer", "range": "[2,10000]"},
    "MAX_WORKER_THREADS": {"type": "integer", "range": "[2,10000]"},
    "MES_POOL_SIZE": {"type": "integer", "range": "[256,16384]"},
}


def parse_size_to_kb(value):
    text = str(value).strip()
    if text == "0":
        return 0
    match = re.fullmatch(r"(\d+)([KkMmGgTt])", text)
    if not match:
        return None
    number = int(match.group(1))
    unit = match.group(2).upper()
    multipliers = {"K": 1, "M": 1024, "G": 1024 * 1024, "T": 1024 * 1024 * 1024}
    return number * multipliers[unit]


def _parse_bound(value, value_type):
    if value_type == "size":
        return parse_size_to_kb(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_range(range_text, value_type):
    pattern = r"([\[\(])\s*([^,]+)\s*,\s*([^\]\)]+)\s*([\]\)])"
    match = re.fullmatch(pattern, range_text)
    if not match:
        return None
    lower_mark, lower_text, upper_text, upper_mark = match.groups()
    lower = _parse_bound(lower_text, value_type)
    upper = _parse_bound(upper_text, value_type)
    if lower is None or upper is None:
        return None
    return lower_mark, lower, upper, upper_mark


def value_in_range(value, value_type, range_text):
    parsed_range = _parse_range(range_text, value_type)
    actual = _parse_bound(value, value_type)
    if parsed_range is None or actual is None:
        return False
    lower_mark, lower, upper, upper_mark = parsed_range
    lower_ok = actual >= lower if lower_mark == "[" else actual > lower
    upper_ok = actual <= upper if upper_mark == "]" else actual < upper
    return lower_ok and upper_ok


def normalize_kernel_parameter_name(name):
    return str(name).strip().upper()


def iter_normalized_kernel_parameters(kernel_params):
    for key in sorted(kernel_params):
        param_name = normalize_kernel_parameter_name(key)
        param_value = str(kernel_params[key]).strip()
        yield param_name, param_value


def validate_kernel_parameters(value):
    """Return (is_valid, error_message) for config_params_lun.json kernel_parameters."""
    if value in ("", None):
        return True, ""
    if not isinstance(value, dict):
        return False, "kernel_parameters must be a JSON object"

    for raw_key, raw_value in value.items():
        key = normalize_kernel_parameter_name(raw_key)
        param_value = str(raw_value).strip()
        if not key or not param_value:
            return False, "kernel_parameters contains empty key or value"
        if any(ch in key for ch in ("=", "\n", "\r")):
            return False, f"kernel parameter name '{key}' contains invalid characters"
        if any(ch in param_value for ch in ("\n", "\r")):
            return False, f"kernel parameter '{key}' contains invalid value characters"

        meta = KERNEL_PARAMETER_WHITELIST.get(key)
        if meta is None:
            return False, f"unsupported kernel parameter: {key}"
        if not value_in_range(param_value, meta["type"], meta["range"]):
            return (
                False,
                f"invalid value for kernel parameter {key}: {param_value}, "
                f"expected {meta['range']}",
            )
    return True, ""


def is_generated_kernel_parameter(key):
    match = re.fullmatch(r"Z_KERNEL_PARAMETER(\d+)", key)
    return match is not None and int(match.group(1)) >= 3
