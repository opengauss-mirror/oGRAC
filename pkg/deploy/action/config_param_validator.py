#!/usr/bin/env python3
"""Shared config_params_lun.json structure validation."""

import json
import os
import sys


class ConfigParamValidationError(ValueError):
    """Raised when config_params_lun.json has missing or unknown parameters."""


DEFAULT_REQUIRED_KEYS = {
    "deploy_mode",
    "node_id",
    "cms_ip",
    "db_type",
    "mes_ssl_switch",
    "MAX_ARCH_FILES_SIZE",
    "redo_num",
    "redo_size",
    "auto_tune",
    "dss_vg_list",
    "gcc_home",
    "cms_port",
    "dss_port",
    "ograc_port",
    "interconnect_port",
    "_SHM_KEY",
    "module_config",
}


def _log_error(logger, message, *args):
    if logger:
        logger.error(message, *args)


def _load_json(path, logger=None):
    try:
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
    except Exception as error:
        _log_error(logger, "load %s error: %s", path, str(error))
        raise ConfigParamValidationError(f"load {path} error: {error}")
    if not isinstance(data, dict):
        _log_error(logger, "%s must be a JSON object", path)
        raise ConfigParamValidationError(f"{path} must be a JSON object")
    return data


def _template_required_keys(template_path, logger=None):
    if template_path is None:
        return set(DEFAULT_REQUIRED_KEYS)
    template = _load_json(template_path, logger)
    return set(template.keys())


def validate_config_params_file(config_path, template_path=None, logger=None):
    """Validate required keys, unknown keys, and module_config without writing files."""
    install_config = _load_json(config_path, logger)
    required_keys = _template_required_keys(template_path, logger)

    missing = required_keys - set(install_config.keys())
    if missing:
        for key in sorted(missing):
            _log_error(logger, "%s need %s", config_path, key)
        raise ConfigParamValidationError(
            f"{config_path} missing required params: {', '.join(sorted(missing))}"
        )

    lifecycle_keys = {"install_type", "uninstall_type"}
    compatibility_keys = {
        "ograc_in_container", "link_type", "cluster_id", "cluster_name",
        "mes_type", "deploy_policy", "ograc_vlan_ip",
        "storage_share_fs", "storage_archive_fs", "storage_metadata_fs",
        "share_logic_ip", "archive_logic_ip", "metadata_logic_ip",
        "SYS_PASSWORD", "kernel_parameters",
    }
    mes_type_keys = {"ca_path", "crt_path", "key_path"}

    allowed_keys = required_keys | lifecycle_keys | compatibility_keys
    if install_config.get("mes_ssl_switch"):
        allowed_keys |= mes_type_keys

    unknown = set(install_config.keys()) - allowed_keys
    if unknown:
        for key in sorted(unknown):
            _log_error(logger, "Unknown parameter '%s' in %s", key, config_path)
        raise ConfigParamValidationError(
            f"{config_path} has unknown params: {', '.join(sorted(unknown))}"
        )

    module_config = install_config.get("module_config")
    if module_config is None:
        _log_error(logger, "%s need module_config", config_path)
        raise ConfigParamValidationError(f"{config_path} missing module_config")
    if not isinstance(module_config, dict):
        _log_error(logger, "module_config must be a JSON object")
        raise ConfigParamValidationError("module_config must be a JSON object")

    module_required_keys = {"ograc_home", "data_root", "user"}
    module_missing = module_required_keys - set(module_config.keys())
    if module_missing:
        for key in sorted(module_missing):
            _log_error(logger, "%s need module_config.%s", config_path, key)
        raise ConfigParamValidationError(
            f"{config_path} missing module_config params: {', '.join(sorted(module_missing))}"
        )

    module_allowed_keys = {"ograc_home", "data_root", "user", "group", "nfs_port"}
    module_unknown = set(module_config.keys()) - module_allowed_keys
    if module_unknown:
        for key in sorted(module_unknown):
            _log_error(logger, "Unknown parameter '%s' in module_config", key)
        raise ConfigParamValidationError(
            f"module_config has unknown params: {', '.join(sorted(module_unknown))}"
        )

    return True


def main():
    if len(sys.argv) not in (2, 3):
        print(
            "Usage: python3 config_param_validator.py <config_path> [template_path]",
            file=sys.stderr,
        )
        return 1
    config_path = sys.argv[1]
    template_path = sys.argv[2] if len(sys.argv) == 3 else None
    try:
        validate_config_params_file(config_path, template_path=template_path)
    except ConfigParamValidationError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
