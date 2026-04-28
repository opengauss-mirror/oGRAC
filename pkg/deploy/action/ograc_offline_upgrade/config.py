#!/usr/bin/env python3
"""
Configuration management for oGRAC offline upgrade module.

This module provides comprehensive configuration management including:
- Multi-source configuration (defaults, files, environment variables, CLI args)
- Configuration validation
- Type-safe configuration access
- Configuration persistence
"""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Callable


@dataclass
class UpgradeConfig:
    """Configuration class for oGRAC offline upgrade.

    This class manages all configuration parameters needed for the upgrade
    process. It supports loading from multiple sources with precedence:
    1. Command line arguments (highest)
    2. Environment variables
    3. Configuration files
    4. Default values (lowest)

    Attributes:
        ograc_home: oGRAC installation directory
        backup_root: Root directory for upgrade backups
        deploy_mode: Deployment mode (combined, file, dss, dbstor)
        node_id: Current node ID (0 for primary)
        ograc_user: oGRAC service user
        ograc_group: oGRAC service group
        ograc_common_group: oGRAC common group for shared access
        ogmgr_user: OG manager user
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_dir: Directory for log files
        timeout_default: Default timeout for operations (seconds)
        timeout_backup: Timeout for backup operations
        timeout_upgrade: Timeout for upgrade operations
        dorado_ip: Dorado storage array IP (for snapshot)
        max_backup_keep: Maximum number of backups to retain
        metadata_fs: Metadata filesystem name
        deploy_pkg_dir: Deployment package directory
        action_dir: Action scripts directory
        config_dir: Configuration directory
        versions_file: Path to versions.yml
        upgrade_mode: Upgrade mode (offline, rollup)
        dry_run: Whether to perform a dry run
    """

    # Directory paths
    ograc_home: Path = field(default_factory=lambda: Path("/opt/ograc"))
    backup_root: Path = field(default_factory=lambda: Path("/opt/ograc/upgrade_backup"))
    log_dir: Path = field(default_factory=lambda: Path("/opt/ograc/log/upgrade"))

    # User and group settings
    ograc_user: str = "ograc"
    ograc_group: str = "ograc"
    ograc_common_group: str = "ograc_common"
    ogmgr_user: str = "ogracmgr"

    # Deployment settings
    deploy_mode: str = "dss"  # combined, file, dss, dbstor
    node_id: int = 0
    upgrade_mode: str = "offline"  # offline, rollup
    ograc_in_container: str = "0"  # "0" = host mode, "1" or "2" = container mode

    # Logging settings
    log_level: str = "INFO"

    # Timeout settings (seconds)
    timeout_default: int = 1800
    timeout_backup: int = 3600
    timeout_upgrade: int = 3600
    timeout_rollback: int = 3600

    # Storage settings
    dorado_ip: Optional[str] = None
    storage_metadata_fs: Optional[str] = None
    storage_share_fs: Optional[str] = None
    storage_archive_fs: Optional[str] = None

    # Backup settings
    max_backup_keep: int = 5

    # Runtime settings
    dry_run: bool = False
    force: bool = False

    # Module settings
    pre_upgrade_order: List[str] = field(
        default_factory=lambda: ["ograc", "cms", "dss"]
    )
    upgrade_order: List[str] = field(
        default_factory=lambda: ["og_om", "ograc_exporter", "cms", "ograc"]
    )
    rollback_order: List[str] = field(
        default_factory=lambda: ["cms", "ograc", "og_om", "ograc_exporter"]
    )

    def __post_init__(self) -> None:
        """Post-initialization processing.

        Converts string paths to Path objects and validates configuration.
        """
        # Ensure Path objects
        if isinstance(self.ograc_home, str):
            self.ograc_home = Path(self.ograc_home)
        if isinstance(self.backup_root, str):
            self.backup_root = Path(self.backup_root)
        if isinstance(self.log_dir, str):
            self.log_dir = Path(self.log_dir)

        # Validate configuration
        self._validate()

    def _validate(self) -> None:
        """Validate configuration parameters.

        Raises:
            ValueError: If any configuration parameter is invalid
        """
        valid_modes = ["combined", "file", "dss", "dbstor"]
        if self.deploy_mode not in valid_modes:
            raise ValueError(
                f"Invalid deploy_mode: {self.deploy_mode}. "
                f"Must be one of: {valid_modes}"
            )

        valid_upgrade_modes = ["offline", "rollup"]
        if self.upgrade_mode not in valid_upgrade_modes:
            raise ValueError(
                f"Invalid upgrade_mode: {self.upgrade_mode}. "
                f"Must be one of: {valid_upgrade_modes}"
            )

        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_log_levels:
            raise ValueError(
                f"Invalid log_level: {self.log_level}. "
                f"Must be one of: {valid_log_levels}"
            )

        if self.node_id < 0:
            raise ValueError(f"node_id must be non-negative, got: {self.node_id}")

        if self.max_backup_keep < 1:
            raise ValueError(
                f"max_backup_keep must be at least 1, got: {self.max_backup_keep}"
            )

    @property
    def action_dir(self) -> Path:
        """Get the action directory path.

        Returns:
            Path to action directory
        """
        return self.ograc_home / "action"

    @property
    def config_dir(self) -> Path:
        """Get the configuration directory path.

        Returns:
            Path to config directory
        """
        return self.ograc_home / "config"

    @property
    def repo_dir(self) -> Path:
        """Get the repository directory path.

        Returns:
            Path to repo directory
        """
        return self.ograc_home / "repo"

    @property
    def common_dir(self) -> Path:
        """Get the common directory path.

        Returns:
            Path to common directory
        """
        return self.ograc_home / "common"

    @property
    def versions_file(self) -> Path:
        """Get the versions file path.

        Returns:
            Path to versions.yml
        """
        return self.ograc_home / "versions.yml"

    @property
    def deploy_param_file(self) -> Path:
        """Get the deployment parameters file path.

        Returns:
            Path to deploy_param.json
        """
        return self.config_dir / "deploy_param.json"

    @property
    def is_primary_node(self) -> bool:
        """Check if this is the primary node (node_id == 0).

        Returns:
            True if primary node, False otherwise
        """
        return self.node_id == 0

    @property
    def is_offline_mode(self) -> bool:
        """Check if upgrade mode is offline.

        Returns:
            True if offline mode, False otherwise
        """
        return self.upgrade_mode == "offline"

    def get_backup_path(self, version: str) -> Path:
        """Get the backup path for a specific version.

        Args:
            version: Version string

        Returns:
            Path to version-specific backup directory
        """
        return self.backup_root / version

    def get_metadata_path(self) -> Optional[Path]:
        """Get the metadata filesystem path.

        Returns:
            Path to metadata directory, or None if not configured
        """
        if not self.storage_metadata_fs:
            return None
        return Path(f"/mnt/dbdata/remote/metadata_{self.storage_metadata_fs}")

    def get_upgrade_path(self) -> Optional[Path]:
        """Get the upgrade directory in metadata filesystem.

        Returns:
            Path to upgrade directory, or None if metadata not configured
        """
        metadata_path = self.get_metadata_path()
        if not metadata_path:
            return None
        return metadata_path / "upgrade"

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration
        """
        data = asdict(self)
        # Convert Path objects to strings
        for key, value in data.items():
            if isinstance(value, Path):
                data[key] = str(value)
        return data

    def to_json(self, indent: int = 2) -> str:
        """Convert configuration to JSON string.

        Args:
            indent: JSON indentation level

        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, path: Path) -> None:
        """Save configuration to a JSON file.

        Args:
            path: Path to save configuration
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.to_json())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UpgradeConfig':
        """Create configuration from dictionary.

        Args:
            data: Dictionary containing configuration values

        Returns:
            UpgradeConfig instance
        """
        # Convert string paths to Path objects
        path_fields = ['ograc_home', 'backup_root', 'log_dir']
        for field_name in path_fields:
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = Path(data[field_name])

        return cls(**data)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> 'UpgradeConfig':
        """Load configuration from a JSON file.

        Args:
            path: Path to configuration file

        Returns:
            UpgradeConfig instance

        Raises:
            FileNotFoundError: If configuration file doesn't exist
            json.JSONDecodeError: If file contains invalid JSON
        """
        path = Path(path)
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_deploy_param(cls, path: Optional[Path] = None) -> 'UpgradeConfig':
        """Load configuration from oGRAC deploy_param.json.

        This method extracts relevant configuration from the standard
        oGRAC deployment parameters file.

        Args:
            path: Path to deploy_param.json (default: /opt/ograc/config/deploy_param.json)

        Returns:
            UpgradeConfig instance with values from deploy parameters
        """
        if path is None:
            path = Path("/opt/ograc/config/deploy_param.json")

        with open(path, 'r', encoding='utf-8') as f:
            deploy_data = json.load(f)

        config = cls()

        # Map deploy parameters to config fields
        mappings = {
            'deploy_mode': 'deploy_mode',
            'node_id': 'node_id',
            'ograc_user': 'ograc_user',
            'ograc_group': 'ograc_group',
            'ograc_common_group': 'ograc_common_group',
            'ogmgr_user': 'ogmgr_user',
            'storage_metadata_fs': 'storage_metadata_fs',
            'storage_share_fs': 'storage_share_fs',
            'storage_archive_fs': 'storage_archive_fs',
            'ograc_in_container': 'ograc_in_container',
        }

        for deploy_key, config_key in mappings.items():
            if deploy_key in deploy_data:
                setattr(config, config_key, deploy_data[deploy_key])

        config._validate()
        return config

    @classmethod
    def from_environment(cls) -> 'UpgradeConfig':
        """Load configuration from environment variables.

        Environment variables are expected to be prefixed with OGRAC_UPGRADE_
        and use uppercase with underscores.

        Examples:
            OGRAC_UPGRADE_OGRAC_HOME=/opt/ograc
            OGRAC_UPGRADE_LOG_LEVEL=DEBUG

        Returns:
            UpgradeConfig instance with values from environment
        """
        config = cls()

        # Mapping of env var names to config attributes
        env_mappings: Dict[str, Callable[[str], Any]] = {
            'OGRAC_UPGRADE_OGRAC_HOME': Path,
            'OGRAC_UPGRADE_BACKUP_ROOT': Path,
            'OGRAC_UPGRADE_LOG_DIR': Path,
            'OGRAC_UPGRADE_LOG_LEVEL': str,
            'OGRAC_UPGRADE_DEPLOY_MODE': str,
            'OGRAC_UPGRADE_NODE_ID': int,
            'OGRAC_UPGRADE_OGRAC_USER': str,
            'OGRAC_UPGRADE_OGRAC_GROUP': str,
            'OGRAC_UPGRADE_DORADO_IP': str,
            'OGRAC_UPGRADE_MAX_BACKUP_KEEP': int,
            'OGRAC_UPGRADE_DRY_RUN': lambda x: x.lower() in ('true', '1', 'yes'),
        }

        for env_var, converter in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                # Remove prefix and convert to lowercase for attribute name
                attr_name = env_var.replace('OGRAC_UPGRADE_', '').lower()
                setattr(config, attr_name, converter(value))

        config._validate()
        return config

    def merge(self, other: 'UpgradeConfig') -> 'UpgradeConfig':
        """Merge another configuration into this one.

        The other configuration takes precedence for non-default values.

        Args:
            other: Another UpgradeConfig instance to merge

        Returns:
            New merged UpgradeConfig instance
        """
        self_dict = self.to_dict()
        other_dict = other.to_dict()

        # Merge with other taking precedence
        merged = {**self_dict, **other_dict}

        return self.from_dict(merged)
