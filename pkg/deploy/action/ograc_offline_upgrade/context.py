#!/usr/bin/env python3
"""
Upgrade context management for oGRAC offline upgrade.

This module provides the UpgradeContext class that maintains state
throughout the upgrade process, enabling coordination between different
stages and supporting rollback operations.
"""

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Dict, Any, List

from .config import UpgradeConfig


class UpgradeStage(Enum):
    """Enumeration of upgrade process stages.

    This enum represents the various stages of the upgrade process,
    used for tracking progress and state management.
    """
    IDLE = auto()
    PRE_UPGRADE = auto()
    STOP = auto()
    BACKUP = auto()
    UPGRADE = auto()
    POST_UPGRADE = auto()
    COMMIT = auto()
    ROLLBACK = auto()
    COMPLETED = auto()
    FAILED = auto()

    def __str__(self) -> str:
        """Return human-readable stage name."""
        return self.name.lower()


@dataclass
class StageInfo:
    """Information about a specific upgrade stage.

    This class tracks timing and status information for each stage
    of the upgrade process.

    Attributes:
        stage: The upgrade stage
        started_at: Timestamp when stage started
        completed_at: Timestamp when stage completed (None if ongoing)
        status: Stage status (pending, running, completed, failed)
        message: Optional status message
        metadata: Additional stage-specific metadata
    """
    stage: UpgradeStage
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    status: str = "running"  # pending, running, completed, failed
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def complete(self, success: bool = True, message: str = "") -> None:
        """Mark the stage as completed.

        Args:
            success: Whether the stage completed successfully
            message: Optional completion message
        """
        self.completed_at = datetime.now()
        self.status = "completed" if success else "failed"
        if message:
            self.message = message

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get the stage duration in seconds.

        Returns:
            Duration if stage has completed, None otherwise
        """
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "stage": self.stage.name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "message": self.message,
            "metadata": self.metadata,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class UpgradeContext:
    """Context object that maintains state throughout the upgrade process.

    The UpgradeContext serves as a central state repository that tracks:
    - Configuration settings
    - Version information (source and target)
    - Current stage and stage history
    - Backup information
    - Error information
    - Custom metadata

    This context is passed between components and can be persisted to
    enable recovery and rollback operations.

    Attributes:
        config: Upgrade configuration
        source_version: Current installed version
        target_version: Target upgrade version
        current_stage: Current upgrade stage
        stage_history: History of all stages
        backup_path: Path to current backup
        error_info: Error information if any
        start_time: When the upgrade process started
        metadata: Custom metadata storage
    """

    # Configuration
    config: UpgradeConfig = field(default_factory=UpgradeConfig)

    # Version information
    source_version: str = ""
    target_version: str = ""

    # Stage tracking
    current_stage: UpgradeStage = UpgradeStage.IDLE
    stage_history: List[StageInfo] = field(default_factory=list)

    # Backup information
    backup_path: Optional[Path] = None
    backup_success: bool = False

    # Error tracking
    error_info: Optional[Dict[str, Any]] = None

    # Timing
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    # Custom metadata storage
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Post-initialization processing."""
        # Ensure Path objects
        if self.backup_path and isinstance(self.backup_path, str):
            self.backup_path = Path(self.backup_path)

    def transition_to(self, stage: UpgradeStage, message: str = "") -> StageInfo:
        """Transition to a new upgrade stage.

        This method handles stage transitions by:
        1. Completing the current stage if any
        2. Creating a new StageInfo for the target stage
        3. Updating the current_stage reference

        Args:
            stage: The target stage to transition to
            message: Optional message for the new stage

        Returns:
            The new StageInfo object
        """
        # Complete current stage if transitioning from a running stage
        if self.stage_history and self.stage_history[-1].status == "running":
            self.stage_history[-1].complete(success=True)

        # Create new stage info
        stage_info = StageInfo(
            stage=stage,
            message=message,
            metadata={"transition_from": self.current_stage.name}
        )

        self.stage_history.append(stage_info)
        self.current_stage = stage

        return stage_info

    def fail_stage(self, error_message: str, error_details: Optional[Dict[str, Any]] = None) -> None:
        """Mark the current stage as failed.

        Args:
            error_message: Error description
            error_details: Additional error details
        """
        if self.stage_history and self.stage_history[-1].status == "running":
            self.stage_history[-1].complete(success=False, message=error_message)

        self.error_info = {
            "message": error_message,
            "stage": self.current_stage.name,
            "timestamp": datetime.now().isoformat(),
            "details": error_details or {},
        }

        self.current_stage = UpgradeStage.FAILED

    def complete(self, success: bool = True) -> None:
        """Mark the entire upgrade process as complete.

        Args:
            success: Whether the upgrade completed successfully
        """
        self.end_time = datetime.now()

        # Complete current stage
        if self.stage_history and self.stage_history[-1].status == "running":
            self.stage_history[-1].complete(success=success)

        self.current_stage = UpgradeStage.COMPLETED if success else UpgradeStage.FAILED

    @property
    def total_duration_seconds(self) -> Optional[float]:
        """Get the total upgrade duration in seconds.

        Returns:
            Duration if upgrade has ended, None otherwise
        """
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def can_rollback(self) -> bool:
        """Check if rollback is possible.

        Rollback is possible if:
        - A backup was successfully created
        - The upgrade has not been committed

        Returns:
            True if rollback is possible, False otherwise
        """
        return self.backup_success and self.backup_path is not None

    def get_stage_info(self, stage: UpgradeStage) -> Optional[StageInfo]:
        """Get information about a specific stage.

        Args:
            stage: The stage to look up

        Returns:
            StageInfo if found, None otherwise
        """
        for info in reversed(self.stage_history):
            if info.stage == stage:
                return info
        return None

    def set_metadata(self, key: str, value: Any) -> None:
        """Set a metadata value.

        Args:
            key: Metadata key
            value: Metadata value (must be JSON serializable)
        """
        self.metadata[key] = value

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get a metadata value.

        Args:
            key: Metadata key
            default: Default value if key not found

        Returns:
            Metadata value or default
        """
        return self.metadata.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary representation.

        Returns:
            Dictionary containing all context information
        """
        return {
            "config": self.config.to_dict(),
            "source_version": self.source_version,
            "target_version": self.target_version,
            "current_stage": self.current_stage.name,
            "stage_history": [s.to_dict() for s in self.stage_history],
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "backup_success": self.backup_success,
            "error_info": self.error_info,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_duration_seconds": self.total_duration_seconds,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert context to JSON string.

        Args:
            indent: JSON indentation level

        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_to_file(self, path: Path) -> None:
        """Save context to a JSON file.

        This enables recovery and status tracking across process restarts.

        Args:
            path: Path to save context
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.to_json())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UpgradeContext':
        """Create context from dictionary.

        Args:
            data: Dictionary containing context values

        Returns:
            UpgradeContext instance
        """
        # Parse config
        config = UpgradeConfig.from_dict(data.get('config', {}))

        # Parse stage history
        stage_history = []
        for stage_data in data.get('stage_history', []):
            stage = UpgradeStage[stage_data['stage']]
            stage_info = StageInfo(
                stage=stage,
                started_at=datetime.fromisoformat(stage_data['started_at']),
                completed_at=datetime.fromisoformat(stage_data['completed_at']) if stage_data['completed_at'] else None,
                status=stage_data['status'],
                message=stage_data['message'],
                metadata=stage_data.get('metadata', {}),
            )
            stage_history.append(stage_info)

        # Parse current stage
        current_stage = UpgradeStage[data.get('current_stage', 'IDLE')]

        # Parse backup path
        backup_path = data.get('backup_path')
        if backup_path:
            backup_path = Path(backup_path)

        return cls(
            config=config,
            source_version=data.get('source_version', ''),
            target_version=data.get('target_version', ''),
            current_stage=current_stage,
            stage_history=stage_history,
            backup_path=backup_path,
            backup_success=data.get('backup_success', False),
            error_info=data.get('error_info'),
            start_time=datetime.fromisoformat(data['start_time']) if 'start_time' in data else datetime.now(),
            end_time=datetime.fromisoformat(data['end_time']) if data.get('end_time') else None,
            metadata=data.get('metadata', {}),
        )

    @classmethod
    def from_file(cls, path: Path) -> 'UpgradeContext':
        """Load context from a JSON file.

        Args:
            path: Path to context file

        Returns:
            UpgradeContext instance

        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file contains invalid JSON
        """
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
