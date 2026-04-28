#!/usr/bin/env python3
"""
Exception hierarchy for oGRAC offline upgrade module.

This module defines a comprehensive exception hierarchy to handle various
types of errors that can occur during the upgrade process. Each exception
type corresponds to a specific stage of the upgrade workflow.
"""

from typing import Optional, Dict, Any


class UpgradeError(Exception):
    """Base exception for all upgrade-related errors.

    This is the root exception class that all other upgrade exceptions
    inherit from. It provides common attributes for error tracking and
    recovery.

    Attributes:
        message: Human-readable error description
        error_code: Optional error code for programmatic handling
        context: Additional context information about the error
        recoverable: Whether this error allows for rollback/recovery
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        recoverable: bool = False
    ) -> None:
        """Initialize the exception.

        Args:
            message: Human-readable error description
            error_code: Optional error code for programmatic handling
            context: Additional context information about the error
            recoverable: Whether this error allows for rollback/recovery
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        self.recoverable = recoverable

    def __str__(self) -> str:
        """Return string representation of the exception."""
        parts = [self.message]
        if self.error_code:
            parts.append(f"[Error Code: {self.error_code}]")
        if self.context:
            parts.append(f"Context: {self.context}")
        return " ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for serialization.

        Returns:
            Dictionary containing exception details
        """
        return {
            "type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "context": self.context,
            "recoverable": self.recoverable,
        }


class PreUpgradeError(UpgradeError):
    """Exception raised during the pre-upgrade phase.

    This exception is raised when errors occur during pre-upgrade checks,
    configuration validation, or version whitelist verification.

    Examples:
        - Invalid configuration parameters
        - Version not in whitelist
        - Pre-upgrade script failures
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize PreUpgradeError.

        Pre-upgrade errors are typically recoverable since no changes
        have been made to the system yet.
        """
        super().__init__(
            message=message,
            error_code=error_code or "PRE_UPGRADE_ERROR",
            context=context,
            recoverable=True
        )


class StopError(UpgradeError):
    """Exception raised during the stop phase.

    This exception is raised when errors occur while stopping oGRAC
    services before backup and upgrade.

    Examples:
        - Failed to stop oGRAC daemon
        - Failed to stop CMS server
        - Services still running after stop command
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize StopError.

        Stop errors are typically recoverable since no data changes
        have been made yet.
        """
        super().__init__(
            message=message,
            error_code=error_code or "STOP_ERROR",
            context=context,
            recoverable=True
        )


class BackupError(UpgradeError):
    """Exception raised during the backup phase.

    This exception is raised when backup operations fail, including
    directory creation failures, copy errors, or insufficient space.

    Examples:
        - Insufficient disk space for backup
        - Permission denied when creating backup directories
        - File copy failures
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize BackupError.

        Backup errors may or may not be recoverable depending on
        whether partial backups were created.
        """
        super().__init__(
            message=message,
            error_code=error_code or "BACKUP_ERROR",
            context=context,
            recoverable=True
        )


class UpgradeProcessError(UpgradeError):
    """Exception raised during the actual upgrade process.

    This exception is raised when errors occur during package installation,
    file operations, or module upgrades.

    Examples:
        - Package extraction failures
        - Module upgrade script failures
        - File permission errors during upgrade
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        current_module: Optional[str] = None
    ) -> None:
        """Initialize UpgradeProcessError.

        Args:
            message: Error description
            error_code: Error code
            context: Error context
            current_module: The module being upgraded when error occurred
        """
        ctx = context or {}
        if current_module:
            ctx["current_module"] = current_module
        super().__init__(
            message=message,
            error_code=error_code or "UPGRADE_PROCESS_ERROR",
            context=ctx,
            recoverable=True
        )
        self.current_module = current_module


class PostUpgradeError(UpgradeError):
    """Exception raised during post-upgrade operations.

    This exception is raised when errors occur during service startup,
    status checks, or system table modifications after upgrade.

    Examples:
        - Service startup failures
        - Node status check failures
        - System table modification errors
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize PostUpgradeError.

        Post-upgrade errors are typically recoverable through rollback.
        """
        super().__init__(
            message=message,
            error_code=error_code or "POST_UPGRADE_ERROR",
            context=context,
            recoverable=True
        )


class CommitError(UpgradeError):
    """Exception raised during the upgrade commit phase.

    This exception is raised when errors occur during version number
    updates or commit marker creation.

    Examples:
        - CMS version update failures
        - Commit marker creation failures
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize CommitError."""
        super().__init__(
            message=message,
            error_code=error_code or "COMMIT_ERROR",
            context=context,
            recoverable=False  # Commit errors typically mean upgrade succeeded but commit failed
        )


class RollbackError(UpgradeError):
    """Exception raised during rollback operations.

    This exception is raised when rollback operations fail, potentially
    leaving the system in an inconsistent state.

    Examples:
        - Backup restoration failures
        - Service restart failures during rollback
        - Missing backup files
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ) -> None:
        """Initialize RollbackError.

        Args:
            message: Error description
            error_code: Error code
            context: Error context
            original_error: The original error that triggered rollback
        """
        ctx = context or {}
        if original_error:
            ctx["original_error"] = str(original_error)
            ctx["original_error_type"] = original_error.__class__.__name__
        super().__init__(
            message=message,
            error_code=error_code or "ROLLBACK_ERROR",
            context=ctx,
            recoverable=False  # Rollback errors are critical
        )
        self.original_error = original_error


class ValidationError(UpgradeError):
    """Exception raised when validation checks fail.

    This exception is used for various validation failures including
    version checks, configuration validation, and pre-conditions.

    Examples:
        - Version whitelist check failures
        - Configuration parameter validation failures
        - Service status validation failures
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        validation_type: Optional[str] = None
    ) -> None:
        """Initialize ValidationError.

        Args:
            message: Error description
            error_code: Error code
            context: Error context
            validation_type: Type of validation that failed
        """
        ctx = context or {}
        if validation_type:
            ctx["validation_type"] = validation_type
        super().__init__(
            message=message,
            error_code=error_code or "VALIDATION_ERROR",
            context=ctx,
            recoverable=True
        )
        self.validation_type = validation_type


class TimeoutError(UpgradeError):
    """Exception raised when operations exceed their time limits.

    This exception is raised when commands or operations timeout.

    Examples:
        - Command execution timeouts
        - Service startup timeouts
        - Status check timeouts
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        timeout_seconds: Optional[int] = None
    ) -> None:
        """Initialize TimeoutError.

        Args:
            message: Error description
            error_code: Error code
            context: Error context
            timeout_seconds: The timeout value that was exceeded
        """
        ctx = context or {}
        if timeout_seconds:
            ctx["timeout_seconds"] = timeout_seconds
        super().__init__(
            message=message,
            error_code=error_code or "TIMEOUT_ERROR",
            context=ctx,
            recoverable=True
        )
        self.timeout_seconds = timeout_seconds
