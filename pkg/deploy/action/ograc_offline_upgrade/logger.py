#!/usr/bin/env python3
"""
Logging configuration for oGRAC offline upgrade module.

This module provides comprehensive logging capabilities including:
- Colored console output for better visibility
- File-based logging with rotation support
- Structured logging with contextual information
- Multiple log levels appropriate for different scenarios
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Union
from datetime import datetime


# Color codes for terminal output
class ColorCode:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to log levels in terminal output.

    This formatter enhances log readability by color-coding different
    log levels when outputting to a terminal.

    Attributes:
        COLORS: Mapping of log levels to color codes
    """

    COLORS: Dict[str, str] = {
        'DEBUG': ColorCode.CYAN,
        'INFO': ColorCode.GREEN,
        'WARNING': ColorCode.YELLOW,
        'ERROR': ColorCode.RED,
        'CRITICAL': ColorCode.BOLD + ColorCode.RED,
    }

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        use_colors: bool = True
    ) -> None:
        """Initialize the colored formatter.

        Args:
            fmt: Log message format string
            datefmt: Date format string
            use_colors: Whether to use ANSI colors (auto-detected if None)
        """
        super().__init__(fmt=fmt, datefmt=datefmt)
        if use_colors is None:
            # Auto-detect: use colors if stdout is a terminal
            use_colors = sys.stdout.isatty()
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with optional color coding.

        Args:
            record: The log record to format

        Returns:
            Formatted log message string
        """
        # Make a copy to avoid modifying the original
        record_copy = logging.makeLogRecord(record.__dict__)

        if self.use_colors and record_copy.levelname in self.COLORS:
            color = self.COLORS[record_copy.levelname]
            reset = ColorCode.RESET
            record_copy.levelname = f"{color}{record_copy.levelname}{reset}"

        return super().format(record_copy)


class ContextFilter(logging.Filter):
    """Filter that adds contextual information to log records.

    This filter enriches log records with additional context such as
    upgrade stage, node ID, and other relevant information.
    """

    def __init__(self, context: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the context filter.

        Args:
            context: Dictionary of context information to add to logs
        """
        super().__init__()
        self.context = context or {}

    def filter(self, record: logging.LogRecord) -> bool:
        """Add context information to the log record.

        Args:
            record: The log record to enrich

        Returns:
            True to always allow the record through
        """
        for key, value in self.context.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True

    def update_context(self, context: Dict[str, Any]) -> None:
        """Update the context dictionary.

        Args:
            context: New context dictionary (merged with existing)
        """
        self.context.update(context)


class UpgradeLogger:
    """Centralized logging manager for the upgrade process.

    This class provides a unified interface for configuring and
    using logging throughout the upgrade process.

    Attributes:
        logger: The underlying Python logger instance
        context_filter: Filter for adding contextual information
    """

    # Default log format
    DEFAULT_FORMAT = (
        "[%(asctime)s] [%(levelname)s] "
        "[%(name)s] %(message)s"
    )

    # Detailed format with context
    DETAILED_FORMAT = (
        "[%(asctime)s] [%(levelname)s] "
        "[%(name)s] [%(stage)s] %(message)s"
    )

    # Date format
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    def __init__(
        self,
        name: str = "ograc_upgrade",
        log_level: Union[str, int] = logging.INFO,
        log_file: Optional[Path] = None,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        use_colors: bool = True,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize the upgrade logger.

        Args:
            name: Logger name
            log_level: Minimum log level to record
            log_file: Path to log file (None for console-only)
            max_bytes: Maximum bytes per log file before rotation
            backup_count: Number of backup files to keep
            use_colors: Whether to use colored output
            context: Initial context dictionary
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self._parse_level(log_level))
        self.logger.handlers = []  # Clear any existing handlers

        # Context filter for adding metadata
        self.context_filter = ContextFilter(context)
        self.logger.addFilter(self.context_filter)

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_formatter = ColoredFormatter(
            fmt=self.DEFAULT_FORMAT,
            datefmt=self.DATE_FORMAT,
            use_colors=use_colors
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # File handler with rotation
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                fmt=self.DETAILED_FORMAT,
                datefmt=self.DATE_FORMAT
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

    def _parse_level(self, level: Union[str, int]) -> int:
        """Parse log level from string or int.

        Args:
            level: Log level as string (e.g., 'INFO') or int

        Returns:
            Integer log level
        """
        if isinstance(level, int):
            return level

        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'WARN': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL,
        }
        return level_map.get(level.upper(), logging.INFO)

    def set_stage(self, stage: str) -> None:
        """Set the current upgrade stage for context.

        Args:
            stage: Current stage name (e.g., 'pre_upgrade', 'backup')
        """
        self.context_filter.update_context({'stage': stage})
        self.logger.info(f"Entering stage: {stage}")

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log a debug message.

        Args:
            message: Log message
            **kwargs: Additional context data
        """
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log an info message.

        Args:
            message: Log message
            **kwargs: Additional context data
        """
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log a warning message.

        Args:
            message: Log message
            **kwargs: Additional context data
        """
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log an error message.

        Args:
            message: Log message
            **kwargs: Additional context data
        """
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log a critical message.

        Args:
            message: Log message
            **kwargs: Additional context data
        """
        self._log(logging.CRITICAL, message, **kwargs)

    def _log(self, level: int, message: str, **kwargs: Any) -> None:
        """Internal method to log with optional context.

        Args:
            level: Log level
            message: Log message
            **kwargs: Additional context data to add to the record
        """
        if kwargs:
            extra = kwargs
        else:
            extra = {}
        self.logger.log(level, message, extra=extra)

    def log_exception(
        self,
        exception: Exception,
        message: Optional[str] = None,
        level: int = logging.ERROR
    ) -> None:
        """Log an exception with full traceback.

        Args:
            exception: The exception to log
            message: Optional custom message
            level: Log level (default ERROR)
        """
        if message:
            self.logger.log(level, message)
        self.logger.log(level, f"Exception: {exception}", exc_info=True)


# Global logger instance (lazy initialization)
_logger_instance: Optional[UpgradeLogger] = None


def get_logger(
    name: str = "ograc_upgrade",
    log_level: Union[str, int] = logging.INFO,
    log_file: Optional[Path] = None,
    **kwargs: Any
) -> UpgradeLogger:
    """Get or create the global logger instance.

    This function provides a singleton-like interface for accessing
    the upgrade logger throughout the application.

    Args:
        name: Logger name
        log_level: Minimum log level
        log_file: Path to log file
        **kwargs: Additional arguments for UpgradeLogger

    Returns:
        UpgradeLogger instance

    Example:
        >>> logger = get_logger(log_level="DEBUG", log_file=Path("/var/log/upgrade.log"))
        >>> logger.info("Starting upgrade process")
    """
    global _logger_instance

    if _logger_instance is None:
        _logger_instance = UpgradeLogger(
            name=name,
            log_level=log_level,
            log_file=log_file,
            **kwargs
        )

    return _logger_instance


def reset_logger() -> None:
    """Reset the global logger instance.

    This is useful for testing or when you need to reconfigure logging.
    """
    global _logger_instance
    _logger_instance = None
