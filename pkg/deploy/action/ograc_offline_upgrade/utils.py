#!/usr/bin/env python3
"""
Utility functions for oGRAC offline upgrade module.

This module provides various utility functions used throughout the
upgrade process, including file operations, command execution helpers,
and version parsing utilities.
"""

import functools
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Tuple, Union


class VersionInfo:
    """Represents a semantic version.

    This class provides version parsing and comparison capabilities
    compatible with oGRAC version formats.

    Attributes:
        major: Major version number
        minor: Minor version number
        patch: Patch version number
        suffix: Optional version suffix (e.g., 'B1', 'SP1')
    """

    VERSION_PATTERN = re.compile(
        r'^(\d+)\.(\d+)(?:\.(\d+))?(?:[.-]?(.*))?$'
    )

    def __init__(
        self,
        major: int,
        minor: int,
        patch: int = 0,
        suffix: str = ""
    ) -> None:
        """Initialize version info.

        Args:
            major: Major version number
            minor: Minor version number
            patch: Patch version number (default 0)
            suffix: Version suffix (default empty)
        """
        self.major = major
        self.minor = minor
        self.patch = patch
        self.suffix = suffix

    @classmethod
    def parse(cls, version_str: str) -> 'VersionInfo':
        """Parse a version string.

        Args:
            version_str: Version string (e.g., "1.0.0", "1.0.0.B1")

        Returns:
            VersionInfo instance

        Raises:
            ValueError: If version string is invalid
        """
        match = cls.VERSION_PATTERN.match(version_str.strip())
        if not match:
            raise ValueError(f"Invalid version string: {version_str}")

        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        suffix = match.group(4) or ""

        return cls(major, minor, patch, suffix)

    def __str__(self) -> str:
        """Return version as string."""
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.suffix:
            version += f".{self.suffix}"
        return version

    def __repr__(self) -> str:
        """Return detailed string representation."""
        return f"VersionInfo({self.major}, {self.minor}, {self.patch}, '{self.suffix}')"

    def __eq__(self, other: object) -> bool:
        """Check equality with another version."""
        if not isinstance(other, VersionInfo):
            return NotImplemented
        return (
            self.major == other.major and
            self.minor == other.minor and
            self.patch == other.patch and
            self.suffix == other.suffix
        )

    def __lt__(self, other: 'VersionInfo') -> bool:
        """Check if this version is less than another."""
        if not isinstance(other, VersionInfo):
            return NotImplemented

        # Compare major, minor, patch
        for attr in ['major', 'minor', 'patch']:
            self_val = getattr(self, attr)
            other_val = getattr(other, attr)
            if self_val != other_val:
                return self_val < other_val

        # Compare suffix (empty suffix is greater)
        if not self.suffix and other.suffix:
            return False
        if self.suffix and not other.suffix:
            return True
        return self.suffix < other.suffix

    def __le__(self, other: 'VersionInfo') -> bool:
        """Check if this version is less than or equal to another."""
        return self == other or self < other

    def __gt__(self, other: 'VersionInfo') -> bool:
        """Check if this version is greater than another."""
        return not self <= other

    def __ge__(self, other: 'VersionInfo') -> bool:
        """Check if this version is greater than or equal to another."""
        return not self < other

    @property
    def base_version(self) -> str:
        """Get base version without suffix."""
        return f"{self.major}.{self.minor}.{self.patch}"


def read_version_from_yaml(path: Path) -> str:
    """Read version from versions.yml file.

    Args:
        path: Path to versions.yml file

    Returns:
        Version string

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If version cannot be parsed
    """
    if not path.exists():
        raise FileNotFoundError(f"Versions file not found: {path}")

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('Version:'):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1].strip()

    raise ValueError(f"Version not found in {path}")


def ensure_dir(
    path: Path,
    mode: int = 0o755,
    user: Optional[str] = None,
    group: Optional[str] = None
) -> Path:
    """Ensure a directory exists with proper permissions.

    Args:
        path: Directory path
        mode: Directory permissions (octal)
        user: Owner username
        group: Group name

    Returns:
        The directory path
    """
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)

    if user or group:
        shutil.chown(path, user=user, group=group)

    return path


def safe_remove(path: Path, recursive: bool = False) -> bool:
    """Safely remove a file or directory.

    Args:
        path: Path to remove
        recursive: Whether to recursively remove directories

    Returns:
        True if removed successfully, False otherwise
    """
    try:
        if not path.exists():
            return True

        if path.is_file() or path.is_symlink():
            path.unlink()
        elif path.is_dir() and recursive:
            shutil.rmtree(path)
        elif path.is_dir():
            path.rmdir()

        return True
    except (OSError, PermissionError) as e:
        return False


def copy_tree(
    src: Path,
    dst: Path,
    preserve_symlinks: bool = True,
    ignore_patterns: Optional[List[str]] = None
) -> None:
    """Copy a directory tree.

    Args:
        src: Source directory
        dst: Destination directory
        preserve_symlinks: Whether to preserve symlinks
        ignore_patterns: List of patterns to ignore
    """
    if ignore_patterns is None:
        ignore_patterns = ['__pycache__', '*.pyc', '.git']

    def ignore_func(dir: str, contents: List[str]) -> List[str]:
        import fnmatch
        ignored = []
        for pattern in ignore_patterns:
            for content in contents:
                if fnmatch.fnmatch(content, pattern):
                    ignored.append(content)
        return ignored

    if dst.exists():
        shutil.rmtree(dst)

    shutil.copytree(
        src,
        dst,
        symlinks=preserve_symlinks,
        ignore=ignore_func
    )


def chown_recursive(
    path: Path,
    user: Optional[str] = None,
    group: Optional[str] = None
) -> None:
    """Recursively change ownership of a directory.

    Args:
        path: Path to change ownership
        user: New owner username
        group: New group name
    """
    if not path.exists():
        return

    shutil.chown(path, user=user, group=group)

    if path.is_dir():
        for item in path.iterdir():
            chown_recursive(item, user=user, group=group)


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: Tuple[type, ...] = (Exception,)
) -> Callable:
    """Decorator for retrying a function with exponential backoff.

    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay between attempts (seconds)
        backoff: Backoff multiplier
        exceptions: Tuple of exceptions to catch

    Returns:
        Decorated function

    Example:
        @retry(max_attempts=3, delay=1.0)
        def flaky_operation():
            # Might fail occasionally
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_delay = delay
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        time.sleep(current_delay)
                        current_delay *= backoff

            raise last_exception

        return wrapper
    return decorator


def parse_cms_stat(output: str) -> Dict[str, Any]:
    """Parse CMS stat command output.

    Args:
        output: Raw output from 'cms stat' command

    Returns:
        Dictionary with parsed node status information
    """
    nodes = []
    lines = output.strip().split('\n')

    # Skip header line if present
    start_idx = 0
    if lines and ('NODE_ID' in lines[0] or 'NAME' in lines[0]):
        start_idx = 1

    for line in lines[start_idx:]:
        parts = line.split()
        if len(parts) >= 4:
            nodes.append({
                'node_id': parts[0],
                'name': parts[1],
                'stat': parts[2],
                'pre_stat': parts[3],
            })

    online_count = sum(1 for n in nodes if n['stat'] == 'ONLINE')

    return {
        'nodes': nodes,
        'total': len(nodes),
        'online': online_count,
        'status': 'ONLINE' if online_count == len(nodes) and nodes else 'OFFLINE'
    }


def is_process_running(pattern: str) -> bool:
    """Check if a process matching the pattern is running.

    Args:
        pattern: Pattern to match in process list

    Returns:
        True if process is running, False otherwise
    """
    try:
        result = subprocess.run(
            ['pgrep', '-f', pattern],
            capture_output=True,
            text=True
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        # Fallback to ps command
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True
            )
            return pattern in result.stdout
        except subprocess.SubprocessError:
            return False


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Human-readable duration string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.2f}h"


def truncate_string(s: str, max_length: int, suffix: str = "...") -> str:
    """Truncate a string to maximum length.

    Args:
        s: Input string
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


class ProgressTracker:
    """Simple progress tracker for long-running operations.

    This class provides a simple way to track and display progress
    for operations that process multiple items.

    Example:
        tracker = ProgressTracker(total=100, description="Processing")
        for i in range(100):
            # Do work
            tracker.update(1)
        tracker.finish()
    """

    def __init__(
        self,
        total: int,
        description: str = "Processing",
        logger: Optional[Any] = None
    ) -> None:
        """Initialize progress tracker.

        Args:
            total: Total number of items
            description: Operation description
            logger: Optional logger for output
        """
        self.total = total
        self.description = description
        self.logger = logger
        self.current = 0
        self.start_time = time.time()

    def update(self, increment: int = 1) -> None:
        """Update progress.

        Args:
            increment: Number of items completed
        """
        self.current += increment

        if self.logger:
            percent = (self.current / self.total) * 100
            elapsed = time.time() - self.start_time
            self.logger.info(
                f"{self.description}: {self.current}/{self.total} "
                f"({percent:.1f}%) - Elapsed: {format_duration(elapsed)}"
            )

    def finish(self) -> None:
        """Mark progress as complete."""
        self.current = self.total
        elapsed = time.time() - self.start_time

        if self.logger:
            self.logger.info(
                f"{self.description} completed in {format_duration(elapsed)}"
            )
