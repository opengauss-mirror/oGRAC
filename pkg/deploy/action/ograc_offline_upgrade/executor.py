#!/usr/bin/env python3
"""
Command execution utilities for oGRAC offline upgrade module.

This module provides safe and robust command execution capabilities
with proper error handling, timeout support, and logging integration.
"""

import subprocess
import shlex
import getpass
from pathlib import Path
from typing import Optional, List, Tuple, Union, Dict, Any, Callable
from dataclasses import dataclass
from enum import Enum

from .exceptions import UpgradeError, TimeoutError


class ExecutionResult:
    """Result of a command execution.

    This class encapsulates the result of executing a command including
    return code, stdout, stderr, and execution time.

    Attributes:
        returncode: Command exit code (0 for success)
        stdout: Standard output as string
        stderr: Standard error as string
        command: The executed command
        execution_time: Time taken to execute (seconds)
        success: Whether the command succeeded (returncode == 0)
    """

    def __init__(
        self,
        returncode: int,
        stdout: str,
        stderr: str,
        command: str,
        execution_time: float
    ) -> None:
        """Initialize execution result.

        Args:
            returncode: Command exit code
            stdout: Standard output
            stderr: Standard error
            command: Executed command
            execution_time: Execution time in seconds
        """
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.command = command
        self.execution_time = execution_time

    @property
    def success(self) -> bool:
        """Check if command executed successfully."""
        return self.returncode == 0

    def raise_for_error(self, error_message: Optional[str] = None) -> None:
        """Raise exception if command failed.

        Args:
            error_message: Custom error message

        Raises:
            UpgradeError: If command failed
        """
        if not self.success:
            msg = error_message or f"Command failed with exit code {self.returncode}"
            detail = f"Command: {self.command}"
            if self.stderr:
                detail += f"\nStderr: {self.stderr[:500]}"
            raise UpgradeError(f"{msg}\n{detail}")

    def __str__(self) -> str:
        """Return string representation."""
        status = "success" if self.success else f"failed ({self.returncode})"
        return f"Command '{self.command[:50]}...' {status} in {self.execution_time:.2f}s"

    def __repr__(self) -> str:
        """Return detailed representation."""
        return (
            f"ExecutionResult("
            f"returncode={self.returncode}, "
            f"command='{self.command[:50]}...', "
            f"execution_time={self.execution_time:.2f}s)"
        )


class CommandExecutor:
    """Executor for shell commands with enhanced capabilities.

    This class provides a centralized way to execute commands with:
    - Timeout support
    - User switching (su execution)
    - Environment variable management
    - Automatic logging
    - Error handling

    Attributes:
        logger: Optional logger for command execution details
        default_timeout: Default timeout for commands (seconds)
        shell: Whether to use shell execution
    """

    def __init__(
        self,
        logger: Optional[Any] = None,
        default_timeout: int = 1800,
        shell: bool = True
    ) -> None:
        """Initialize command executor.

        Args:
            logger: Logger instance for output
            default_timeout: Default command timeout in seconds
            shell: Whether to use shell execution by default
        """
        self.logger = logger
        self.default_timeout = default_timeout
        self.shell = shell

    def execute(
        self,
        command: Union[str, List[str]],
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        input_data: Optional[str] = None,
        check: bool = False
    ) -> ExecutionResult:
        """Execute a command.

        Args:
            command: Command to execute (string or list)
            timeout: Timeout in seconds (None for default)
            cwd: Working directory for command
            env: Environment variables
            input_data: Input to pass to command
            check: Whether to raise exception on failure

        Returns:
            ExecutionResult with command output

        Raises:
            TimeoutError: If command times out
            UpgradeError: If check=True and command fails
        """
        import time

        timeout = timeout or self.default_timeout

        # Convert list to string if needed
        if isinstance(command, list):
            cmd_str = ' '.join(shlex.quote(str(c)) for c in command)
        else:
            cmd_str = str(command)

        if self.logger:
            self.logger.debug(f"Executing: {cmd_str[:200]}")

        start_time = time.time()

        try:
            result = subprocess.run(
                cmd_str if self.shell else shlex.split(cmd_str),
                shell=self.shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
                input=input_data
            )

            execution_time = time.time() - start_time

            exec_result = ExecutionResult(
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                command=cmd_str,
                execution_time=execution_time
            )

            if self.logger:
                level = "debug" if exec_result.success else "warning"
                getattr(self.logger, level)(
                    f"Command completed in {execution_time:.2f}s "
                    f"(rc={result.returncode})"
                )

            if check:
                exec_result.raise_for_error()

            return exec_result

        except subprocess.TimeoutExpired as e:
            execution_time = time.time() - start_time
            if self.logger:
                self.logger.error(f"Command timed out after {timeout}s")
            raise TimeoutError(
                f"Command timed out after {timeout} seconds",
                timeout_seconds=timeout,
                context={"command": cmd_str}
            ) from e

        except subprocess.SubprocessError as e:
            execution_time = time.time() - start_time
            if self.logger:
                self.logger.error(f"Command execution failed: {e}")
            raise UpgradeError(
                f"Command execution failed: {e}",
                context={"command": cmd_str}
            ) from e

    def execute_as_user(
        self,
        command: Union[str, List[str]],
        user: str,
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        check: bool = False
    ) -> ExecutionResult:
        """Execute a command as a specific user.

        This uses 'su' to switch to the target user before executing
        the command.

        Args:
            command: Command to execute
            user: Target username
            timeout: Timeout in seconds
            cwd: Working directory
            env: Environment variables
            check: Whether to raise on failure

        Returns:
            ExecutionResult with command output
        """
        # Build su command
        if isinstance(command, list):
            cmd_str = ' '.join(shlex.quote(str(c)) for c in command)
        else:
            cmd_str = str(command)

        # Use su to execute as target user
        su_cmd = f"su - {user} -s /bin/bash -c {shlex.quote(cmd_str)}"

        return self.execute(
            su_cmd,
            timeout=timeout,
            cwd=cwd,
            env=env,
            check=check
        )

    def execute_with_bashrc(
        self,
        command: Union[str, List[str]],
        user: Optional[str] = None,
        timeout: Optional[int] = None,
        check: bool = False
    ) -> ExecutionResult:
        """Execute command with user's .bashrc sourced.

        This is commonly needed for oGRAC commands that depend on
        environment variables set in .bashrc.

        Args:
            command: Command to execute
            user: Target user (None for current user)
            timeout: Timeout in seconds
            check: Whether to raise on failure

        Returns:
            ExecutionResult with command output
        """
        if isinstance(command, list):
            cmd_str = ' '.join(shlex.quote(str(c)) for c in command)
        else:
            cmd_str = str(command)

        # Source .bashrc before executing command
        wrapped_cmd = f"source ~/.bashrc && {cmd_str}"

        if user:
            return self.execute_as_user(
                wrapped_cmd,
                user=user,
                timeout=timeout,
                check=check
            )
        else:
            return self.execute(
                wrapped_cmd,
                timeout=timeout,
                check=check
            )

    def run_pipeline(
        self,
        commands: List[Union[str, List[str]]],
        timeout: Optional[int] = None,
        check: bool = True
    ) -> List[ExecutionResult]:
        """Execute multiple commands in sequence.

        Args:
            commands: List of commands to execute
            timeout: Timeout per command
            check: Whether to stop on first failure

        Returns:
            List of ExecutionResult for each command
        """
        results = []

        for cmd in commands:
            result = self.execute(cmd, timeout=timeout, check=False)
            results.append(result)

            if check and not result.success:
                if self.logger:
                    self.logger.error(
                        f"Pipeline stopped due to failure in: {cmd}"
                    )
                break

        return results

    def check_command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH.

        Args:
            command: Command to check

        Returns:
            True if command exists, False otherwise
        """
        result = self.execute(
            f"which {shlex.quote(command)}",
            check=False
        )
        return result.success

    def get_command_path(self, command: str) -> Optional[str]:
        """Get the full path of a command.

        Args:
            command: Command to lookup

        Returns:
            Full path to command, or None if not found
        """
        result = self.execute(
            f"which {shlex.quote(command)}",
            check=False
        )
        if result.success:
            return result.stdout.strip()
        return None


# Global executor instance
_default_executor: Optional[CommandExecutor] = None


def get_executor(
    logger: Optional[Any] = None,
    default_timeout: int = 1800
) -> CommandExecutor:
    """Get or create the default command executor.

    Args:
        logger: Logger instance
        default_timeout: Default timeout

    Returns:
        CommandExecutor instance
    """
    global _default_executor

    if _default_executor is None:
        _default_executor = CommandExecutor(
            logger=logger,
            default_timeout=default_timeout
        )

    return _default_executor


def reset_executor() -> None:
    """Reset the default executor."""
    global _default_executor
    _default_executor = None
