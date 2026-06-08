#!/usr/bin/env python3
"""Failure diagnostics helpers for deploy actions."""

import glob
import os
import sys
from collections import deque


DEFAULT_TAIL_LINES = 30
DEFAULT_MAX_FILES = 3


def _read_tail(path, lines):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return "".join(deque(f, maxlen=lines)).rstrip()
    except OSError as err:
        return f"(failed to read: {err})"


def _file_status(path):
    if not os.path.exists(path):
        return "missing"
    if os.path.isdir(path):
        return "is directory"
    if not os.path.isfile(path):
        return "not regular file"
    try:
        return f"exists, size={os.path.getsize(path)}"
    except OSError as err:
        return f"exists, stat failed: {err}"


def _latest_files(paths, max_files):
    files = [p for p in paths if os.path.isfile(p)]
    try:
        return sorted(files, key=lambda p: os.path.getmtime(p), reverse=True)[:max_files]
    except OSError:
        return files[:max_files]


def _resolve_spec(spec):
    name = spec.get("name", "log")
    path = spec.get("path", "")
    kind = spec.get("kind", "file")
    lines = int(spec.get("lines", DEFAULT_TAIL_LINES))
    max_files = int(spec.get("max_files", DEFAULT_MAX_FILES))

    resolved = {
        "name": name,
        "path": path,
        "kind": kind,
        "lines": lines,
        "status": "",
        "files": [],
    }

    if not path:
        resolved["status"] = "empty path"
        return resolved

    if kind == "file":
        resolved["status"] = _file_status(path)
        if os.path.isfile(path):
            resolved["files"] = [path]
        return resolved

    if kind == "dir":
        if not os.path.exists(path):
            resolved["status"] = "missing"
            return resolved
        if not os.path.isdir(path):
            resolved["status"] = "not directory"
            return resolved
        pattern = spec.get("pattern", "*.log")
        resolved["status"] = "exists"
        resolved["files"] = _latest_files(glob.glob(os.path.join(path, pattern)), max_files)
        if not resolved["files"]:
            resolved["status"] = f"exists, no files matched {pattern}"
        return resolved

    if kind == "glob":
        files = _latest_files(glob.glob(path), max_files)
        resolved["status"] = f"matched {len(files)} file(s)" if files else "no matches"
        resolved["files"] = files
        return resolved

    resolved["status"] = f"unknown kind: {kind}"
    return resolved


def format_failure_diagnostics(component, action, specs, error=None,
                               exit_code=None, tail_lines=DEFAULT_TAIL_LINES):
    """Return a human-readable failure diagnostics report."""
    header = f"{component} {action} failed"
    if exit_code is not None:
        header += f" (exit code: {exit_code})"
    if error is not None:
        header += f": {error}"

    resolved = []
    for spec in specs or []:
        item = dict(spec)
        item.setdefault("lines", tail_lines)
        resolved.append(_resolve_spec(item))

    lines = [header, "", "Diagnostic log paths:"]
    if not resolved:
        lines.append("- no diagnostic logs registered")
    else:
        for item in resolved:
            lines.append(
                f"- {item['name']}: {item['path']} "
                f"[{item['kind']}, {item['status']}]"
            )

    for item in resolved:
        for fpath in item["files"]:
            lines.extend([
                "",
                f"--- {item['name']}: {fpath} (last {item['lines']} lines) ---",
                _read_tail(fpath, item["lines"]) or "(empty)",
            ])

    return "\n".join(lines)


def emit_failure_diagnostics(component, action, specs, error=None,
                             exit_code=None, stream=None,
                             tail_lines=DEFAULT_TAIL_LINES):
    """Print a failure diagnostics report to stderr by default."""
    if stream is None:
        stream = sys.stderr
    print(
        format_failure_diagnostics(
            component, action, specs, error=error,
            exit_code=exit_code, tail_lines=tail_lines,
        ),
        file=stream,
    )
