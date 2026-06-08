#!/usr/bin/env python3
"""logicrep utilities."""

import os
import subprocess
import sys

_ACTION_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ACTION_ROOT not in sys.path:
    sys.path.append(_ACTION_ROOT)
from nofile_utils import (
    apply_nofile_rlimit_before_setuid,
    resolve_nofile_rlimit_for_user,
)


class CommandError(Exception):
    def __init__(self, cmd, returncode, stdout="", stderr=""):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Command failed (rc={returncode}): {cmd}")


def exec_popen(cmd, timeout=600):
    pobj = subprocess.Popen(
        ["bash", "-c", cmd],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = pobj.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        pobj.kill()
        pobj.communicate()
        return -1, "", f"Timeout after {timeout}s"
    return (
        pobj.returncode,
        stdout_b.decode(errors="replace").strip(),
        stderr_b.decode(errors="replace").strip(),
    )


def run_cmd(cmd, timeout=600, error_msg="Command failed"):
    rc, out, err = exec_popen(cmd, timeout=timeout)
    if rc:
        raise CommandError(cmd, rc, out, err)
    return out


def _tail_log(log_file, n=20):
    """Read last n lines from a log file for error summary."""
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        tail = "".join(lines[-n:]).strip()
        if tail:
            return f"{tail}\nSee full log: {log_file}"
    except OSError:
        pass
    return ""


def run_python_as_user(script, args, user, log_file=None, cwd=None, timeout=600, env_extra=None):
    import pwd
    pw = pwd.getpwnam(user)
    uid, gid, home = pw.pw_uid, pw.pw_gid, pw.pw_dir

    soft, hard = resolve_nofile_rlimit_for_user(user)

    def _demote():
        apply_nofile_rlimit_before_setuid(soft, hard)
        os.setgid(gid)
        os.initgroups(user, gid)
        os.setuid(uid)

    env = os.environ.copy()
    env.update({"HOME": home, "USER": user, "LOGNAME": user})
    if env_extra:
        env.update(env_extra)

    cmd_list = [sys.executable, "-B", script] + list(args)
    work_dir = cwd or os.path.dirname(os.path.abspath(script))

    try:
        proc = subprocess.Popen(
            cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=work_dir, env=env, preexec_fn=_demote,
        )
        stdout_b, stderr_b = proc.communicate(timeout=timeout)
        stdout = stdout_b.decode("utf-8", errors="replace").strip()
        stderr = stderr_b.decode("utf-8", errors="replace").strip()

        if log_file:
            try:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                with open(log_file, "a", encoding="utf-8") as log_fh:
                    combined = "\n".join(part for part in (stdout, stderr) if part)
                    if combined:
                        log_fh.write(combined + "\n")
            except OSError:
                pass

        if proc.returncode != 0 and not stderr and log_file:
            fallback = _tail_log(log_file, 20)
            if fallback:
                stderr = fallback

        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", f"Timeout after {timeout}s"


def run_shell_as_user(cmd, user, timeout=600):
    full_cmd = f'su -s /bin/bash - {user} -c "{cmd}"'
    return exec_popen(full_cmd, timeout=timeout)


def ensure_dir(path, mode=0o750, owner=""):
    os.makedirs(path, mode=mode, exist_ok=True)
    if owner:
        exec_popen(f"chown {owner} {path}")


def chown_recursive(path, owner):
    exec_popen(f"chown -hR {owner} {path}")
