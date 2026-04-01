#!/usr/bin/env python3
"""og_om utilities."""

import os
import subprocess
import sys


class CommandError(Exception):
    def __init__(self, cmd, returncode, stdout="", stderr=""):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Command failed (rc={returncode}): {cmd}")


def exec_popen(cmd, timeout=600):
    """Execute a shell command."""
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


def run_python_as_user(script, args, user, log_file=None, cwd=None, timeout=600):
    """Run a Python script as the specified user."""
    import pwd

    pw = pwd.getpwnam(user)
    uid, gid, home = pw.pw_uid, pw.pw_gid, pw.pw_dir

    def _demote():
        os.setgid(gid)
        os.initgroups(user, gid)
        os.setuid(uid)

    env = os.environ.copy()
    env.update({"HOME": home, "USER": user, "LOGNAME": user})

    cmd_list = [sys.executable, script] + list(args)
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
                if not os.path.exists(log_file):
                    open(log_file, "a").close()
                os.chown(log_file, uid, gid)
                os.chmod(log_file, 0o640)
                with open(log_file, "a", encoding="utf-8") as log_fh:
                    combined = "\n".join(part for part in (stdout, stderr) if part)
                    if combined:
                        log_fh.write(combined + "\n")
            except OSError:
                pass

        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_b, stderr_b = proc.communicate()
        stdout = stdout_b.decode("utf-8", errors="replace").strip()
        stderr = stderr_b.decode("utf-8", errors="replace").strip()
        if log_file:
            try:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                if not os.path.exists(log_file):
                    open(log_file, "a").close()
                os.chown(log_file, uid, gid)
                os.chmod(log_file, 0o640)
                with open(log_file, "a", encoding="utf-8") as log_fh:
                    combined = "\n".join(part for part in (stdout, stderr, f"Timeout after {timeout}s") if part)
                    if combined:
                        log_fh.write(combined + "\n")
            except OSError:
                pass
        return -1, "", f"Timeout after {timeout}s"


def run_shell_as_user(cmd, user, timeout=600):
    """Run a shell command as the specified user via su."""
    rc, _, _ = exec_popen(f"id -u {user}", timeout=10)
    if rc != 0:
        raise CommandError(f"id -u {user}", rc, "", f"user {user} not exist")

    full_cmd = f'su -s /bin/bash - {user} -c "{cmd}"'
    return exec_popen(full_cmd, timeout=timeout)


def ensure_dir(path, mode=0o750, owner=""):
    os.makedirs(path, mode=mode, exist_ok=True)
    if owner:
        exec_popen(f"chown {owner} {path}")


def ensure_file(path, mode=0o640, owner=""):
    if not os.path.exists(path):
        open(path, "a").close()
    os.chmod(path, mode)
    if owner:
        exec_popen(f"chown {owner} {path}")


def chown_recursive(path, owner):
    exec_popen(f"chown -hR {owner} {path}")


def chmod_recursive(path, mode):
    exec_popen(f"chmod -Rf {mode} {path}")
