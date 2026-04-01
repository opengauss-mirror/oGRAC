#!/usr/bin/env python3
"""logicrep utilities."""

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


def run_python_as_user(script, args, user, log_file=None, cwd=None, timeout=600, env_extra=None):
    import pwd
    pw = pwd.getpwnam(user)
    uid, gid, home = pw.pw_uid, pw.pw_gid, pw.pw_dir

    def _demote():
        os.setgid(gid)
        os.initgroups(user, gid)
        os.setuid(uid)

    env = os.environ.copy()
    env.update({"HOME": home, "USER": user, "LOGNAME": user})
    if env_extra:
        env.update(env_extra)

    cmd_list = [sys.executable, "-B", script] + list(args)
    work_dir = cwd or os.path.dirname(os.path.abspath(script))

    log_fh = None
    try:
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            log_fh = open(log_file, "a", encoding="utf-8")
            proc = subprocess.Popen(
                cmd_list, stdout=log_fh, stderr=subprocess.STDOUT,
                cwd=work_dir, env=env, preexec_fn=_demote,
            )
            proc.communicate(timeout=timeout)
            return proc.returncode, "", ""
        proc = subprocess.Popen(
            cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=work_dir, env=env, preexec_fn=_demote,
        )
        stdout_b, stderr_b = proc.communicate(timeout=timeout)
        return (
            proc.returncode,
            stdout_b.decode("utf-8", errors="replace").strip(),
            stderr_b.decode("utf-8", errors="replace").strip(),
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", f"Timeout after {timeout}s"
    finally:
        if log_fh:
            log_fh.close()


def run_shell_as_user(cmd, user, timeout=600):
    full_cmd = f'su -s /bin/bash - {user} -c "{cmd}"'
    return exec_popen(full_cmd, timeout=timeout)


def ensure_dir(path, mode=0o750, owner=""):
    os.makedirs(path, mode=mode, exist_ok=True)
    if owner:
        exec_popen(f"chown {owner} {path}")


def chown_recursive(path, owner):
    exec_popen(f"chown -hR {owner} {path}")
