# -*- coding: utf-8 -*-
"""RLIMIT_NOFILE for setuid children: match target user's login ulimit (su + ulimit)."""

import logging
import os
import re
import resource
import subprocess
from typing import Dict, Optional, Tuple

LOG = logging.getLogger(__name__)

_rlimit_cache: Dict[str, Tuple[int, int]] = {}


def read_fs_nr_open() -> Optional[int]:
    """Linux per-process open file ceiling from ``/proc/sys/fs/nr_open`` (not root ``ulimit -Hn``)."""
    try:
        with open("/proc/sys/fs/nr_open", encoding="ascii", errors="replace") as fh:
            text = fh.read().strip()
        n = int(text)
        if n < 1:
            return None
        return n
    except (OSError, ValueError) as exc:
        LOG.warning("nofile: cannot read /proc/sys/fs/nr_open: %s", exc)
        return None


def query_login_ulimit_sn_hn(target_user: str) -> Optional[Tuple[int, int]]:
    """Return (soft, hard) nofile from a non-interactive su session (PAM/limits.conf)."""
    cmd = [
        "su",
        "-s",
        "/bin/bash",
        "-",
        target_user,
        "-c",
        "ulimit -Sn; ulimit -Hn",
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        LOG.warning(
            "nofile: su/ulimit subprocess failed for user %r: %s",
            target_user,
            exc,
        )
        return None
    if proc.returncode != 0:
        LOG.warning(
            "nofile: su/ulimit returned rc=%s for user %r stderr=%r",
            proc.returncode,
            target_user,
            (proc.stderr or "").strip(),
        )
        return None
    lines = [ln.strip() for ln in proc.stdout.strip().splitlines() if ln.strip()]
    if len(lines) < 2:
        LOG.warning(
            "nofile: unexpected ulimit output for user %r: %r",
            target_user,
            proc.stdout,
        )
        return None
    try:
        soft, hard = int(lines[0]), int(lines[1])
    except ValueError:
        LOG.warning(
            "nofile: non-integer ulimit for user %r: %r",
            target_user,
            lines[:2],
        )
        return None
    if soft < 1 or hard < 1:
        return None
    if soft > hard:
        soft, hard = hard, soft
    return soft, hard


def _cap_nofile_to_nr_open(
    soft: int,
    hard: int,
    nr_open: int,
    target_user: str,
) -> Tuple[int, int]:
    """Cap soft/hard to ``fs.nr_open``; keep ``soft <= hard``."""
    eff_hard = min(hard, nr_open)
    eff_soft = min(soft, eff_hard)
    if eff_soft < 1:
        eff_soft = 1
    if eff_hard < eff_soft:
        eff_hard = eff_soft
    if (eff_soft, eff_hard) != (soft, hard):
        LOG.warning(
            "nofile: target user %r login nofile %d:%d exceeds fs.nr_open %d, use %d:%d",
            target_user,
            soft,
            hard,
            nr_open,
            eff_soft,
            eff_hard,
        )
    return eff_soft, eff_hard


def resolve_nofile_rlimit_for_user(target_user: str) -> Tuple[int, int]:
    """
    Call from the parent process before subprocess.Popen(..., preexec_fn=...).
    Reads login ulimit and ``/proc/sys/fs/nr_open``, returns effective (soft, hard)
    for ``apply_nofile_rlimit_before_setuid`` only.
    """
    user = (target_user or "ograc").strip() or "ograc"
    if user in _rlimit_cache:
        return _rlimit_cache[user]

    parsed = query_login_ulimit_sn_hn(user)
    if parsed is None:
        LOG.warning(
            "nofile: using fallback 102400:102400 for user %r (login ulimit query failed)",
            user,
        )
        soft, hard = 102400, 102400
    else:
        soft, hard = parsed

    nr_open = read_fs_nr_open()
    if nr_open is not None:
        soft, hard = _cap_nofile_to_nr_open(soft, hard, nr_open, user)
    else:
        LOG.warning(
            "nofile: fs.nr_open unavailable for user %r; using uncapped login/fallback %d:%d",
            user,
            soft,
            hard,
        )

    _rlimit_cache[user] = (soft, hard)
    return soft, hard


def apply_nofile_rlimit_before_setuid(soft: int, hard: int) -> None:
    """
    preexec_fn only: must not fork further. Caller passes parent-resolved (soft, hard).
    On failure, fail-fast so the child does not exec with wrong inherited nofile.
    """
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    except (ValueError, OSError) as exc:
        msg = (
            f"nofile: setrlimit(RLIMIT_NOFILE, ({soft}, {hard})) failed in preexec_fn: "
            f"{exc}; refusing to start child with inherited limits\n"
        )
        try:
            os.write(2, msg.encode("utf-8", errors="replace"))
        except OSError:
            pass
        os._exit(127)


def update_limits_conf_user_nofile(
    limits_path: str,
    username: str,
    nofile_value: int,
) -> None:
    """
    Remove only ``username``'s soft/hard nofile lines from limits.conf, then append
    new hard/soft entries. Values are capped to ``/proc/sys/fs/nr_open`` when readable,
    matching runtime ``resolve_nofile_rlimit_for_user`` / ``storage_deploy/start.sh``.
    """
    if not username or nofile_value < 1:
        return
    write_value = nofile_value
    nr_open = read_fs_nr_open()
    if nr_open is not None:
        if write_value > nr_open:
            LOG.warning(
                "nofile: limits.conf requested nofile %d for user %r exceeds "
                "fs.nr_open %d, writing %d",
                nofile_value,
                username,
                nr_open,
                nr_open,
            )
            write_value = nr_open
    else:
        LOG.warning(
            "nofile: fs.nr_open unavailable; writing requested nofile %d for user %r "
            "to limits.conf without cap",
            nofile_value,
            username,
        )

    if not os.path.exists(limits_path):
        open(limits_path, "a", encoding="utf-8").close()
    out_lines = []
    with open(limits_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                parts = re.split(r"\s+", stripped)
                if (
                    len(parts) >= 4
                    and parts[0] == username
                    and parts[1] in ("soft", "hard")
                    and parts[2] == "nofile"
                ):
                    continue
            out_lines.append(line)
    with open(limits_path, "w", encoding="utf-8") as fh:
        for line in out_lines:
            fh.write(line)
        if out_lines and not out_lines[-1].endswith("\n"):
            fh.write("\n")
        fh.write(f"{username} hard nofile {write_value}\n")
        fh.write(f"{username} soft nofile {write_value}\n")
