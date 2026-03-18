#!/usr/bin/env python3
"""CMS daemon management."""

import os
import sys
import signal
import time

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger
from utils import exec_popen

LOGGER = get_logger()

LOOP_TIME = 1


class CmsDaemon:
    """CMS daemon enable/disable management."""

    def __init__(self):
        cfg = get_config()
        self.cms_enable_flag = cfg.paths.cms_enable_flag
        self.daemon_log = cfg.paths.deploy_daemon_log
        self.dss_home = os.path.join(cfg.paths.ograc_home, "dss")

    def _log(self, msg):
        """Write to daemon log."""
        LOGGER.info(msg)
        try:
            log_dir = os.path.dirname(self.daemon_log)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, mode=0o750, exist_ok=True)
            from datetime import datetime
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.daemon_log, "a") as f:
                f.write(f"[{ts}] {msg}\n")
        except OSError:
            pass


    @staticmethod
    def _is_process_running(name):
        """Check if process exists."""
        ret, stdout, _ = exec_popen(f"pgrep -u $(id -u) -f '{name}' 2>/dev/null || true")
        return bool(stdout.strip())

    @staticmethod
    def _is_exact_process_running(name):
        """Exact match process name."""
        ret, stdout, _ = exec_popen(f"pgrep -u $(id -u) -x '{name}' 2>/dev/null || true")
        return bool(stdout.strip())

    def _clean_residual_dss(self):
        """Clean residual dssserver processes."""
        if self._is_process_running("cms server -start"):
            return
        if not self._is_process_running(f"dssserver -D {self.dss_home}"):
            return

        self._log("[cms reg] stop residual dssserver processes")
        exec_popen("dsscmd stopdss 2>/dev/null")
        time.sleep(3)

        if self._is_process_running(f"dssserver -D {self.dss_home}"):
            ret, stdout, _ = exec_popen(f"pgrep -u $(id -u) -f 'dssserver -D {self.dss_home}'")
            pids = stdout.strip()
            if pids:
                self._log(
                    f"[cms reg] Stop dssserver failed, force killing: {pids}"
                )
                for pid in pids.split():
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except (ProcessLookupError, ValueError):
                        pass
        self._log("[cms reg] dssserver cleanup done")


    def enable(self):
        """Enable CMS daemon."""
        self._log("[cms reg] begin to set cms daemon enable")
        if not os.path.exists(self.cms_enable_flag):
            self._clean_residual_dss()
            try:
                flag_dir = os.path.dirname(self.cms_enable_flag)
                if flag_dir and not os.path.exists(flag_dir):
                    os.makedirs(flag_dir, mode=0o750, exist_ok=True)
                with open(self.cms_enable_flag, "w"):
                    pass
                os.chmod(self.cms_enable_flag, 0o400)
            except OSError as e:
                self._log(f"Error: [cms reg] set daemon enable failed: {e}")
                return False
        time.sleep(LOOP_TIME)
        print("RES_SUCCESS")
        return True

    def disable(self):
        """Disable CMS daemon."""
        self._log("[cms reg] begin to set cms daemon disable")
        if os.path.exists(self.cms_enable_flag):
            try:
                os.remove(self.cms_enable_flag)
            except OSError as e:
                self._log(f"Error: [cms reg] set daemon disable failed: {e}")
                return False
        time.sleep(LOOP_TIME)
        print("RES_SUCCESS")
        return True



def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("enable", "disable"):
        print("Usage: cms_daemon.py <enable|disable>")
        sys.exit(1)

    action = sys.argv[1]
    daemon = CmsDaemon()

    try:
        if action == "enable":
            ok = daemon.enable()
        else:
            ok = daemon.disable()
        sys.exit(0 if ok else 1)
    except Exception as e:
        LOGGER.error(f"cms_daemon failed: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
