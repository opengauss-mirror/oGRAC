#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly (no venv, no pip install needed):
#      OGDB_DATA=/path/to/data uv run ogsql_tty_history.py /path/to/ogsql
# 3. Or make executable and run:
#      chmod +x ogsql_tty_history.py && ./ogsql_tty_history.py /path/to/ogsql
# ──────────────────

from __future__ import annotations

import errno
import os
import pwd
import re
import select
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import Final

PROMPT: Final = b"SQL> "
UP: Final = "\x1b[A"
CLEAR: Final = "\x15"


class UsageError(Exception):
    pass


class TtySession:
    """A bounded, event-driven ogsql PTY session."""

    def __init__(self, ogsql: str, home: Path) -> None:
        self.ogsql = ogsql
        self.home = home
        self.master = -1
        self.proc: subprocess.Popen[bytes] | None = None
        self.transcript = bytearray()

    def __enter__(self) -> TtySession:
        master, slave = os.openpty()
        env = os.environ.copy()
        env["HOME"] = str(self.home)
        env["OGSQL_SSL_QUIET"] = "TRUE"
        self.master = master
        test_user = env.get("OGSQL_TEST_USER")
        if test_user:
            command = (
                f"HOME={shlex.quote(str(self.home))} OGSQL_SSL_QUIET=TRUE "
                f"OGDB_DATA={shlex.quote(env['OGDB_DATA'])} {shlex.quote(self.ogsql)} / as sysdba -q"
            )
            argv = ["su", "-", test_user, "-c", command]
        else:
            argv = [self.ogsql, "/", "as", "sysdba", "-q"]
        self.proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave)
        self.expect(PROMPT)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.proc is not None and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=2)
        if self.master >= 0:
            os.close(self.master)

    def expect(self, marker: bytes, timeout: float = 8) -> bytes:
        """Wait for a marker only when the PTY becomes readable."""
        deadline = time.monotonic() + timeout
        data = bytearray()
        while marker not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"missing {marker!r}; output={bytes(data)!r}")
            readable, _, _ = select.select([self.master], [], [], remaining)
            if not readable:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                raise EOFError(bytes(self.transcript)) from error
            if not chunk:
                raise EOFError(bytes(data))
            data.extend(chunk)
            self.transcript.extend(chunk)
        return bytes(data)

    def send(self, text: str) -> None:
        os.write(self.master, text.encode())

    def line(self, text: str, prompt: bytes = PROMPT) -> bytes:
        self.send(text + "\r")
        return self.expect(prompt)

    def finish(self) -> None:
        assert self.proc is not None
        self.send(CLEAR + "exit\r")
        self.proc.wait(timeout=8)


def enable_history(session: TtySession) -> None:
    session.line("SET HISTORY ON")


def recall(session: TtySession, expected: bytes) -> bytes:
    session.send(CLEAR + UP)
    return session.expect(expected)


def history_records(home: Path) -> list[bytes]:
    path = home / ".ogsql_history_SYS"
    data = path.read_bytes()
    assert data[:8] == b"OGSQLH01"
    records: list[bytes] = []
    offset = 8
    while offset < len(data):
        nbytes, _ = struct.unpack_from("=II", data, offset)
        offset += 8
        records.append(data[offset:offset + nbytes])
        offset += nbytes
    assert offset == len(data)
    return records


def test_multiline_history(ogsql: str, home: Path) -> None:
    # Given an open comment; When SQL follows a bare close; Then one history slot is recalled.
    with TtySession(ogsql, home) as session:
        enable_history(session)
        session.line("/*", b"  2 ")
        session.line(" * c", b"  3 ")
        session.line(" */", b"  4 ")
        session.line("select 1", b"  5 ")
        session.line("from sys_dummy;")
        output = recall(session, b"from sys_dummy;")
        assert b"/*" in output and b"select 1" in output and b"from sys_dummy;" in output
        assert b"SET HISTORY ON" in recall(session, b"SET HISTORY ON")
        session.finish()


def test_line_comment(ogsql: str, home: Path) -> None:
    # Given a closed block; When a line comment follows; Then it stays with the subsequent SQL.
    with TtySession(ogsql, home) as session:
        enable_history(session)
        session.line("/*", b"  2 ")
        session.line(" */", b"  3 ")
        session.line("-- note", b"  4 ")
        session.line("select 1", b"  5 ")
        session.line("from sys_dummy;")
        output = recall(session, b"from sys_dummy;")
        assert b"-- note" in output and b"select 1" in output
        assert b"SET HISTORY ON" in recall(session, b"SET HISTORY ON")
        session.finish()


def test_same_line_comment(ogsql: str, home: Path) -> None:
    # Given a closed block; When a same-line comment follows; Then the comment draft is committed.
    with TtySession(ogsql, home) as session:
        enable_history(session)
        session.line("/*", b"  2 ")
        session.line(" */", b"  3 ")
        session.line("/* another */")
        session.line("select 1 from sys_dummy;")
        assert b"select 1 from sys_dummy;" in recall(session, b"select 1 from sys_dummy;")
        output = recall(session, b"/* another */")
        assert b"/*" in output and b"select 1" not in output
        assert b"SET HISTORY ON" in recall(session, b"SET HISTORY ON")
        session.finish()


def test_single_command(ogsql: str, home: Path) -> None:
    # Given a closed comment; When SET executes; Then command and comment use separate slots.
    with TtySession(ogsql, home) as session:
        enable_history(session)
        session.line("/*", b"  2 ")
        session.line(" */", b"  3 ")
        output = session.line("SET TIMING ON")
        assert b"ON" in output
        session.line("select 8 from sys_dummy;")
        assert b"select 8 from sys_dummy;" in recall(session, b"select 8 from sys_dummy;")
        assert b"SET TIMING ON" in recall(session, b"SET TIMING ON")
        output = recall(session, b"*/")
        assert b"/*" in output and b"SET TIMING ON" not in output
        session.finish()


def test_rollback(ogsql: str, home: Path) -> None:
    # Given the first SQL line; When Backspace rolls it back; Then COMMENT_END and line 4 return.
    with TtySession(ogsql, home) as session:
        enable_history(session)
        session.line("/*", b"  2 ")
        session.line(" */", b"  3 ")
        session.line("select 1", b"  4 ")
        session.send("\x7f")
        output = session.expect(b"select 1")
        assert b"  3 " in output
        session.send("\r")
        session.expect(b"  4 ")
        session.line("from sys_dummy;")
        session.finish()


def test_exit_saves_comment(ogsql: str, home: Path) -> None:
    # Given a closed comment; When exit arrives; Then the comment is saved before the command exits.
    with TtySession(ogsql, home) as session:
        enable_history(session)
        session.line("/*", b"  2 ")
        session.line(" * saved", b"  3 ")
        session.line(" */", b"  4 ")
        session.finish()
    assert any(b"saved" in record for record in history_records(home))


def test_multiline_string(ogsql: str, home: Path) -> None:
    # Given a string with an empty line; When SQL executes; Then its original length is preserved.
    with TtySession(ogsql, home) as session:
        enable_history(session)
        session.line("select length('a", b"  2 ")
        session.line("", b"  3 ")
        output = session.line("b') from sys_dummy;")
        assert re.search(rb"\r?\n4\s+\r?\n", output) is not None
        session.finish()


def test_overflow_keeps_sql(ogsql: str, home: Path) -> None:
    # Given a near-limit comment; When SQL crosses the limit; Then both slots remain recallable.
    with TtySession(ogsql, home) as session:
        enable_history(session)
        session.line("/*", b"  2 ")
        for index in range(40):
            session.line(" * " + "x" * 96, f"{index + 3:3d} ".encode())
        session.line(" */", b" 43 ")
        sql = "select '" + "y" * 180 + "' from sys_dummy;"
        session.line(sql)
        session.finish()
    records = history_records(home)
    assert len(records) == 3
    assert records[-1] == sql.encode()
    assert records[-2].startswith(b"/*") and b"xxxx" in records[-2]


def main() -> int:
    if len(sys.argv) != 2:
        raise UsageError("usage: ogsql_tty_history.py /path/to/ogsql")
    if not os.environ.get("OGDB_DATA"):
        raise UsageError("OGDB_DATA must name the local database directory")
    tests: tuple[tuple[str, Callable[[str, Path], None]], ...] = (
        ("multiline_history", test_multiline_history),
        ("line_comment", test_line_comment),
        ("same_line_comment", test_same_line_comment),
        ("single_command", test_single_command),
        ("rollback", test_rollback),
        ("exit_saves_comment", test_exit_saves_comment),
        ("multiline_string", test_multiline_string),
        ("overflow_keeps_sql", test_overflow_keeps_sql),
    )
    failures = 0
    test_user = os.environ.get("OGSQL_TEST_USER")
    for name, test in tests:
        with tempfile.TemporaryDirectory(prefix=f"ogsql-{name}-") as directory:
            if test_user:
                account = pwd.getpwnam(test_user)
                os.chown(directory, account.pw_uid, account.pw_gid)
            try:
                test(sys.argv[1], Path(directory))
            except (AssertionError, TimeoutError, EOFError) as error:
                failures += 1
                print(f"FAIL {name}: {error}")
            else:
                print(f"PASS {name}")
    print(f"{len(tests) - failures} passed, {failures} failed")
    return int(failures > 0)


if __name__ == "__main__":
    raise SystemExit(main())
