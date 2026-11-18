"""Parse OpenSSH (sshd) log lines into structured events.

Each line looks like:
    Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186

parse_line() turns it into a dict such as:
    {"timestamp": datetime(2016, 12, 10, 6, 55, 46), "host": "LabSZ", "pid": 24200,
     "event": "invalid_user", "user": "webmaster", "ip": "173.234.31.186", "raw": "..."}
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import pandas as pd

# Syslog header: month, day, time, host, process[pid]: message
HEADER = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>[\d:]{8}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<msg>.*)$")

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
# (event name, regex for the message part). Order matters: first match wins.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("accepted_login",     re.compile(rf"Accepted (?:password|publickey) for (?P<user>\S+) from {IP}")),
    ("failed_invalid_user", re.compile(rf"Failed (?:password|none) for invalid user (?P<user>.*?) from {IP}")),
    ("failed_password",    re.compile(rf"Failed password for (?P<user>\S+) from {IP}")),
    ("invalid_user",       re.compile(rf"Invalid user (?P<user>.*?) from {IP}")),
    ("break_in_attempt",   re.compile(rf"reverse mapping checking getaddrinfo for (?P<hostname>\S+) \[{IP}\] failed - POSSIBLE BREAK-IN ATTEMPT")),
    ("too_many_failures",  re.compile(r"Disconnecting: Too many authentication failures for (?P<user>\S+)")),
    ("auth_failure_pam",   re.compile(r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?")),
    ("disconnect",         re.compile(rf"Received disconnect from {IP}")),
    ("connection_closed",  re.compile(rf"Connection closed by {IP}")),
    ("no_identification",  re.compile(rf"Did not receive identification string from {IP}")),
    ("session_opened",     re.compile(r"session opened for user (?P<user>\S+)")),
]


def parse_line(line: str, year: int = 2016) -> dict | None:
    """Parse one log line. Returns None if the line is not an sshd line."""
    m = HEADER.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    event = {"timestamp": ts, "host": m["host"], "pid": int(m["pid"]), "event": "other",
             "user": None, "ip": None, "raw": m["msg"]}
    for name, pattern in PATTERNS:
        hit = pattern.search(m["msg"])
        if hit:
            event["event"] = name
            groups = hit.groupdict()
            event["user"] = (groups.get("user") or "").strip() or None
            event["ip"] = groups.get("ip")
            break
    return event


def parse_file(path: str | Path, year: int = 2016) -> pd.DataFrame:
    """Parse a whole log file into a DataFrame, one row per line."""
    with open(path, encoding="utf-8", errors="replace") as f:
        rows = [e for e in (parse_line(line, year) for line in f) if e]
    return pd.DataFrame(rows)
