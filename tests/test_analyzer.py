"""Unit tests: run with `pytest` from the repository root."""
import pandas as pd

from src.detections import brute_force, success_after_failures, user_enumeration
from src.parser import parse_line


def test_parse_failed_password():
    e = parse_line("Dec 10 07:07:38 LabSZ sshd[24206]: Failed password for root from 112.95.230.3 port 47956 ssh2")
    assert e["event"] == "failed_password" and e["user"] == "root" and e["ip"] == "112.95.230.3"


def test_parse_invalid_user():
    e = parse_line("Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186")
    assert e["event"] == "invalid_user" and e["user"] == "webmaster"


def test_parse_accepted():
    e = parse_line("Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2")
    assert e["event"] == "accepted_login" and e["user"] == "fztu"


def test_non_sshd_line_is_ignored():
    assert parse_line("this is not a log line") is None


def _events(rows):
    return pd.DataFrame(rows, columns=["timestamp", "event", "user", "ip"]).assign(timestamp=lambda d: pd.to_datetime(d["timestamp"]))


def test_brute_force_triggers_at_threshold():
    rows = [(f"2016-12-10 10:00:0{i}", "failed_password", "root", "1.2.3.4") for i in range(5)]
    assert len(brute_force(_events(rows), threshold=5)) == 1
    assert brute_force(_events(rows[:4]), threshold=5) == []


def test_slow_failures_do_not_trigger():
    rows = [(f"2016-12-10 1{i}:00:00", "failed_password", "root", "1.2.3.4") for i in range(5)]  # one per hour
    assert brute_force(_events(rows), threshold=5, window="10min") == []


def test_user_enumeration():
    rows = [("2016-12-10 10:00:00", "invalid_user", u, "5.6.7.8") for u in ["admin", "test", "oracle"]]
    assert user_enumeration(_events(rows), threshold=3)[0]["source_ip"] == "5.6.7.8"


def test_success_after_failures_is_critical():
    rows = [(f"2016-12-10 10:00:0{i}", "failed_password", "bob", "9.9.9.9") for i in range(3)]
    rows.append(("2016-12-10 10:01:00", "accepted_login", "bob", "9.9.9.9"))
    assert success_after_failures(_events(rows))[0]["severity"] == "CRITICAL"
