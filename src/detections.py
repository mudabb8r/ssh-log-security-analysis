"""Detection rules that turn parsed SSH events into security alerts.

Each rule maps to a MITRE ATT&CK technique so an analyst knows what the alert means.
Thresholds are parameters so they can be tuned for a noisier or quieter server.
"""
from __future__ import annotations

import pandas as pd

FAILED = {"failed_password", "failed_invalid_user"}


def _alert(rule, severity, ip, first, last, count, detail, mitre):
    return {"rule": rule, "severity": severity, "source_ip": ip, "first_seen": first, "last_seen": last,
            "event_count": count, "detail": detail, "mitre_attack": mitre}


def brute_force(events: pd.DataFrame, threshold: int = 5, window: str = "10min") -> list[dict]:
    """Rule 1: many failed logins from one IP inside a short time window (password guessing)."""
    alerts = []
    failed = events[events["event"].isin(FAILED)].set_index("timestamp").sort_index()
    for ip, grp in failed.groupby("ip"):
        counts = grp["event"].rolling(window).count()          # failures in the trailing window
        if counts.max() >= threshold:
            users = grp["user"].value_counts().head(3).index.tolist()
            alerts.append(_alert("Brute-force login", "HIGH", ip, grp.index.min(), grp.index.max(), len(grp),
                                 f"peak {int(counts.max())} failures in {window}; top users tried: {', '.join(users)}",
                                 "T1110.001 Password Guessing"))
    return alerts


def user_enumeration(events: pd.DataFrame, threshold: int = 3) -> list[dict]:
    """Rule 2: one IP trying several usernames that do not exist on the server."""
    alerts = []
    inv = events[events["event"].isin({"invalid_user", "failed_invalid_user"})]
    for ip, grp in inv.groupby("ip"):
        names = grp["user"].dropna().unique()
        if len(names) >= threshold:
            alerts.append(_alert("Username enumeration", "MEDIUM", ip, grp["timestamp"].min(), grp["timestamp"].max(),
                                 len(grp), f"{len(names)} invalid usernames, e.g. {', '.join(map(str, names[:5]))}",
                                 "T1110 Brute Force (username guessing)"))
    return alerts


def success_after_failures(events: pd.DataFrame, min_failures: int = 3) -> list[dict]:
    """Rule 3: a successful login from an IP that failed several times first (possible compromise)."""
    alerts = []
    for _, ok in events[events["event"] == "accepted_login"].iterrows():
        before = events[(events["ip"] == ok["ip"]) & (events["timestamp"] <= ok["timestamp"]) & events["event"].isin(FAILED)]
        severity = "CRITICAL" if len(before) >= min_failures else "INFO"
        detail = (f"login as '{ok['user']}' after {len(before)} failures from the same IP" if len(before)
                  else f"login as '{ok['user']}' with no earlier failures (review if user/IP is unexpected)")
        alerts.append(_alert("Successful login" + (" after failures" if len(before) >= min_failures else ""), severity,
                             ok["ip"], ok["timestamp"], ok["timestamp"], 1 + len(before), detail, "T1078 Valid Accounts"))
    return alerts


def reverse_dns_mismatch(events: pd.DataFrame) -> list[dict]:
    """Rule 4: hostname does not resolve back to the IP. sshd flags it as POSSIBLE BREAK-IN ATTEMPT."""
    grp = events[events["event"] == "break_in_attempt"].groupby("ip")["timestamp"].agg(["min", "max", "count"])
    return [_alert("Reverse DNS mismatch", "LOW", ip, r["min"], r["max"], int(r["count"]),
                   "hostname does not map back to this IP (often spoofed or misconfigured attack hosts)", "T1036 Masquerading")
            for ip, r in grp.iterrows()]


def run_all(events: pd.DataFrame) -> pd.DataFrame:
    """Run every rule and return one table of alerts sorted by severity."""
    alerts = brute_force(events) + user_enumeration(events) + success_after_failures(events) + reverse_dns_mismatch(events)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    df = pd.DataFrame(alerts)
    if df.empty:
        return df
    return df.sort_values(["severity", "event_count"], key=lambda s: s.map(order) if s.name == "severity" else -s).reset_index(drop=True)
