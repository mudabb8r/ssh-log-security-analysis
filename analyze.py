"""Analyze an SSH auth log: parse it, run detection rules, and write a report.

Usage:
    python analyze.py                          # uses data/OpenSSH_2k.log
    python analyze.py path/to/auth.log --year 2026
Outputs:
    output/events.csv   every parsed line
    output/alerts.csv   alerts from the detection rules
    output/report.md    short incident summary
    images/*.png        charts
"""
import argparse
from pathlib import Path

import matplotlib.pyplot as plt

from src.detections import FAILED, run_all
from src.parser import parse_file

ROOT = Path(__file__).parent


def make_charts(events, out):
    failed = events[events["event"].isin(FAILED)]
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5))
    failed.set_index("timestamp").resample("15min")["event"].count().plot(ax=axes[0], color="#c0504d")
    axes[0].set(title="Failed logins per 15 minutes", xlabel="", ylabel="failed logins")
    failed["ip"].value_counts().head(10)[::-1].plot.barh(ax=axes[1], color="#2a7ab9")
    axes[1].set(title="Top 10 attacking IPs (failed logins)", xlabel="failed logins", ylabel="")
    failed["user"].value_counts().head(10)[::-1].plot.barh(ax=axes[2], color="#7f7f7f")
    axes[2].set(title="Top 10 usernames tried", xlabel="attempts", ylabel="")
    plt.tight_layout(); fig.savefig(out / "attack_overview.png", dpi=110, bbox_inches="tight"); plt.close(fig)


def write_report(events, alerts, path, log_name):
    failed = events[events["event"].isin(FAILED)]
    root_share = (failed["user"] == "root").mean()
    lines = [
        f"# SSH Log Analysis Report — `{log_name}`", "",
        f"**Period:** {events['timestamp'].min():%b %d %H:%M} to {events['timestamp'].max():%b %d %H:%M} "
        f"· **Lines parsed:** {len(events):,} · **Unique source IPs:** {events['ip'].nunique()}", "",
        "## Summary",
        f"- **{len(failed):,} failed logins** from **{failed['ip'].nunique()} IPs**; {root_share:.0%} targeted `root`.",
        f"- **{(events['event'] == 'invalid_user').sum()}** attempts used usernames that do not exist.",
        f"- **{(events['event'] == 'accepted_login').sum()}** successful login(s).",
        f"- **{len(alerts)} alerts**: " + ", ".join(f"{n} {s}" for s, n in alerts['severity'].value_counts().items()), "",
        "## Alerts", "", "| Severity | Rule | Source IP | Events | Detail | MITRE ATT&CK |", "|---|---|---|---|---|---|",
    ]
    for _, a in alerts.iterrows():
        lines.append(f"| {a.severity} | {a.rule} | {a.source_ip} | {a.event_count} | {a.detail} | {a.mitre_attack} |")
    lines += ["", "## Recommended actions",
              "1. Block the HIGH-severity IPs at the firewall (or with fail2ban) and review any CRITICAL login immediately.",
              "2. Disable password login for `root` (`PermitRootLogin no`) and prefer SSH keys (`PasswordAuthentication no`).",
              "3. Rate-limit SSH (fail2ban, `MaxAuthTries 3`) and consider moving it behind a VPN.",
              "4. Forward these logs to a SIEM so the same rules run continuously."]
    path.write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", nargs="?", default=ROOT / "data" / "OpenSSH_2k.log")
    ap.add_argument("--year", type=int, default=2016, help="syslog lines have no year; set it here")
    args = ap.parse_args()
    out_dir, img_dir = ROOT / "output", ROOT / "images"
    out_dir.mkdir(exist_ok=True); img_dir.mkdir(exist_ok=True)

    events = parse_file(args.log, args.year)
    alerts = run_all(events)
    events.to_csv(out_dir / "events.csv", index=False)
    alerts.to_csv(out_dir / "alerts.csv", index=False)
    make_charts(events, img_dir)
    write_report(events, alerts, out_dir / "report.md", Path(args.log).name)

    print(f"Parsed {len(events):,} lines; event types:\n{events['event'].value_counts().to_string()}\n")
    print(alerts[["severity", "rule", "source_ip", "event_count"]].to_string(index=False))


if __name__ == "__main__":
    main()
