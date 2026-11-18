# SSH Log Analysis Report — `OpenSSH_2k.log`

**Period:** Dec 10 06:55 to Dec 10 11:04 · **Lines parsed:** 2,000 · **Unique source IPs:** 32

## Summary
- **524 failed logins** from **24 IPs**; 71% targeted `root`.
- **113** attempts used usernames that do not exist.
- **1** successful login(s).
- **20 alerts**: 9 HIGH, 6 MEDIUM, 4 LOW, 1 INFO

## Alerts

| Severity | Rule | Source IP | Events | Detail | MITRE ATT&CK |
|---|---|---|---|---|---|
| HIGH | Brute-force login | 183.62.140.253 | 286 | peak 279 failures in 10min; top users tried: root, oracle, zhangyan | T1110.001 Password Guessing |
| HIGH | Brute-force login | 187.141.143.180 | 80 | peak 80 failures in 10min; top users tried: root, oracle, git | T1110.001 Password Guessing |
| HIGH | Brute-force login | 103.99.0.122 | 46 | peak 30 failures in 10min; top users tried: admin, root, user | T1110.001 Password Guessing |
| HIGH | Brute-force login | 112.95.230.3 | 26 | peak 26 failures in 10min; top users tried: root, pgadmin, utsims | T1110.001 Password Guessing |
| HIGH | Brute-force login | 5.188.10.180 | 20 | peak 20 failures in 10min; top users tried: admin, 0, default | T1110.001 Password Guessing |
| HIGH | Brute-force login | 185.190.58.151 | 18 | peak 18 failures in 10min; top users tried: admin, 0, 123 | T1110.001 Password Guessing |
| HIGH | Brute-force login | 123.235.32.19 | 7 | peak 7 failures in 10min; top users tried: root | T1110.001 Password Guessing |
| HIGH | Brute-force login | 119.4.203.64 | 6 | peak 6 failures in 10min; top users tried: admin | T1110.001 Password Guessing |
| HIGH | Brute-force login | 60.2.12.12 | 5 | peak 5 failures in 10min; top users tried: root | T1110.001 Password Guessing |
| MEDIUM | Username enumeration | 103.99.0.122 | 70 | 15 invalid usernames, e.g. admin, support, user, 1234, anonymous | T1110 Brute Force (username guessing) |
| MEDIUM | Username enumeration | 187.141.143.180 | 58 | 24 invalid usernames, e.g. eoor, butter, redhat, oracle, postgres | T1110 Brute Force (username guessing) |
| MEDIUM | Username enumeration | 5.188.10.180 | 28 | 6 invalid usernames, e.g. 0101, 0, 1234, admin, default | T1110 Brute Force (username guessing) |
| MEDIUM | Username enumeration | 185.190.58.151 | 25 | 4 invalid usernames, e.g. 0, 123, admin, api | T1110 Brute Force (username guessing) |
| MEDIUM | Username enumeration | 183.62.140.253 | 18 | 8 invalid usernames, e.g. zhangyan, dff, oracle, test, ubuntu | T1110 Brute Force (username guessing) |
| MEDIUM | Username enumeration | 52.80.34.196 | 10 | 3 invalid usernames, e.g. test9, test, matlab | T1110 Brute Force (username guessing) |
| LOW | Reverse DNS mismatch | 187.141.143.180 | 80 | hostname does not map back to this IP (often spoofed or misconfigured attack hosts) | T1036 Masquerading |
| LOW | Reverse DNS mismatch | 173.234.31.186 | 2 | hostname does not map back to this IP (often spoofed or misconfigured attack hosts) | T1036 Masquerading |
| LOW | Reverse DNS mismatch | 195.154.37.122 | 2 | hostname does not map back to this IP (often spoofed or misconfigured attack hosts) | T1036 Masquerading |
| LOW | Reverse DNS mismatch | 191.210.223.172 | 1 | hostname does not map back to this IP (often spoofed or misconfigured attack hosts) | T1036 Masquerading |
| INFO | Successful login | 119.137.62.142 | 1 | login as 'fztu' with no earlier failures (review if user/IP is unexpected) | T1078 Valid Accounts |

## Recommended actions
1. Block the HIGH-severity IPs at the firewall (or with fail2ban) and review any CRITICAL login immediately.
2. Disable password login for `root` (`PermitRootLogin no`) and prefer SSH keys (`PasswordAuthentication no`).
3. Rate-limit SSH (fail2ban, `MaxAuthTries 3`) and consider moving it behind a VPN.
4. Forward these logs to a SIEM so the same rules run continuously.
