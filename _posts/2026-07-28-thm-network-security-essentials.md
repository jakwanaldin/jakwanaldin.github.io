---
title: "TryHackMe — Network Security Essentials"
date: 2026-07-28 09:00:00 +0600
categories: [TryHackMe, Network Security Monitoring]
tags: [network-security, firewall-logs, ids-ips, vpn-logs, incident-investigation, splunk, c2-beaconing, data-exfiltration]
---

## Overview
![Network Security Essentials room banner](/assets/img/thm-network-security-essentials/network-essential.png)

**Room:** [Network Security Essentials](https://tryhackme.com/room/networksecurityessentials)

**Path:** SOC Level 1 → Network Security Monitoring

**Objective:** Build a defensive understanding of enterprise network structure, then apply it to real perimeter log analysis — firewall, WAF/IDS, and VPN logs — culminating in a full incident investigation that traces an attacker from initial reconnaissance through VPN brute-force, lateral movement, C2 beaconing, and data exfiltration.

**Tools used:** Linux command line (`grep`, `cut`, `sort`, `uniq`), Splunk (`index="network_logs"`)

**Log files provided:** `~/Desktop/Perimeter_logs/task6/` (scenario logs: `firewall.log`, WAF/IDS logs, `vpn_auth.log`), `~/Desktop/Perimeter_logs/challenge/` (`firewall.log`, `ids_alerts.log`, `vpn_auth.log`), pre-ingested into Splunk at `10.48.152.53:8000`

This room splits cleanly into two halves: a conceptual foundation (network components, visibility, the perimeter) and a hands-on half where that foundation gets applied to an actual month-long intrusion buried in three log files.

---

## Part 1 — Network Components: The Building Blocks

A quick reference table of what lives on an enterprise network and why each asset matters from a defender's seat:

| Component | Role | Why Attackers Target It |
|---|---|---|
| User Workstations | Daily employee endpoints | Most common entry point — phishing, malicious downloads; often under-monitored |
| File & Database Servers | Store business-critical data | Ransomware and exfiltration targets — highest-value data |
| Application Servers (Web/Email/VPN) | Externally-facing services | Constantly scanned for vulnerabilities; a foothold into the internal network |
| Active Directory / Auth Servers | Identity backbone — users, groups, access rights | Target for privilege escalation, persistence, lateral movement |
| Routers & Switches | Connect networks and devices | If compromised: MITM, traffic rerouting, hidden backdoor channels |
| Firewalls / Perimeter Devices | Gatekeeper between trusted and untrusted networks | The first log source for scans, brute-force, and exploitation attempts |

**Key defensive point:** endpoint logs show *what* malware did locally, but network logs are often the *first* signal — a C2 connection usually shows up on the wire before an EDR agent flags the process behind it.

---

## Part 2 — Network Visibility: Host-Centric vs. Network-Centric Logs

Two log categories, and an investigation needs both to build a complete timeline:

| | Host-Centric Logs | Network-Centric Logs |
|---|---|---|
| **Sources** | OS logs (Windows Event Log, syslog), application logs, AV/EDR/HIDS | Firewalls, IDS/IPS, routers/switches (flow data), web proxies, VPN |
| **Tells you** | What happened *inside* a machine — processes, file access, logons | What happened *between* machines — who talked to whom, when, how |
| **Best for** | Forensic detail, process/execution tracking, user activity, malware impact | Early detection, C2 identification, lateral movement, exfiltration |

The room's framing: *"Host-centric logs tell you what happened inside a room, while network-centric logs tell you who entered and left the building."* Firewalls flag unauthorized connections first; IDS/IPS catches signature/anomaly-based attacks in real time; flow data from routers gives a high-level traffic overview; proxies and VPN logs cover web-based threats and remote access respectively.

---

## Part 3 — The Network Perimeter

The perimeter is the boundary between the trusted internal network and the untrusted Internet — every packet in or out crosses it, making it the first and most consistently probed line of defense.

**Common perimeter components:**
- **Firewalls** — filter traffic between internal/external networks
- **Routers/Gateways** — route traffic, enforce access rules
- **DMZ** — buffer segment hosting public-facing services (web, mail, VPN)
- **VPN Gateways** — secure remote-access entry points

**A weak or misconfigured perimeter lets attackers:** exploit exposed services (RDP/MySQL/SMB), scan and map the network, brute-force login services, and exfiltrate data. As a security analyst, monitoring the perimeter means reviewing firewall allow/block decisions, spotting scanning or brute-force patterns, flagging unusual outbound traffic (beaconing/exfil), and knowing what should — and shouldn't — be exposed at all.

---

## Part 4 — Monitoring the Perimeter: Three Scenarios

Practical log-reading walkthroughs, each demonstrating one attack pattern:

### Scenario 1 — Port Scanning (Firewall Log)

Same external IP hitting multiple ports on one internal host in rapid succession — the textbook port-scan signature:
```
2025-09-22 08:30:05 BLOCK TCP 203.0.113.10:50001 -> 10.0.0.20:21
2025-09-22 08:30:06 BLOCK TCP 203.0.113.10:50002 -> 10.0.0.20:22
2025-09-22 08:30:08 BLOCK TCP 203.0.113.10:50003 -> 10.0.0.20:23
2025-09-22 08:30:09 BLOCK TCP 203.0.113.10:50004 -> 10.0.0.20:25
```

Ran:
```bash
cat firewall_logs.txt
cat firewall_logs.txt | grep "BLOCK"
```

![IP performing the port scan](/assets/img/thm-network-security-essentials/ip-performing-port-scan.png)

**Q: Which IP address is performing the port scan?**
**A: `203.0.113.10`** — filtering to `BLOCK` entries and reading the source column shows one IP hitting five-plus different destination ports on the same internal host within seconds.

### Scenario 2 — SQL Injection / Web Attack (WAF Log)

WAF logs go a step further than a firewall — they name the *attack type*, not just allow/block:
```
action=BLOCK request="GET /search.php?q=<script>alert('XSS')</script>" attack_type="XSS"
action=BLOCK request="GET /../../../../etc/passwd" attack_type="Directory Traversal"
```

Ran:
```bash
cat waf_logs.txt
cat waf_logs.txt | grep "BLOCK"
```

![IP responsible for all blocked web attacks](/assets/img/thm-network-security-essentials/ip-responsible-for-all-blocked-web-attacks.png)

**Q: In the WAF Logs, which single source IP is responsible for all the blocked web attacks?**
**A: `198.51.100.12`** — filtering to `action=BLOCK` and reading the `src_ip` field across every blocked entry (SQLi, XSS, directory traversal) converges on one IP.

### Scenario 3 — VPN Brute-Force (VPN Gateway Log)

Volume is the tell here — a flood of `FAILED_AUTH` entries against common usernames (`admin`, `guest`, `user`), followed by scattered legitimate `SUCCESS_AUTH` from real employees. Ran:
```bash
cat vpn_logs.txt
cat vpn_logs.txt | grep -c "FAILED_AUTH"
```

![Total failed brute-force attempt count](/assets/img/thm-network-security-essentials/number-of-brute-force-attack.png)

**Q: In the VPN logs, how many brute-force attempts failed?**
**A: `90`** — a straight count of every `FAILED_AUTH` line in the log.

To isolate *which* IP was responsible rather than just the total, grouped the failures by source:
```bash
cat vpn_logs.txt | grep "FAILED_AUTH" | cut -d " " -f5 | cut -d ":" -f1 | uniq
```

![Suspicious IP behind the VPN brute-force](/assets/img/thm-network-security-essentials/brute-force-attack-ip.png)

**Q: Which suspicious IP address was found attempting the brute-force attack against the VPN gateway?**
**A: `45.137.22.13`**

**Pattern cheat-sheet from this task (useful beyond this room):**
- One source → many destinations = **scanning**
- One source → one destination, repeated = **brute-forcing**
- Perfectly regular intervals = **malware beaconing**
- An IDS/WAF alert explaining *why* > a bare firewall block

---

## Part 5 — Incident Investigation: Initech Corp

**Scenario:** Initech Corp (mid-sized financial services) deployed a new firewall + IDS. A month of perimeter logs needs review to determine what technique(s) an adversary used and whether the perimeter was actually breached.

**Logs:** `Perimeter_logs/challenge/firewall.log`, `ids_alerts.log`, `vpn_auth.log`

**Asset reference:**

| IP | Hostname | Role | Criticality |
|---|---|---|---|
| 10.0.0.20 | FINANCE-SRV1 | File/Finance Server (SMB) | High |
| 10.0.0.50 | VPN-GW | VPN Gateway | Critical |
| 10.0.0.51 | APP-WEB-01 | Internal Web/App | High |
| 10.0.0.60 | WORKSTATION-60 | Employee Workstation | Medium |
| 10.8.0.23 | VPN-CLIENT-ATTK | VPN Assigned Client (Ephemeral) | Critical |
| 10.0.1.10 | DMZ-WEB | DMZ Web Server | Medium |

### Stage 1 — Reconnaissance

Started with blocked firewall traffic to find who's probing the perimeter:
```bash
cat firewall.log | grep "BLOCK"
cat firewall.log | grep "BLOCK" | cut -d " " -f5 | cut -d ":" -f1 | sort -nr | uniq -c
```

![External IP performing the most reconnaissance](/assets/img/thm-network-security-essentials/most-recon.png)

**Q: Examine the firewall logs. What external IP performed the most reconnaissance?**
**A: `203.0.113.45`** — the source-IP column, grouped and counted, shows one IP far ahead of the rest of the block-count.

To find *what* it was scanning, ran the same pipeline against the destination field instead:
```bash
cat firewall.log | grep "BLOCK" | cut -d " " -f7 | cut -d ":" -f1 | sort | uniq -c
```

![Internal host targeted by scans](/assets/img/thm-network-security-essentials/internal-host.png)

**Q: In the firewall log, which internal host was targeted by scans?**
**A: `10.0.0.20`**

### Stage 2 — VPN Brute-Force / Credential Access

```bash
cat vpn_auth.log | grep "FAIL"
```

![Failed VPN authentications, checking timing and username pattern](/assets/img/thm-network-security-essentials/ip-assigned-after-brute-force-1-check-time-and-fail.png)

**Q: Which username was targeted in VPN logs?**
**A: `svc_backup`** — the same service account name recurs across the block of failed attempts.

Then filtered directly to that account to find where the failures ended and a login succeeded:
```bash
cat vpn_auth.log | grep "svc_backup"
```

![Internal IP assigned after the successful brute-forced login](/assets/img/thm-network-security-essentials/ip-assigned-after-brute-force-2.png)

**Q: What internal IP was assigned after successful VPN login?**
**A: `10.8.0.23`** — the `assigned_ip` field on the first `SUCCESS` entry immediately following the run of `FAIL`s.

### Stage 3 — Lateral Movement

Filtering the firewall log to the now-compromised internal IP showed it actively probing other internal hosts across SSH/SMB/RDP (22/445/3389):
```bash
cat firewall.log | grep <compromised-ip> | grep "ALLOW" | head
```
Cross-referencing against `ids_alerts.log` confirmed matching signatures — SSH scans, RDP brute-force attempts, and specifically an **MS-SMB Lateral Movement** exploit alert:
```bash
cat ids_alerts.log | grep "SMB"
cat ids_alerts.log | grep "SMB" | cut -d " " -f21 | cut -d ":" -f2 | uniq
```

![Port used for lateral SMB attempts](/assets/img/thm-network-security-essentials/port-used-for-SMB.png)

**Q: Which port was used for lateral SMB attempts?**
**A: `445`** — extracted directly from the destination-port field of every `SMB` alert; every hit lands on the same port.

### Stage 4 — C2 Beaconing

Searched IDS alerts directly for the Trojan signature:
```bash
cat ids_alerts.log | grep C2 | head
```
Then pulled the source IP directly off the C2 alerts to identify the beaconing host:
```bash
cat ids_alerts.log | grep "C2" | cut -d " " -f20 | cut -d ":" -f1 | uniq
```

![Internal host beaconing to the C2](/assets/img/thm-network-security-essentials/host-beaconed.png)

**Q: In the IDS logs, which host beaconed to the C2?**
**A: `10.0.0.60`**

Same alerts, this time reading the destination field to pull the external C2 server:
```bash
cat ids_alerts.log | grep "C2" | cut -d " " -f22 | cut -d ":" -f1 | uniq
```

![External IP associated with the C2 traffic](/assets/img/thm-network-security-essentials/ip-associated-with-C2.png)

**Q: During the investigation, which IP was observed to be associated with C2?**
**A: `198.51.100.77`** — consistently the destination on port 4444, a classic reverse-shell/C2 listener port.

### Stage 5 — Data Exfiltration

Searched the IDS alerts directly for the exfiltration classification rather than starting from the firewall log:
```bash
cat ids_alerts.log | grep "Exfiltration"
cat ids_alerts.log | grep "Exfiltration" | cut -d " " -f20 | cut -d ":" -f1 | uniq
```

![Host showing data exfiltration attempts](/assets/img/thm-network-security-essentials/data-exfiltration.png)

**Q: Which host showed the exfiltration attempts?**
**A: `10.0.0.51`** — every `ET INFO Possible HTTP POST Large Upload [Classification: Potential Data Exfiltration]` alert traces back to this one internal source, sending large POST uploads to an external destination on ports 80/8080.

### Method 2 — Splunk

The same investigation is repeatable in Splunk against the pre-ingested `index="network_logs"` via the Search & Reporting app at `localhost:8000` — the manual `grep`/`cut`/`sort`/`uniq` pipeline above maps directly onto Splunk's `stats count by` and `search` syntax, useful once log volume makes command-line grepping impractical.

![Splunk Search & Reporting against index="network_logs"](/assets/img/thm-network-security-essentials/image.png)

---

## Summary of Findings

| # | Section | Question | Answer |
|---|---|---|---|
| 1 | Scenario 1 | IP performing the port scan | `203.0.113.10` |
| 2 | Scenario 2 | Source IP behind all blocked WAF attacks | `198.51.100.12` |
| 3 | Scenario 3 | Failed VPN brute-force attempt count | `90` |
| 4 | Scenario 3 | Suspicious IP brute-forcing the VPN | `45.137.22.13` |
| 5 | Incident | External IP performing most reconnaissance | `203.0.113.45` |
| 6 | Incident | Internal host targeted by scans | `10.0.0.20` |
| 7 | Incident | Username targeted in VPN logs | `svc_backup` |
| 8 | Incident | Internal IP assigned after VPN login | `10.8.0.23` |
| 9 | Incident | Port used for lateral SMB attempts | `445` |
| 10 | Incident | Host that beaconed to the C2 | `10.0.0.60` |
| 11 | Incident | IP associated with the C2 | `198.51.100.77` |
| 12 | Incident | Host showing exfiltration attempts | `10.0.0.51` |

---

## Attack Chain Reconstruction

```
Reconnaissance (203.0.113.45 → scans FINANCE-SRV1 / 10.0.0.20)
        │
        ▼
VPN Brute-Force (svc_backup account) → success
        │
        ▼
Initial Access → assigned internal IP 10.8.0.23
        │
        ▼
Lateral Movement → SSH scans + RDP brute-force + MS-SMB exploit (port 445)
   compromised host: 10.0.0.60
        │
        ▼
C2 Beaconing → 10.0.0.60 ↔ 198.51.100.77 (port 4444, regular intervals)
        │
        ▼
Data Exfiltration → 10.0.0.51 sends large HTTP POSTs to external IP (ports 80/8080)
```

---

## Takeaways

- **The perimeter tells the whole story if you know where to pivot** — this entire month-long intrusion was reconstructed from three log files using nothing but `grep`, `cut`, `sort`, and `uniq`, moving from one suspicious IP to the next log source it touched.
- **Volume and pattern matter more than any single log line** — a port scan, a brute-force, and C2 beaconing are all distinguishable purely by *shape* (many destinations vs. one destination vs. regular intervals), before reading a single payload.
- **A successful `ALLOW` after a wave of `BLOCK`s is a red flag, not a relief** — the reconnaissance IP eventually getting through is the exact moment recon became compromise.
- **IDS/WAF context beats a bare firewall log every time** — a firewall only says allow/block; the IDS alert naming `MS-SMB Lateral Movement` or `Possible C2 Beaconing` is what turns a log line into an actionable finding.
- **Correlation across host-centric and network-centric sources is the job** — no single log (firewall, IDS, or VPN) told the full story alone; the attack chain only became visible by pivoting an IP from one log into the next.
