---
title: "TryHackMe: Investigating with Splunk"
date: 2026-07-06 12:00:00 +0600
categories: [TryHackMe, DFIR]
tags: [splunk, siem, log-analysis, powershell, windows, incident-response, threat-hunting]
---

> **Note for publishing:** this post references 13 screenshots at paths like `/assets/img/01-....png`. Upload the accompanying `investigating-with-splunk-thm` image folder into your repo's `assets/img/` directory (create it if it doesn't exist) so the paths resolve correctly.
{: .prompt-tip }

## Overview

**Room:** [Investigating with Splunk](https://tryhackme.com/room/investigatingwithsplunk)
**Difficulty:** Easy
**Category:** SOC / Log Analysis / SIEM

SOC Analyst "Johny" noticed anomalous behavior across several Windows hosts. Logs from the suspected machines were pulled and ingested into Splunk under the `main` index for investigation. The objective of this room is to work through those logs as a SOC analyst would — using Splunk's Search Processing Language (SPL) to trace an attacker's actions from initial anomaly to full attack chain reconstruction.

This writeup documents the investigation process, the SPL queries used at each stage, and the reasoning behind pivoting from one indicator to the next.

**Skills demonstrated:** Splunk SPL, Windows Security Event ID triage, Sysmon log analysis, PowerShell script block log analysis, Base64/payload decoding with CyberChef, IOC defanging.

---

## Initial Triage

First step in any Splunk-based investigation: confirm scope. How much data are we working with?

```spl
index="main"
```

This returned **12,256 events** ingested into the index — confirming the full dataset was available before narrowing the search.

![Initial search showing 12,256 events ingested into the main index](/assets/img/01-initial-search-12256-events.png)
_12,256 total events confirmed in the `main` index_

---

## Identifying the Backdoor User Account

Windows Security Event ID **4720** ("A user account was created") is the standard indicator for new local/domain account creation — a common persistence technique. Searching for it directly:

```spl
index="main" EventID="4720"
```

This returned a single event, showing a new account created on `WORKSTATION6`:

![EventID 4720 search returning one account creation event](/assets/img/02-eventid-4720-search.png)
_A single 4720 event — an account was created on `WORKSTATION6`_

- **New Account Name:** `A1berto`
- **SAM Account Name:** `A1berto`
- **Creating account:** `James` (domain: `Cybertees`)

![Full account creation event details showing account attributes](/assets/img/03-new-account-details.png)
_Full 4720 event detail confirming the new account `A1berto` on `WORKSTATION6`_

The username `A1berto` is a clear typosquat of a legitimate-looking name (`Alberto`), using the digit `1` in place of the letter `l` — a common technique to blend in with real usernames during a quick review of user lists while still being distinguishable to the attacker.

---

## Registry Evidence of the New Account

Sysmon Event ID **12** (Registry object added/deleted) confirmed the account creation left a registry artifact under the SAM hive:

```spl
index="main" Hostname="Micheal.Beaven" A1berto
```

This surfaced a `Microsoft-Windows-Sysmon/Operational` event showing the registry key:

```
HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
```

Process responsible: `C:\windows\system32\lsass.exe` (expected, since LSASS manages SAM account objects).

![Sysmon EventID 12 registry event showing the SAM registry key for A1berto](/assets/img/04-sysmon-registry-key.png)
_Sysmon EventID 12 confirming the SAM registry artifact for the new account_

---

## Tracing the Remote Command Execution

With the backdoor account confirmed, the next question was: **how** was it created, and from where?

Searching more broadly for the account creation command:

```spl
index="main" a new process was created A1berto
```

This surfaced Event ID **4688** (process creation) with the following command line, executed via WMIC from a remote node:

```
"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
```

![Full EventID 4688 process creation event with WMIC command line](/assets/img/05-wmic-process-creation-event.png)
_EventID 4688 showing the remote WMIC process creation initiated from `James.browne`_

![Zoomed view of the WMIC command line creating the backdoor account](/assets/img/06-wmic-commandline-zoom.png)
_The exact command line used to create the backdoor account remotely_

Key details from this event:

| Field | Value |
|---|---|
| Host that issued the command | `James.browne` |
| Target node | `WORKSTATION6` |
| Creator account | `James` (domain `Cybertees`) |
| Technique | Remote process creation via WMIC → `net user /add` |

This confirms the attacker had already compromised `James.browne`'s session and used it to pivot laterally, executing account creation remotely on `WORKSTATION6` rather than locally — a common lateral movement pattern to avoid raising alarms on the host they're currently operating from.

**MITRE ATT&CK mapping:** T1136.001 (Create Account: Local Account), T1047 (Windows Management Instrumentation), T1021 (Lateral Movement).

---

## Checking for Backdoor Account Usage

To determine whether the attacker actually logged in using the newly created `A1berto` account:

```spl
index="main" logged on A1berto
```

**Result: 0 events.**

![Search for login events using the A1berto account returning zero results](/assets/img/07-backdoor-login-search-zero-events.png)
_No login events found for the `A1berto` backdoor account_

This is a useful negative finding — it indicates the account was created as a persistence mechanism but was **not used to authenticate** during the timeframe captured in these logs, suggesting the investigation caught the intrusion before the attacker returned to use their backdoor, or that account was created for later use.

---

## Identifying the PowerShell Execution Host

Turning attention to PowerShell abuse — a common secondary technique alongside account creation. Searching broadly:

```spl
index="main" Powershell commands
```

This pointed to **`James.browne`** as the host on which suspicious PowerShell activity occurred — consistent with this being the attacker's initial foothold, from which they pivoted to `WORKSTATION6`.

![Search results for suspicious PowerShell command activity](/assets/img/08-powershell-commands-search.png)
_PowerShell command activity traced back to `James.browne`_

---

## Measuring PowerShell Logging Volume

PowerShell Script Block Logging was enabled on `James.browne`, captured via **Event ID 4103** (Module Logging — records pipeline execution details and the context PowerShell commands ran in).

```spl
index="main" EventID="4103" James.Browne
```

This returned **79 events**, confirming PowerShell logging was actively capturing the malicious activity on this host in detail — enough to fully reconstruct the attacker's script.

![Search for EventID 4103 returning 79 events](/assets/img/09-eventid-4103-79-events.png)
_79 Module Logging (4103) events captured on `James.browne`_

---

## Decoding the Malicious PowerShell Payload

Reviewing the EventID 4103 events revealed a heavily obfuscated PowerShell one-liner using mixed-case syntax (a common AMSI/detection evasion technique) and an embedded Base64-encoded string passed through `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))`.

The relevant fragment:

```powershell
$ser=$([TeXT.ENCodiNG]::UnicodE.GetStriNG([CoNVeRT]::FroMBASe64StRIng('aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==')))
```

### Decoding with CyberChef

1. **Input:** the extracted Base64 blob `aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==`
2. **Recipe:** `From Base64` → output showed UTF-16LE encoded bytes
3. **Result:** `http://10.10.10.5/news.php`

![CyberChef input of the full Base64-encoded PowerShell payload](/assets/img/10-cyberchef-base64-input.png)
_The full Base64-encoded PowerShell payload extracted from the 4103 event logs_

![CyberChef From Base64 and Remove null bytes recipe revealing the deobfuscated PowerShell script](/assets/img/11-cyberchef-decoded-powershell.png)
_`From Base64` → `Remove null bytes` reveals the full WebClient/IEX download-and-execute chain_

![CyberChef decoding the smaller embedded Base64 string to reveal the C2 URL](/assets/img/12-cyberchef-decoded-c2-url.png)
_Decoding the inner Base64 string reveals the C2 callback: `http://10.10.10.5`_

This is the attacker's callback/C2 endpoint — the compromised host was reaching out to `10.10.10.5/news.php`, most likely to pull down a secondary payload or exfiltrate data, consistent with the surrounding script logic which built a WebClient, set headers, and used a proxy-aware download routine before executing the response with `IEX`.

For the wider Base64-encoded PowerShell body (the full obfuscated launcher captured in the 4103 events), the same `From Base64` → `Remove null bytes` recipe in CyberChef was used to reveal the deobfuscated script, exposing the full WebClient/IEX download-and-execute chain.

**MITRE ATT&CK mapping:** T1059.001 (PowerShell), T1027 (Obfuscated Files or Information), T1105 (Ingress Tool Transfer), T1071.001 (Application Layer Protocol: Web).

---

## Defanging the Indicator

Before sharing the C2 URL in any report or threat intel feed, it was defanged using CyberChef's `Defang URL` operation (escaping `.`, `http`, and `://`):

```
http://10.10.10.5/news.php
```
→
```
hxxp[://]10[.]10[.]10[.]5/news[.]php
```

![CyberChef Defang URL recipe applied to the C2 URL](/assets/img/13-cyberchef-defang-url.png)
_Defanged C2 URL, safe to include in a report or ticket_

This prevents the URL from being accidentally clicked or auto-parsed as a live link when shared in Slack, email, or a report.

---

## Summary of Findings

| Question | Answer |
|---|---|
| Total events ingested | 12,256 |
| Backdoor username created | `A1berto` |
| Registry key for new account | `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto` |
| User being impersonated | `Alberto` |
| Command used to create backdoor remotely | `wmic /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"` |
| Login attempts by backdoor account | 0 |
| Host with malicious PowerShell activity | `James.browne` |
| PowerShell (EventID 4103) events logged | 79 |
| Decoded C2 URL from encoded PowerShell | `hxxp[://]10[.]10[.]10[.]5/news[.]php` |

---

## Attack Chain Reconstruction

```
1. Initial foothold on James.browne
2. Obfuscated PowerShell executed (Base64 + UTF-16 encoded payload)
   → decoded to reveal C2 callback: 10.10.10.5/news.php
3. Attacker pivots laterally to WORKSTATION6 via WMIC (remote process creation)
4. Backdoor local account "A1berto" created (typosquat of "Alberto") for persistence
5. Account created but not yet used to authenticate (no login events observed)
```

---

## Key Takeaways

- **Event ID triage is the fastest path to signal.** Knowing that 4720 = account creation and 4688 = process creation let me jump straight to the relevant events instead of scrolling through 12k+ raw logs.
- **Negative results matter.** Confirming 0 login events for the backdoor account was as important as finding the account itself — it changes the incident's severity and response priority.
- **Obfuscation doesn't survive decoding.** Mixed-case PowerShell and layered Base64/UTF-16 encoding are meant to slow down analysts and evade string-matching detections, not withstand manual decoding in CyberChef.
- **Always defang before sharing.** A live, clickable C2 URL in a Slack message or ticket is an easy way to accidentally trigger a callback or get flagged by outbound security tooling.

---

*Room: [TryHackMe – Investigating with Splunk](https://tryhackme.com/room/investigatingwithsplunk)*
