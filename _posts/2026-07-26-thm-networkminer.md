---
title: "TryHackMe — NetworkMiner"
date: 2026-07-26 09:00:00 +0600
categories: [TryHackMe, Network Traffic Analysis]
tags: [networkminer, pcap, network-forensics, credential-extraction, file-carving, osint]
---

## Overview

**Room:** [NetworkMiner](https://tryhackme.com/room/networkminer)

**Module:** Network Traffic Analysis

**Objective:** Learn NetworkMiner as a Network Forensic Analysis Tool (NFAT) — a passive, PCAP-first alternative to Wireshark that prioritizes a fast overview (hosts, sessions, credentials, extracted files) over deep manual packet inspection. Covers the tool's tabs, how it differs from Wireshark, the free-vs-professional split, version differences between v1.6 and v2.7, and hands-on extraction exercises across five separate capture files.

**Tools used:** NetworkMiner (v1.6 and v2.7, both provided on the lab VM)

**Capture files provided:** `~/Desktop/Exercise Files/mx-3.pcap`, `mx-4.pcap`, `mx-7.pcap`, `mx-9.pcap`, `case1.pcap`, `case2.pcap`

This is a tool-orientation room rather than a single attack narrative, so the structure below follows the room's own path: tool background → tab-by-tab breakdown with embedded questions → version differences → two larger standalone exercises.

---

## NetworkMiner vs. Wireshark

NetworkMiner is built for **passive** analysis — it doesn't actively probe the network, it either sniffs quietly or parses an existing PCAP. Its value is speed: point it at a capture and it immediately buckets the traffic into hosts, sessions, credentials, files, images, parameters, keywords, and messages, without writing a single filter.

| Feature | NetworkMiner | Wireshark |
|---|---|---|
| Purpose | Quick overview, traffic mapping, data extraction | In-depth analysis |
| OS Fingerprinting | ✅ (Satori + p0f) | ❌ |
| Credential / File / Parameter Extraction | ✅ | ✅ (manual) |
| Filtering | Limited | ✅ |
| Protocol / Payload / Statistical Analysis | ❌ | ✅ |
| Host Categorisation | ✅ | ❌ |

**Practical takeaway from the room:** record traffic for offline analysis, get the fast overview with NetworkMiner first to grab "low-hanging fruit," then go deep with Wireshark for anything that needs manual protocol-level inspection.

**Pros:** OS fingerprinting, easy file extraction, credential grabbing, cleartext keyword parsing, strong overall overview.
**Cons:** unreliable as an active sniffer, weak on large PCAPs, limited filtering, not built for manual packet-level investigation.

---

## Tab-by-Tab Breakdown

**Hosts** — every identified host with IP, MAC, OS fingerprint (via Satori/p0f), open ports, packet counts, and session direction.

**Sessions** — detected sessions (frame #, client/server address, ports, protocol, start time), searchable via `ExactPhrase` / `AllWords` / `AnyWord` / `RegExp` filter modes.

**DNS** — every DNS query with timestamp, TTL, transaction ID/type, query/answer pair (Alexa Top 1M lookup is Pro-only).

**Credentials** — extracted Kerberos hashes, NTLM hashes, RDP cookies, HTTP cookies/requests, IMAP, FTP, SMTP, and MS SQL credentials, crackable downstream with Hashcat or John the Ripper.

**Files / Images / Parameters / Keywords / Messages** — carved artifacts from the capture: reconstructed files, extracted images (with hover-to-reveal source/destination and path), HTTP parameters, matched keywords with context, and reconstructed emails/chats.

**Anomalies** — NetworkMiner isn't an IDS, but it flags a couple of specific signatures out of the box: EternalBlue exploit attempts and spoofing indicators.

---

## Section 1 — Credentials Tab: `mx-3.pcap` & `mx-4.pcap`

**Q: Using `mx-3.pcap` — what is the total number of frames?**

![Total frame count in the Case Panel / status bar](/assets/img/thm-network-miner/frame-1.png)

**A:** `<verify from screenshot>`

---

**Q: How many IP addresses use the same MAC address as host `145.253.2.203`?**

Checked via the Hosts tab, sorted/grouped by MAC address to spot every IP sharing that same physical address (a MAC-address conflict indicator).

![Hosts sharing MAC address with 145.253.2.203](/assets/img/thm-network-miner/mac-address-1.png)

**A:** `<verify from screenshot>`

---

**Q: How many packets were sent from host `65.208.228.223`?**

![Packet count for 65.208.228.223 in Hosts tab](/assets/img/thm-network-miner/packet-sent.png)

**A:** `<verify from screenshot>`

---

**Q: What is the name of the webserver banner under host `65.208.228.223`?**

![Webserver banner detail for 65.208.228.223](/assets/img/thm-network-miner/webserver.png)

**A:** `<verify from screenshot>`

---

**Q: Using `mx-4.pcap` — what is the extracted username for the `02694W-WIN10` host?**

![Extracted username for 02694W-WIN10 in Credentials tab](/assets/img/thm-network-miner/username.png)

**A:** `<verify from screenshot>`

---

**Q: What is the extracted password for the user logged into `02694W-WIN10`? (Enter the full NTLM hash.)**

![Full NTLM hash extracted for the logged-in user](/assets/img/thm-network-miner/password.png)

**A:** `<verify from screenshot>`

---

## Section 2 — Files, Images, Parameters, Keywords, Messages, Anomalies: `mx-7.pcap` & `mx-9.pcap`

**Q: Using `mx-7.pcap` — what is the name of the Linux distro mentioned in the file associated with frame 63602?** *(if no results, check frame 63075)*

Located via the Files tab, cross-referencing the frame number column, then opening the reconstructed file.

![Linux distro name in file linked to frame 63602](/assets/img/thm-network-miner/linux-distro.png)

**A:** `<verify from screenshot>`

---

**Q: What name and surname are mentioned in the file associated with frame 76469?** *(if no results, check frame 75942)*

![Name and surname in file linked to frame 76469](/assets/img/thm-network-miner/name-surname.png)

**A:** `<verify from screenshot>`

---

**Q: What is the source address of the image `ads.bmp.2E5F0FD9[1].bmp`?**

Found via the Images tab — hovering over the extracted image reveals its source/destination address and reconstructed path.

![Source address of the extracted ads.bmp image](/assets/img/thm-network-miner/source-address.png)

**A:** `<verify from screenshot>`

---

**Q: What is the frame number of the possible TLS anomaly?**

Found via the Anomalies tab.

![TLS anomaly flagged in the Anomalies tab](/assets/img/thm-network-miner/anomaly-frame.png)

**A:** `<verify from screenshot>`

---

**Q: Using `mx-9.pcap` — which platform sent an email with the subject starting with "You have more..."?**

Found via the Messages tab.

![Email with subject "You have more..." in Messages tab](/assets/img/thm-network-miner/platform.png)

**A:** `<verify from screenshot>`

---

**Q: What is the email address of Branson Matheson?**

![Branson Matheson's email address in Messages tab](/assets/img/thm-network-miner/email.png)

**A:** `<verify from screenshot>`

---

## Section 3 — Version Differences (v1.6 vs v2.7)

The lab VM ships both major versions since several capabilities moved, were added, or were dropped between them:

| Capability | v1.6 | v2.7 |
|---|---|---|
| MAC address conflict correlation | ❌ | ✅ |
| Detailed frame handling/processing | ✅ | ❌ |
| Extensive parameter processing | Fewer parameters caught | ✅ more thorough |
| Single-tab cleartext data view | ✅ | ❌ (no longer matchable to individual packets) |

**Q: Which version can detect duplicate MAC addresses?**

![MAC address conflict detection in v2.7](/assets/img/thm-network-miner/mac-address-2png.png)

**A: `2.7`**

---

**Q: Which version can handle frames?**

![Frame handling tab present in v1.6](/assets/img/thm-network-miner/frame-2.png)

**A: `1.6`**

---

**Q: Which version can provide more details on packet details?**

**A: `1.6`**

---

## Section 4 — Exercise: `case1.pcap`

**Q: What is the full OS name of the host `131.151.37.122`?**

Read directly off the Hosts tab's OS fingerprint column (Satori/p0f).

![Full OS fingerprint for 131.151.37.122](/assets/img/thm-network-miner/os.png)

**A:** `<verify from screenshot>`

---

**Q: Investigate the communication between `131.151.37.122` and `131.151.32.91`. How many bytes were sent by the client (`*.32.91`) through port 1065?**

Isolated via the Sessions tab, filtered to the session on port 1065 between the two hosts.

![Bytes sent by client on port 1065](/assets/img/thm-network-miner/bytes-send.png)

**A:** `<verify from screenshot>`

---

**Q: Investigate the communication between `131.151.37.122` and `131.151.32.21`. How many bytes were sent back by the server (`*.37.122`) through port 143?**

![Bytes sent by server on port 143](/assets/img/thm-network-miner/bytes-send-2.png)

**A:** `<verify from screenshot>`

---

**Q: What is the sequence number of frame number 9?**

Since v1.6 retains per-frame detail (unlike v2.7), this was pulled from the v1.6 Frames tab.

![Sequence number for frame 9](/assets/img/thm-network-miner/sequence-number.png)

**A:** `<verify from screenshot>`

---

**Q: What is the number of the detected "content types"?**

![Detected content type count](/assets/img/thm-network-miner/content-types.png)

**A:** `<verify from screenshot>`

---

## Section 5 — Exercise: `case2.pcap`

**Q: What is the USB product's brand name?**

Surfaced via the Keywords/Parameters extraction of USB descriptor strings in the capture.

![USB product brand name](/assets/img/thm-network-miner/usb-name.png)

**A:** `<verify from screenshot>`

---

**Q: What is the name of the phone model?**

![Phone model name extracted from traffic](/assets/img/thm-network-miner/phone-model.png)

**A:** `<verify from screenshot>`

---

**Q: What is the source IP of the fish image?**

Found via the Images tab, hovering the extracted fish image for its source address.

![Source IP of the extracted fish image](/assets/img/thm-network-miner/fish-source-ip.png)

**A:** `<verify from screenshot>`

---

**Q: What is the password of `homer.pwned.se@gmx.com`?**

Found via the Credentials tab.

![Password extracted for homer.pwned.se@gmx.com](/assets/img/thm-network-miner/homer-password.png)

**A:** `<verify from screenshot>`

---

**Q: What is the DNS query of frame 62001?**

Found via the DNS tab, filtered/scrolled to frame 62001.

![DNS query for frame 62001](/assets/img/thm-network-miner/DNS-query.png)

**A:** `<verify from screenshot>`

---

## Summary of Findings

| # | Source | Question | Answer |
|---|---|---|---|
| 1 | mx-3 | Total frame count | `<verify>` |
| 2 | mx-3 | IPs sharing MAC with `145.253.2.203` | `<verify>` |
| 3 | mx-3 | Packets sent from `65.208.228.223` | `<verify>` |
| 4 | mx-3 | Webserver banner for `65.208.228.223` | `<verify>` |
| 5 | mx-4 | Username on `02694W-WIN10` | `<verify>` |
| 6 | mx-4 | NTLM hash for that user | `<verify>` |
| 7 | mx-7 | Linux distro (frame 63602/63075) | `<verify>` |
| 8 | mx-7 | Name & surname (frame 76469/75942) | `<verify>` |
| 9 | mx-7 | Source address of `ads.bmp` image | `<verify>` |
| 10 | mx-7 | Frame # of possible TLS anomaly | `<verify>` |
| 11 | mx-9 | Platform sending "You have more..." email | `<verify>` |
| 12 | mx-9 | Branson Matheson's email address | `<verify>` |
| 13 | Version diff | Duplicate MAC detection version | `2.7` |
| 14 | Version diff | Frame handling version | `1.6` |
| 15 | Version diff | More detailed packet info version | `1.6` |
| 16 | case1 | Full OS name of `131.151.37.122` | `<verify>` |
| 17 | case1 | Client bytes sent, port 1065 | `<verify>` |
| 18 | case1 | Server bytes sent, port 143 | `<verify>` |
| 19 | case1 | Sequence number of frame 9 | `<verify>` |
| 20 | case1 | Number of detected content types | `<verify>` |
| 21 | case2 | USB product brand name | `<verify>` |
| 22 | case2 | Phone model name | `<verify>` |
| 23 | case2 | Source IP of fish image | `<verify>` |
| 24 | case2 | Password for `homer.pwned.se@gmx.com` | `<verify>` |
| 25 | case2 | DNS query of frame 62001 | `<verify>` |

---

## Analysis Chain Reconstruction

```
Load PCAP into NetworkMiner (free edition)
        │
        ▼
Hosts tab → IP/MAC/OS fingerprint overview → spot MAC conflicts
        │
        ▼
Sessions tab → isolate specific client↔server conversations by port
        │
        ▼
Credentials tab → cleartext creds + NTLM/Kerberos hashes (mx-3, mx-4, case2)
        │
        ▼
Files / Images / Parameters / Keywords / Messages tabs
   → carved artifacts, embedded strings, reconstructed emails (mx-7, mx-9, case2)
        │
        ▼
Anomalies tab → EternalBlue / spoofing / TLS anomaly flags (mx-7)
        │
        ▼
Cross-check v1.6 vs v2.7 → frame-level detail only in v1.6 (case1)
```

---

## Takeaways

- **NetworkMiner front-loads triage** — within seconds of loading a capture, hosts, sessions, credentials, and carved files are already bucketed, which is exactly the "low-hanging fruit" pass the room keeps emphasizing before reaching for Wireshark.
- **The free/Pro split matters for OSINT** — Alexa Top 1M lookups, OSINT hash lookups, and sample submission are Pro-only; the free edition still covers extraction, just not enrichment.
- **Version choice is a real investigative decision, not just an upgrade** — v1.6 keeps frame-level detail and a single cleartext-data tab that v2.7 drops in favor of MAC-conflict detection and richer parameter parsing. Picking the wrong version for a task (e.g. needing a frame sequence number in v2.7) costs time.
- **Hover-to-reveal is doing a lot of work** — several answers (image source addresses, session byte counts) live in tooltips/detail panes rather than a visible column, so a quick tab scan alone can miss them.
- **NetworkMiner is a mapper, not an analyst** — it consistently pointed at *where* to look (a frame number, a flagged anomaly, a carved file) but Wireshark-level manual inspection was still the tool that confirmed *what* was actually happening at the packet level.

> Screenshot rendering didn't come through cleanly for this batch, so every `<verify from screenshot>` above needs a manual fill-in from your own NetworkMiner session. Paste the values (or re-share the screenshots one at a time) and I'll drop them straight into both the per-question answers and the summary table.
