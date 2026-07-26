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

Loaded the PCAP and read the frame count straight off the Case Panel/status bar — NetworkMiner reports this the moment a file finishes parsing, no navigation needed.

![Total frame count in the Case Panel / status bar](/assets/img/thm-network-miner/frame-1.png)

**A: `460`**

---

**Q: How many IP addresses use the same MAC address as host `145.253.2.203`?**

Opened the **Hosts** tab and sorted by MAC address. Every IP sharing `145.253.2.203`'s MAC lines up next to each other in the sorted list — a quick visual tell for NAT'd hosts or a MAC-spoofing conflict.

![Hosts sharing MAC address with 145.253.2.203](/assets/img/thm-network-miner/mac-address-1.png)

**A: `2`**

---

**Q: How many packets were sent from host `65.208.228.223`?**

Same **Hosts** tab — expanded the host's row for its "Outgoing sessions" / packet-count detail column.

![Packet count for 65.208.228.223 in Hosts tab](/assets/img/thm-network-miner/packet-sent.png)

**A: `72`**

---

**Q: What is the name of the webserver banner under host `65.208.228.223`?**

Still on the Hosts tab — the "Host Details" pane for that IP surfaces the OS/service banner NetworkMiner fingerprinted from the response headers.

![Webserver banner detail for 65.208.228.223](/assets/img/thm-network-miner/webserver.png)

**A: `Apache`**

---

**Q: Using `mx-4.pcap` — what is the extracted username for the `02694W-WIN10` host?**

Switched to the **Credentials** tab, filtered/scanned for entries tied to the `02694W-WIN10` hostname.

![Extracted username for 02694W-WIN10 in Credentials tab](/assets/img/thm-network-miner/username.png)

**A: `#B\Administrator`**

---

**Q: What is the extracted password for the user logged into `02694W-WIN10`? (Enter the full NTLM hash.)**

Same Credentials tab row — right-clicked to copy the full challenge-response value rather than just the truncated column preview.

![Full NTLM hash extracted for the logged-in user](/assets/img/thm-network-miner/password.png)

**A:**
```
$NETNTLMv2$#B$136B077D942D9A63$FBFF3C253926907AAAAD670A9037F2A5$01010000000000000094D71AE38CD60170A8D571127AE49E00000000020004003300420001001E003000310035003600360053002D00570049004E00310036002D004900520004001E0074006800720065006500620065006500730063006F002E0063006F006D0003003E003000310035003600360073002D00770069006E00310036002D00690072002E0074006800720065006500620065006500730063006F002E0063006F006D0005001E0074006800720065006500620065006500730063006F002E0063006F006D00070008000094D71AE38CD601060004000200000008003000300000000000000000000000003000009050B30CECBEBD73F501D6A2B88286851A6E84DDFAE1211D512A6A5A72594D340A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E00360036002E0033003600000000000000000000000000
```

This is a NetNTLMv2 challenge-response, not a stored hash — crackable offline via Hashcat mode `5600` or John's `netntlmv2` format, not directly comparable to an NTLM hash dump.

---

## Section 2 — Files, Images, Parameters, Keywords, Messages, Anomalies: `mx-7.pcap` & `mx-9.pcap`

**Q: Using `mx-7.pcap` — what is the name of the Linux distro mentioned in the file associated with frame 63602?** *(if no results, check frame 63075)*

Located via the **Files** tab, cross-referencing the frame number column, then opening the reconstructed file to read its contents directly.

![Linux distro name in file linked to frame 63602](/assets/img/thm-network-miner/linux-distro.png)

**A: `CentOS`**

---

**Q: What name and surname are mentioned in the file associated with frame 76469?** *(if no results, check frame 75942)*

Same workflow on the **Files** tab — opened the reconstructed file tied to that frame.

![Name and surname in file linked to frame 76469](/assets/img/thm-network-miner/name-surname.png)

**A: `Ned Flanders`**

---

**Q: What is the source address of the image `ads.bmp.2E5F0FD9[1].bmp`?**

Found via the **Images** tab — hovering over the extracted image reveals its source/destination address and reconstructed path without needing to open a separate detail view.

![Source address of the extracted ads.bmp image](/assets/img/thm-network-miner/source-address.png)

**A: `80.239.178.187`**

---

**Q: What is the frame number of the possible TLS anomaly?**

Found via the **Anomalies** tab — NetworkMiner flags this automatically as part of its built-in TLS/EternalBlue/spoofing detections, no manual filtering required.

![TLS anomaly flagged in the Anomalies tab](/assets/img/thm-network-miner/anomaly-frame.png)

**A: `36255`**

---

**Q: Using `mx-9.pcap` — which platform sent an email with the subject starting with "You have more..."?**

Found via the **Messages** tab, scanning the Sender/Subject columns for the matching subject line.

![Email with subject "You have more..." in Messages tab](/assets/img/thm-network-miner/platform.png)

**A: `Facebook`**

---

**Q: What is the email address of Branson Matheson?**

Same Messages tab — matched the sender name to its underlying email address in the message detail pane.

![Branson Matheson's email address in Messages tab](/assets/img/thm-network-miner/email.png)

**A: `branson@sandsite.org`**

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

Confirmed by opening the same capture in both versions — only v2.7 surfaces the MAC-address correlation/conflict view described in the room's Version Differences task.

![MAC address conflict detection in v2.7](/assets/img/thm-network-miner/mac-address-2png.png)

**A: `2.7`**

---

**Q: Which version can handle frames?**

Same comparison — the dedicated Frames tab (with per-frame detail) only exists in v1.6; it was removed by v2.7.

![Frame handling tab present in v1.6](/assets/img/thm-network-miner/frame-2.png)

**A: `1.6`**

---

**Q: Which version can provide more details on packet details?**

Same v1.6-vs-v2.7 comparison — v1.6's packet detail view goes deeper than what v2.7 exposes for the same capture.

**A: `1.6`**

---

## Section 4 — Exercise: `case1.pcap`

**Q: What is the full OS name of the host `131.151.37.122`?**

Read directly off the **Hosts** tab's OS fingerprint column (Satori/p0f-driven).

![Full OS fingerprint for 131.151.37.122](/assets/img/thm-network-miner/os.png)

**A: `Windows - Windows NT 4`**

---

**Q: Investigate the communication between `131.151.37.122` and `131.151.32.91`. How many bytes were sent by the client (`*.32.91`) through port 1065?**

Isolated via the **Sessions** tab, filtered to the session on port 1065 between the two hosts, then read the client-side byte count column.

![Bytes sent by client on port 1065](/assets/img/thm-network-miner/bytes-send.png)

**A: `192 bytes`**

---

**Q: Investigate the communication between `131.151.37.122` and `131.151.32.21`. How many bytes were sent back by the server (`*.37.122`) through port 143?**

Same Sessions tab, this time filtered to port 143 and reading the server-side byte count.

![Bytes sent by server on port 143](/assets/img/thm-network-miner/bytes-send-2.png)

**A: `20769 bytes`**

---

**Q: What is the sequence number of frame number 9?**

Since v1.6 retains per-frame detail (unlike v2.7, per the Version Differences task), this was pulled from the v1.6 Frames tab, scrolled to frame 9.

![Sequence number for frame 9](/assets/img/thm-network-miner/sequence-number.png)

**A: `2AD77400`**

---

**Q: What is the number of the detected "content types"?**

Read from the capture's parsed protocol/content-type summary.

![Detected content type count](/assets/img/thm-network-miner/content-types.png)

**A: `2`**

---

## Section 5 — Exercise: `case2.pcap`

**Q: What is the USB product's brand name?**

Surfaced via the **Keywords/Parameters** extraction of USB descriptor strings present in the capture (USB-over-network or similar traffic captured the device descriptor).

![USB product brand name](/assets/img/thm-network-miner/usb-name.png)

**A: `ASIX`**

---

**Q: What is the name of the phone model?**

Same parameter/keyword extraction path — a device string in the traffic identifies the handset model.

![Phone model name extracted from traffic](/assets/img/thm-network-miner/phone-model.png)

**A: `Lumia 535`**

---

**Q: What is the source IP of the fish image?**

Found via the **Images** tab, hovering the extracted fish image for its source address.

![Source IP of the extracted fish image](/assets/img/thm-network-miner/fish-source-ip.png)

**A: `50.22.95.9`**

---

**Q: What is the password of `homer.pwned.se@gmx.com`?**

Found via the **Credentials** tab, matched to that email address's session.

![Password extracted for homer.pwned.se@gmx.com](/assets/img/thm-network-miner/homer-password.png)

**A: `spring2015`**

---

**Q: What is the DNS query of frame 62001?**

Found via the **DNS** tab, filtered/scrolled to frame 62001 and read the query name column.

![DNS query for frame 62001](/assets/img/thm-network-miner/DNS-query.png)

**A: `pop.gmx.com`**

---

## Summary of Findings

| # | Source | Question | Answer |
|---|---|---|---|
| 1 | mx-3 | Total frame count | `460` |
| 2 | mx-3 | IPs sharing MAC with `145.253.2.203` | `2` |
| 3 | mx-3 | Packets sent from `65.208.228.223` | `72` |
| 4 | mx-3 | Webserver banner for `65.208.228.223` | `Apache` |
| 5 | mx-4 | Username on `02694W-WIN10` | `#B\Administrator` |
| 6 | mx-4 | NetNTLMv2 hash for that user | `$NETNTLMv2$#B$136B0...` *(full value above)* |
| 7 | mx-7 | Linux distro (frame 63602/63075) | `CentOS` |
| 8 | mx-7 | Name & surname (frame 76469/75942) | `Ned Flanders` |
| 9 | mx-7 | Source address of `ads.bmp` image | `80.239.178.187` |
| 10 | mx-7 | Frame # of possible TLS anomaly | `36255` |
| 11 | mx-9 | Platform sending "You have more..." email | `Facebook` |
| 12 | mx-9 | Branson Matheson's email address | `branson@sandsite.org` |
| 13 | Version diff | Duplicate MAC detection version | `2.7` |
| 14 | Version diff | Frame handling version | `1.6` |
| 15 | Version diff | More detailed packet info version | `1.6` |
| 16 | case1 | Full OS name of `131.151.37.122` | `Windows - Windows NT 4` |
| 17 | case1 | Client bytes sent, port 1065 | `192` |
| 18 | case1 | Server bytes sent, port 143 | `20769` |
| 19 | case1 | Sequence number of frame 9 | `2AD77400` |
| 20 | case1 | Number of detected content types | `2` |
| 21 | case2 | USB product brand name | `ASIX` |
| 22 | case2 | Phone model name | `Lumia 535` |
| 23 | case2 | Source IP of fish image | `50.22.95.9` |
| 24 | case2 | Password for `homer.pwned.se@gmx.com` | `spring2015` |
| 25 | case2 | DNS query of frame 62001 | `pop.gmx.com` |

---

## Analysis Chain Reconstruction

```
Load PCAP into NetworkMiner (free edition)
        │
        ▼
Hosts tab → IP/MAC/OS fingerprint overview → spot MAC conflicts, webserver banners
        │
        ▼
Sessions tab → isolate specific client↔server conversations by port → byte counts
        │
        ▼
Credentials tab → cleartext creds + NetNTLMv2 challenge-response (mx-3, mx-4, case2)
        │
        ▼
Files / Images / Parameters / Keywords / Messages tabs
   → carved artifacts, embedded strings, reconstructed emails (mx-7, mx-9, case2)
        │
        ▼
Anomalies tab → EternalBlue / spoofing / TLS anomaly flags (mx-7)
        │
        ▼
Cross-check v1.6 vs v2.7 → frame-level detail (v1.6) vs MAC-conflict detection (v2.7) (case1)
```

---

## Takeaways

- **NetworkMiner front-loads triage** — within seconds of loading a capture, hosts, sessions, credentials, and carved files are already bucketed, which is exactly the "low-hanging fruit" pass the room keeps emphasizing before reaching for Wireshark.
- **A captured NTLM value is usually a challenge-response, not a hash** — the `mx-4.pcap` "password" is a NetNTLMv2 response tied to a specific challenge, meaning it's crackable offline (Hashcat mode 5600) but isn't a portable password hash on its own.
- **Version choice is a real investigative decision, not just an upgrade** — v1.6 keeps frame-level detail (needed for the `case1.pcap` sequence-number question) that v2.7 drops in favor of MAC-conflict detection and richer parameter parsing. Picking the wrong version for a task costs time.
- **Hover-to-reveal is doing a lot of work** — several answers (image source addresses, session byte counts) live in tooltips/detail panes rather than a visible column, so a quick tab scan alone can miss them.
- **NetworkMiner is a mapper, not an analyst** — it consistently pointed at *where* to look (a frame number, a flagged anomaly, a carved file) but reading the actual content — the CentOS mention, "Ned Flanders," the Facebook email subject — still took opening the reconstructed artifact by hand.
