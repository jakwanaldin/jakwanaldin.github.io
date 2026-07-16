---
title: "TryHackMe — Wireshark: Packet Operations"
date: 2026-07-16 17:00:00 +0600
categories: [TryHackMe, Network Traffic Analysis]
tags: [wireshark, packet-analysis, pcap, network-forensics, display-filters, dns, http]
---

## Overview

**Room:** [Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations)

**Module:** Network Traffic Analysis (second room of the Wireshark trio, following [Wireshark: The Basics](https://tryhackme.com/room/wiresharkthebasics))

**Objective:** Move past the interface fundamentals covered in the first room and get hands-on with Wireshark's **Statistics** menu, **display filter syntax**, **protocol-level filters**, and **advanced filtering operators/functions** — the actual toolkit used to go from "a big pcap" to "the specific packets that matter."

**Prerequisites:** Networking Fundamentals, Wireshark: The Basics

**Tools used:** Wireshark (Statistics menu, display filter bar, Configuration Profiles)

**Capture file provided:** `Exercise.pcapng`

Unlike the first room, this one is almost entirely filter- and statistics-driven — no file carving or hex-diving, just building a hypothesis from the Statistics menu and then proving it with increasingly specific display filters. The walkthrough below follows the actual order the questions were solved in.

---

## Part 1 — Statistics: Building the Hypothesis

Before writing a single filter, the **Statistics** menu was used to get the big picture of the capture — protocols in play, endpoints, conversations, and DNS/HTTP-specific summaries.

- Investigated **Statistics → Resolved Addresses** to find the IP address of the hostname starting with "bbc," then searched for `bbc` in the list.

  ![Resolved addresses — bbc hostname lookup](/assets/img/thm-Wireshark-packet-operations/host-name-bbc-ip.png)

  **Answer:** `199.232.24.81`

- Opened **Statistics → Conversations** to get the number of IPv4 conversations.

  ![IPv4 conversations count](/assets/img/thm-Wireshark-packet-operations/no-of-ipv4.png)

  **Answer:** `435`

- To get bytes transferred from the **Micro-St** MAC address, name resolution had to be turned on first: **Edit → Preferences → Name Resolution** → enabled "Resolve transport names" and "Resolve network (IP) addresses," then went to **Statistics → Endpoints** and checked the "Name resolution" box there too, so the manufacturer prefix (Micro-Star) resolved on the Ethernet endpoint list.

  ![Micro-St MAC address bytes transferred](/assets/img/thm-Wireshark-packet-operations/Micro-st-bytes.png)

  **Answer:** `7474` KB

- Switched to the **IPv4** tab in Endpoints and sorted by **City** to count IP addresses linked to "Kansas City."

  ![IP addresses linked to Kansas City](/assets/img/thm-Wireshark-packet-operations/no-of-ip-kansas-city.png)

  **Answer:** `4`

- Sorted the same IPv4 endpoint list by **AS Organization**, located "Blicnet," and applied it as a filter to confirm the linked address.

  ![IP address linked to Blicnet AS organization](/assets/img/thm-Wireshark-packet-operations/blicn-net-ip.png)

  **Answer:** `188.246.82.7`

- Back in **IPv4 Statistics**, sorted the source/destination address list by count to find the most-used IPv4 destination address.

  ![Most used IPv4 destination address](/assets/img/thm-Wireshark-packet-operations/most-visit-destination-ip.png)

  **Answer:** `10.100.1.33`

- Opened **Statistics → DNS**, sorted by max response time value to find the slowest DNS service request-response.

  ![Max DNS service request-response time](/assets/img/thm-Wireshark-packet-operations/max-time-request-response.png)

  **Answer:** `0.467897` seconds

- Opened **Statistics → HTTP → Load Distribution**, sorted by count, and summed the request counts under `rad[.]msn[.]com`.

  ![HTTP requests to rad.msn.com — load distribution](/assets/img/thm-Wireshark-packet-operations/rad-msn-com.png)

  **Answer:** `39`

---

## Part 2 — Protocol Filters: Turning the Hypothesis into a Query

With a feel for the traffic from Statistics, the next set of questions were answered by typing display filters directly into the filter bar and reading the "Displayed" packet count in the status bar.

- Typed `ip` to get the total number of IP packets.

  ![Filter: ip — total IP packet count](/assets/img/thm-Wireshark-packet-operations/no-of-ip-packet.png)

  **Answer:** `81420`

- Typed `ip.ttl < 10` for packets with a TTL below 10.

  ![Filter: ip.ttl < 10](/assets/img/thm-Wireshark-packet-operations/ip-ttl.png)

  **Answer:** `66`

- Typed `tcp.port == 4444` for packets on TCP port 4444.

  ![Filter: tcp.port == 4444](/assets/img/thm-Wireshark-packet-operations/tcp-port-4444.png)

  **Answer:** `632`

- Typed `tcp.port == 80 && http.request.method == "GET"` for HTTP GET requests sent to port 80.

  ![Filter: HTTP GET requests to port 80](/assets/img/thm-Wireshark-packet-operations/get-port-80.png)

  **Answer:** `527`

- Typed `dns.a` for the number of type A DNS queries.

  ![Filter: dns.a — type A DNS queries](/assets/img/thm-Wireshark-packet-operations/click-filter-1.png)

  **Answer:** `51`

---

## Part 3 — Advanced Filtering: Operators and Functions

The final set of questions used Wireshark's advanced filter operators (`contains`, `in`, `matches`-style string functions) and a saved Configuration Profile.

- Typed `http.server contains "Microsoft-IIS" && !(tcp.port == 80)` to find Microsoft IIS servers on a port other than 80.

  ![Microsoft IIS servers not on port 80](/assets/img/thm-Wireshark-packet-operations/microsoft-IIS.png)

  **Answer:** `21`

- Typed `http.server contains "Microsoft-IIS/7.5"` to isolate the version 7.5 packets specifically.

  ![Microsoft IIS version 7.5 packets](/assets/img/thm-Wireshark-packet-operations/server-7.5.png)

  **Answer:** `71`

- Typed `tcp.port in {3333 4444 9999}` using the set-membership `in` operator to catch all three ports at once.

  ![Packets on ports 3333, 4444, or 9999](/assets/img/thm-Wireshark-packet-operations/port-3333-4444-9999.png)

  **Answer:** `2235`

- Typed `string(ip.ttl) matches "[02468]$"` — converting the TTL field to a string and pattern-matching on an even last digit.

  ![Packets with even TTL numbers](/assets/img/thm-Wireshark-packet-operations/even-number-ttl.png)

  **Answer:** `77289`

- Switched profiles via the status bar to **Checksum Control**, then typed `tcp.checksum.status == Bad` to count bad TCP checksum packets.

  ![Bad TCP checksum packets under Checksum Control profile](/assets/img/thm-Wireshark-packet-operations/bad-checksum.png)

  **Answer:** `34185`

- Used an existing saved **filter button** (pre-built for GIF/JPEG traffic with an HTTP 200 response) to filter with a single click and read the displayed packet count.

  ![Existing filter button — displayed packet count](/assets/img/thm-Wireshark-packet-operations/click-filter-2.png)

  **Answer:** `261`

---

## Summary of Findings

| # | Task | Filter / Path Used | Answer |
|---|------|---------------------|--------|
| 1 | Hostname starting with "bbc" | Statistics → Resolved Addresses | `199.232.24.81` |
| 2 | Number of IPv4 conversations | Statistics → Conversations | `435` |
| 3 | Bytes (KB) from "Micro-St" MAC | Name Resolution + Statistics → Endpoints | `7474` |
| 4 | IPs linked to "Kansas City" | IPv4 Endpoints sorted by City | `4` |
| 5 | IP linked to "Blicnet" AS org | IPv4 Endpoints sorted by AS Org → Apply as Filter | `188.246.82.7` |
| 6 | Most used IPv4 destination | IPv4 Statistics sorted by count | `10.100.1.33` |
| 7 | Max DNS request-response time | Statistics → DNS sorted by max val | `0.467897` |
| 8 | HTTP requests to rad.msn.com | Statistics → HTTP → Load Distribution | `39` |
| 9 | Number of IP packets | `ip` | `81420` |
| 10 | Packets with TTL < 10 | `ip.ttl < 10` | `66` |
| 11 | Packets on TCP port 4444 | `tcp.port == 4444` | `632` |
| 12 | HTTP GET requests to port 80 | `tcp.port == 80 && http.request.method == "GET"` | `527` |
| 13 | Type A DNS queries | `dns.a` | `51` |
| 14 | Microsoft IIS packets not on port 80 | `http.server contains "Microsoft-IIS" && !(tcp.port == 80)` | `21` |
| 15 | Microsoft IIS version 7.5 packets | `http.server contains "Microsoft-IIS/7.5"` | `71` |
| 16 | Packets on ports 3333, 4444, or 9999 | `tcp.port in {3333 4444 9999}` | `2235` |
| 17 | Packets with even TTL numbers | `string(ip.ttl) matches "[02468]$"` | `77289` |
| 18 | Bad TCP checksum packets | Checksum Control profile → `tcp.checksum.status == Bad` | `34185` |
| 19 | Displayed packets via saved filter button | Existing filter button (GIF/JPEG, HTTP 200) | `261` |

---

## Analysis Chain Reconstruction

```
Load Exercise.pcapng
        │
        ▼
Statistics → Resolved Addresses / Conversations / Endpoints
   (bbc hostname, IPv4 conversation count)
        │
        ▼
Edit → Preferences → Name Resolution (enable)
   → Statistics → Endpoints (Micro-St bytes, Kansas City count, Blicnet AS org)
        │
        ▼
Statistics → IPv4 / DNS / HTTP
   (most-used destination, max DNS response time, rad.msn.com requests)
        │
        ▼
Display filter bar: ip / ip.ttl / tcp.port / http.request.method / dns.a
   (packet counts by protocol field)
        │
        ▼
Advanced operators: contains / in / matches(string)
   (Microsoft-IIS, port sets, even TTLs)
        │
        ▼
Configuration Profiles: switch to "Checksum Control"
   → tcp.checksum.status == Bad
        │
        ▼
Saved filter button → single-click filter → displayed packet count
```

---

## Takeaways

- **Statistics before filters** — every filter written in Part 2 and 3 was really just "proving" a pattern that Statistics already hinted at (top talkers, DNS load, HTTP distribution). Building the hypothesis first makes the filter syntax almost mechanical.
- **Name resolution isn't automatic** — the Micro-St MAC question is a good reminder that Wireshark's manufacturer/hostname resolution has to be explicitly enabled in both Preferences *and* the specific Statistics window (Endpoints) before it appears.
- **`ip.addr` vs `ip.src`/`ip.dst`** matters for direction-aware filtering, and `!=` should be avoided in favor of `!(...)` — the IIS filter here (`!(tcp.port == 80)`) is the safer pattern the room calls out explicitly.
- **`in {}` beats chained `||`** — for multi-value port/field matching, the set-membership operator is both shorter and less error-prone than stacking OR conditions.
- **Profiles are for repeatable investigation types** — switching to "Checksum Control" instead of manually reconfiguring coloring rules/columns for a one-off check is the whole point of Wireshark profiles.
