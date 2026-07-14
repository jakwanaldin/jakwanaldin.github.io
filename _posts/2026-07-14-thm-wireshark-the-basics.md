---
title: "TryHackMe — Wireshark: The Basics"
date: 2026-07-14 09:00:00 +0600
categories: [TryHackMe, Network Traffic Analysis]
tags: [wireshark, packet-analysis, pcap, network-forensics, tcp-ip]
---

## Overview

**Room:** [Wireshark: The Basics](https://tryhackme.com/room/wiresharkthebasics)
**Module:** Network Traffic Analysis
**Objective:** Get familiar with Wireshark's core interface and workflow — loading captures, dissecting packets across OSI layers, navigating and searching large capture files, exporting embedded objects, and applying basic display filters.
**Tools used:** Wireshark, Linux terminal (`md5sum`)
**Capture files provided:** `http1.pcapng` (used only to mirror the room's example screenshots), `Exercise.pcapng` (used to answer every question)

![Room overview](/assets/img/thm-Wireshark-The-Basics-room-info/1773339068622-wiresharkthebasics.png)

This room is a foundations room rather than a vulnerability walkthrough, so the "attack chain" here is really an **analysis chain** — the sequence of Wireshark features used to move from a raw capture file to specific extracted artifacts (hashes, hidden text, an embedded image, and filtered traffic).

---

## Step 1 — Tool Overview & File Analysis

Before touching individual packets, the capture file's metadata was reviewed via **Statistics → Capture File Properties**.

![Opening Capture File Properties](/assets/img/thm-Wireshark-The-Basics-room-info/go-to-CFS.png)
![Statistics menu](/assets/img/thm-Wireshark-The-Basics-room-info/click-on-statistics.png)

- **Capture file comment:** `TryHackMe_Wireshark_Demo`
  ![Capture file comment / flag](/assets/img/thm-Wireshark-The-Basics-room-info/flag-1.png)
- **Total packets captured:** `58620`
  ![Total packet count](/assets/img/thm-Wireshark-The-Basics-room-info/no-of-packets.png)
- **SHA256 hash of the capture file:** `f446de335565fb0b0ee5e5a3266703c778b2f3dfad7efeaeccb2da5641a6d6eb`
  ![SHA256 hash](/assets/img/thm-Wireshark-The-Basics-room-info/1-sha256-hash.png)

This is a habit worth carrying into real investigations — always record the file's hash and total packet count before analysis, both for chain-of-custody and to sanity-check filtered results later.

---

## Step 2 — Packet Dissection (OSI Layer Breakdown)

Packet 38 was used to walk through Wireshark's layer-by-layer breakdown of an HTTP response:

![Jumping to packet 38](/assets/img/thm-Wireshark-The-Basics-room-info/go-to-38.png)

| Field | Value |
|---|---|
| Markup language in the HTTP body | eXtensible Markup Language |
| Arrival date | 05/13/2004 |
| Time To Live (TTL) | 47 |
| TCP payload size | 424 bytes |
| ETag | `9a01a-4696-7e354b00` |

- **Markup language in the HTTP body:** `eXtensible Markup Language`
  ![Markup language in HTTP body](/assets/img/thm-Wireshark-The-Basics-room-info/markup.png)
- **Arrival date:** `05/13/2004`
  ![Arrival date](/assets/img/thm-Wireshark-The-Basics-room-info/date.png)
- **Time To Live (TTL):** `47`
  ![TTL value](/assets/img/thm-Wireshark-The-Basics-room-info/TTL.png)
- **TCP payload size:** `424 bytes`
  ![TCP payload size](/assets/img/thm-Wireshark-The-Basics-room-info/payload.png)
- **ETag:** `9a01a-4696-7e354b00`
  ![ETag value](/assets/img/thm-Wireshark-The-Basics-room-info/eTag.png)

Each of these came from expanding a different layer in the packet details pane — Frame (arrival time), IP (TTL), TCP (payload size), and HTTP (ETag) — reinforcing how a single packet carries independently inspectable data at every layer of the stack.

---

## Step 3 — Packet Navigation & Search

Using **Ctrl+F** (Find Packet) with a "Packet details" / String search:

![Searching for r4w string](/assets/img/thm-Wireshark-The-Basics-room-info/r4w-search.png)
![r4w match highlighted](/assets/img/thm-Wireshark-The-Basics-room-info/r4w-1.png)

- Searching `r4w` located the artist name string → **`r4w8173`**

![Artist 1 field](/assets/img/thm-Wireshark-The-Basics-room-info/artist-1.png)
![Number of artist entries](/assets/img/thm-Wireshark-The-Basics-room-info/number-of-artist.png)
![Second artist entry](/assets/img/thm-Wireshark-The-Basics-room-info/2nd-artist.png)

- Jumping to **packet 12** and reading the packet comment gave a decoy string (`This_is_Not_a_Flag`), which was a deliberate red herring in the room

![Packet 12 comment](/assets/img/thm-Wireshark-The-Basics-room-info/packet-12.png)
![Hint on packet comments](/assets/img/thm-Wireshark-The-Basics-room-info/hint-1.png)

Using **File → Export Objects → HTTP**, a `.txt` file embedded in the traffic was located and read as ASCII art — revealing the hidden name **`PACKETMASTER`**.

![Searching for the .txt file](/assets/img/thm-Wireshark-The-Basics-room-info/search-.txt.png)
![Full text result](/assets/img/thm-Wireshark-The-Basics-room-info/txt-result.png)
![Locating note.txt](/assets/img/thm-Wireshark-The-Basics-room-info/search-note-txt.png)
![Scrolling to the reassembled HTTP response](/assets/img/thm-Wireshark-The-Basics-room-info/scroll-down-and-double-click-response.png)
![Clicking the line-based text data field](/assets/img/thm-Wireshark-The-Basics-room-info/click-line-based-text.png)
![ASCII art answer — PACKETMASTER](/assets/img/thm-Wireshark-The-Basics-room-info/txt-answer.png)

Checking **Analyze → Expert Information** surfaced protocol-level anomalies, most notably **1636 warnings** (illegal characters in HTTP header names).

![Expert Information — errors](/assets/img/thm-Wireshark-The-Basics-room-info/error.png)
![Expert Information — warning count](/assets/img/thm-Wireshark-The-Basics-room-info/no-of-error.png)

---

## Step 4 — Extracting an Embedded File

Packet **39765** contained a JPEG hidden inside HTTP traffic. Rather than using Export Objects, this one was pulled manually to demonstrate the alternate method:

![Packet 39765 — JPEG layer](/assets/img/thm-Wireshark-The-Basics-room-info/packet-39765.png)

1. Located packet 39765 and expanded the packet details pane
2. Right-clicked the **JPEG File Interchange Format** layer → **Export Packet Bytes**

![Creating the new JPEG file](/assets/img/thm-Wireshark-The-Basics-room-info/create-new-jpeg-file.png)
![Export packet bytes dialog — step 1](/assets/img/thm-Wireshark-The-Basics-room-info/export-1.png)
![Export packet bytes dialog — step 2](/assets/img/thm-Wireshark-The-Basics-room-info/export-2.png)
![Saving to the export path](/assets/img/thm-Wireshark-The-Basics-room-info/export-to.png)

3. Saved the extracted data as `Export.jpeg` to the Desktop
4. Hashed it from the terminal:

```bash
md5sum Export.jpeg
```

**Result:** `911cd574a42865a956ccde2d04495ebf`

![MD5 hash of extracted JPEG](/assets/img/thm-Wireshark-The-Basics-room-info/md5.png)

This matched the answer expected for the packet-12 comment question — a nice reminder that TryHackMe sometimes chains a "read the comment" step to a completely separate technical task (extract-and-hash) elsewhere in the capture.

---

## Step 5 — Packet Filtering

Filtering was applied both by right-click and by typing queries directly into the display filter bar.

![Apply as Filter](/assets/img/thm-Wireshark-The-Basics-room-info/apply-filter.png)

- Right-clicking the HTTP layer in packet 4 → **Apply as Filter → Selected** produced the query `http`
- With that filter active, the status bar showed **1089** displayed packets (1.9% of the total capture)

![Displayed packet count with http filter](/assets/img/thm-Wireshark-The-Basics-room-info/displayed.png)

- Right-clicking the `Follow TCP/HTTP Stream`

![Follow stream feature](/assets/img/thm-Wireshark-The-Basics-room-info/follow-1.png)

- Sreach `artist` and you can find number of artists which is `artist=3`
  ![Follow stream feature](/assets/img/thm-Wireshark-The-Basics-room-info/number-of-artist.png)
- Find the name of 2nd artist `artist=2`
  ![Follow stream feature](/assets/img/thm-Wireshark-The-Basics-room-info/2nd-artist.png)

This is the fastest way to narrow 58,620 packets down to a relevant subset without hand-writing filter syntax — useful during time-pressured triage.


---

## Summary of Findings

| # | Task | Answer / Artifact |
|---|------|--------------------|
| 1 | Capture file comment | `TryHackMe_Wireshark_Demo` |
| 2 | Total packets | 58620 |
| 3 | SHA256 of capture file | `f446de335565fb0b0ee5e5a3266703c778b2f3dfad7efeaeccb2da5641a6d6eb` |
| 4 | Markup language in packet 38 | eXtensible Markup Language |
| 5 | Arrival date (packet 38) | 05/13/2004 |
| 6 | TTL (packet 38) | 47 |
| 7 | TCP payload size (packet 38) | 424 bytes |
| 8 | ETag (packet 38) | `9a01a-4696-7e354b00` |
| 9 | Artist 1 name (string search `r4w`) | `r4w8173` |
| 10 | MD5 of extracted JPEG (packet 39765) | `911cd574a42865a956ccde2d04495ebf` |
| 11 | Hidden alien name in embedded `.txt` | `PACKETMASTER` |
| 12 | Expert Info warning count | 1636 |
| 13 | Filter query from packet 4 (HTTP) | `http` |
| 14 | Displayed packets with `http` filter | 1089 |
| 15 | Filter query for User-Agent field | `http.user_agent` |

---

## Analysis Chain Reconstruction

```
Load Exercise.pcapng
        │
        ▼
Statistics → Capture File Properties
   (hash, packet count, comment)
        │
        ▼
Inspect packet 38 layer-by-layer
   (Frame → IP → TCP → HTTP)
        │
        ▼
Ctrl+F string search ("r4w") → artist name
        │
        ▼
File → Export Objects → HTTP → hidden .txt (ASCII art name)
        │
        ▼
Packet 39765 → right-click JPEG layer → Export Packet Bytes
        │
        ▼
Terminal: md5sum Export.jpeg → confirms packet 12 comment answer
        │
        ▼
Analyze → Expert Information → warning count
        │
        ▼
Right-click HTTP → Apply as Filter → narrow 58,620 → 1089 packets
```

---

## Takeaways

- **Metadata first, packets second** — capture file properties (hash, comments, packet counts) should always be the first stop; they anchor the rest of the investigation and matter for evidentiary integrity.
- **Export Objects vs. manual byte export** — both retrieve embedded files, but manual export (right-click a specific layer → Export Packet Bytes) is useful when the file's protocol isn't one of the five Wireshark natively supports for Export Objects (DICOM, HTTP, IMF, SMB, TFTP).
- **Apply as Filter is the fastest triage tool** — clicking instead of typing filter syntax reduces error and speeds up narrowing large captures during time-boxed analysis.
- **Expert Information is a lead generator, not a verdict** — 1636 warnings doesn't mean 1636 problems; it's a prioritized list of anomalies worth manually reviewing.
