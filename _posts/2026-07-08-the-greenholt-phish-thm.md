---
title: "TryHackMe: The Greenholt Phish"
date: 2026-07-08 14:00:00 +0600
categories: [TryHackMe, Phishing Analysis]
tags: [phishing, email-analysis, soc, spf, dmarc, bec, header-analysis]
---

![](/assets/img/thm-greenholt_phish-walkthroug/616945d482ef350052080da1-1774407310807.png)

## Overview

**Room:** [The Greenholt Phish](https://tryhackme.com/room/phishingemails5fgjlzxc)
**Difficulty:** Easy
**Category:** SOC / Phishing Analysis / Email Header Forensics

A sales executive at **Greenholt PLC** reported a suspicious email claiming to come from a known customer. The message raised several red flags — a generic greeting, an unexpected request for a money transfer, and an unsolicited attachment — none of which matched the customer's usual communication style. The message was escalated to the SOC for investigation.

This writeup documents the process of triaging the reported `.eml` file: extracting header artifacts, tracing the message back to its originating infrastructure, checking domain authentication records, and analyzing the malicious attachment to determine whether the email is legitimate or a phishing/BEC (Business Email Compromise) attempt.

**Skills demonstrated:** email header analysis, `whois`, SPF/DMARC record interpretation, file-type verification (`file`), `sha256sum`, attachment triage.

---

## Opening the Email Sample

The reported message was provided as `challenge.eml`. Opening it in an email client surfaces the visible headers first — display name, subject, and reply-to — before any deeper header inspection is needed.

---

## Transfer Reference Number

BEC lures frequently embed a specific reference number in the subject line to make the request feel tied to a real, ongoing transaction.

![Transfer reference number in the subject line](/assets/img/thm-greenholt_phish-walkthroug/ref-num.png)
_Reference number pulled from the email subject line_

**Answer:** `09674321`

---

## Display Name vs. Actual Sender Address

The first triage check on any suspicious email: does the friendly "From" name match the actual sending address?

![From header showing display name and sender address](/assets/img/thm-greenholt_phish-walkthroug/from.png)
_The "From" header, showing both the display name and the real address_

| Field | Value |
|---|---|
| Display name | `Mr. James Jackson` |
| Sender's email address | `info@mutawamarine.com` |

Neither the name nor the domain has any obvious connection to a legitimate Greenholt PLC customer — an early indicator this isn't who it claims to be.

---

## Reply-To Address

Attackers commonly set a `Reply-To` header that differs from the `From` address, routing any reply to a mailbox they actually control rather than the (possibly spoofed) sender.

![Reply-To header](/assets/img/thm-greenholt_phish-walkthroug/return-to.png)
_Reply-To header pointing to a different mailbox than the sender address_

**Answer:** `info.mutawamarine@mail.com`

This is a free/generic mail provider address on a completely different domain from the sender — a mismatch worth flagging in any triage.

---

## Tracing the Originating IP

Digging into the message source (`View → Message Source`) surfaces the full `Received` header chain. Tracing it back to the earliest hop reveals the true originating IP.

```
Received: from ... [192.119.71.157]
```

![Originating IP address in the email headers](/assets/img/thm-greenholt_phish-walkthroug/or-ip.png)
_Originating IP extracted from the Received chain_

A `whois` lookup on that IP identified the owning provider:
![IP WHOIS search result](/assets/img/thm-greenholt_phish-walkthroug/name.png)
_Host name fetched from lookup details_

| Field | Value |
|---|---|
| Originating IP | `192.119.71.157` |
| IP owner | `HostPapa` |

HostPapa is a shared hosting/webmail provider — not the kind of enterprise mail gateway expected from a legitimate corporate customer, which further supports the phishing theory.

---

## Checking Domain Authentication (SPF & DMARC)

With the sender domain identified, the next step was checking whether that domain's own authentication policy would have caught this message.

![SPF record lookup](/assets/img/thm-greenholt_phish-walkthroug/SPF.png)
_Full SPF TXT record for the domain_

**SPF record:** `v=spf1 include:spf.protection.outlook.com -all`

The `-all` at the end is a hard fail — mail from IPs not covered by the include should be rejected outright. Since the originating IP belongs to HostPapa rather than Microsoft's mail infrastructure, this message should have failed SPF.

![DMARC record lookup](/assets/img/thm-greenholt_phish-walkthroug/DMARC.png)
_Full DMARC TXT record for the domain_

**DMARC record:** `v=DMARC1; p=quarantine; fo=1`

`p=quarantine` means mail failing DMARC alignment should land in spam/junk rather than the inbox — raising the question of why this reached a real employee at all, and pointing to a possible gap in mail-flow enforcement worth escalating separately.

---

## Attachment Analysis

The final piece of the investigation was the delivery mechanism itself.

![Attachment file name in the email](/assets/img/thm-greenholt_phish-walkthroug/attachment.png)
_Attachment as it appears in the email_

**Attachment file name:** `SWT_#09674321____PDF__.CAB`

The naming mirrors the transfer reference number from the subject line and is styled to look like a PDF — classic social engineering to get the target to open it without hesitation.

Rather than trust the extension, I pulled the hash, size, and true file type:

```bash
sha256sum SWT_#09674321____PDF__.CAB
file SWT_#09674321____PDF__.CAB
```

![SHA256 hash of the attachment](/assets/img/thm-greenholt_phish-walkthroug/sha256.png)
_`sha256sum` output for the attachment_

![File size of the attachment](/assets/img/thm-greenholt_phish-walkthroug/size.png)
_Attachment size_

![Actual file type via file command](/assets/img/thm-greenholt_phish-walkthroug/type.png)
_True file type, revealed with the `file` command_

| Property | Value |
|---|---|
| SHA256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| Size | `400.26 KB` |
| Actual file type | **RAR** (despite the `.CAB` extension) |

The extension mismatch — a file claiming to be a `.CAB` that's actually a RAR archive — is a textbook attempt to smuggle an archive past filters that only inspect the stated extension, while also making the file look less suspicious to the recipient at a glance.

**MITRE ATT&CK mapping:** T1566.001 (Phishing: Spearphishing Attachment), T1036.008 (Masquerading: Masquerade File Type).

---

## Summary of Findings

| Question | Answer |
|---|---|
| Transfer reference number | `09674321` |
| Sender display name | `Mr. James Jackson` |
| Sender's email address | `info@mutawamarine.com` |
| Reply-To address | `info.mutawamarine@mail.com` |
| Originating IP | `192.119.71.157` |
| IP owner | `HostPapa` |
| SPF record | `v=spf1 include:spf.protection.outlook.com -all` |
| DMARC record | `v=DMARC1; p=quarantine; fo=1` |
| Attachment file name | `SWT_#09674321____PDF__.CAB` |
| Attachment SHA256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| Attachment size | `400.26 KB` |
| Actual attachment file type | `RAR` |

---

## Verdict

```
1. Email received impersonating a known customer (spoofed display name)
2. Sender domain and Reply-To domain don't align — replies redirect off-brand
3. Originating IP traced to shared hosting (HostPapa), not the sender's claimed infra
4. SPF (-all) and DMARC (p=quarantine) policies would/should have blocked delivery
5. "PDF" attachment confirmed to be a disguised RAR archive via file-type analysis
```

Every artifact points the same direction: **this is a phishing / BEC attempt**, not a legitimate customer request.

**Recommended next steps:** block the sender domain and originating IP at the gateway, detonate the attachment in a sandbox to confirm payload behavior, and review why this message bypassed the domain's own DMARC quarantine policy.

---

## Key Takeaways

- **Display name ≠ authentication.** A convincing "From" name means nothing without checking the underlying address and domain reputation.
- **Reply-To is an underrated pivot point.** Attackers frequently separate the spoofed sender from the mailbox they actually control — always check both.
- **SPF/DMARC tell you what *should* have happened.** Confirming policy alignment (or the lack of it) helps explain how a malicious message reached the inbox in the first place, and flags a possible mail-flow gap to fix.
- **Never trust a file extension.** A five-second `file` check turned a "PDF" into a RAR archive — exactly the kind of quick verification that should be routine in any attachment triage.

---

*Room: [TryHackMe – The Greenholt Phish](https://tryhackme.com/room/phishingemails5fgjlzxc)*
