---
title: "TryHackMe: Snapped Phishing Line"
date: 2026-07-08 16:00:00 +0600
categories: [TryHackMe, Phishing Analysis]
tags: [phishing, credential-harvesting, osint, virustotal, cyberchef, phishing-kit, incident-response]
---

![Downloading the phishing kit archive](/assets/img/thm-snapped_phishing_line-walkthrough/download.png)

## Overview

**Room:** [Snapped Phishing Line](https://tryhackme.com/room/snappedphishingline)
**Difficulty:** Medium
**Category:** SOC / Phishing Analysis / Phishing Kit Teardown

Acting as a member of the IT department at **SwiftSpend Financial**, the task was to investigate a phishing incident reported by multiple employees — some of whom had already had their credentials harvested. The investigation included:

1. Email review and pattern matching
2. Malicious attachment inspection
3. Phishing page reconnaissance
4. Exposed phishing kit discovery and teardown
5. Credential log analysis
6. Adversary exfiltration path tracing

This writeup follows the full chain — inbox, to malicious attachment, to spoofed login page, to the exposed phishing kit and exfiltration endpoint behind it.

**Skills demonstrated:** email/header review, isolated-VM browsing, VirusTotal file/domain lookups, `sha256sum`, archive extraction, phishing-kit source review, log analysis, CyberChef decoding, incident-response indicators (IOCs).

---

## Reviewing the Reported Emails

Investigation started in the `phish-emails` folder on the desktop, which contained five reported emails. Each was reviewed individually to identify the recipient and sender pattern.

![Reviewing phishing emails in the phish-emails folder](/assets/img/thm-snapped_phishing_line-walkthrough/to.png)
_Recipient field on the "Quote for Services Rendered" email_

**Recipient of the "Quote for Services Rendered" email:** `William McClean`

---

## Identifying the Adversary's Sending Address

Across the batch, the attacker reused a consistent sending address while varying display names and subjects — a common pattern that becomes obvious once the emails are lined up side by side.

![Sender addresses across the phishing email batch](/assets/img/thm-snapped_phishing_line-walkthrough/other-names.png)
_Comparing sender details across multiple emails in the batch_

**Adversary's sending address:** `Accounts.Payable@groupmarketingonline.icu`

The `.icu` TLD and generic "group marketing online" domain name are typical of cheap, disposable phishing infrastructure — easy to register and easy to burn after a campaign.

---

## Extracting the Redirection URL (Zoe Duncan's Email)

The email addressed to Zoe Duncan carried an `.html` attachment, so I opened and inspected it directly.

![Clicking into the malicious attachment](/assets/img/thm-snapped_phishing_line-walkthrough/att-click.png)
_Opening the attachment for inspection_

The file contained an embedded redirect to an external domain:

![Redirection URL found inside the attachment](/assets/img/thm-snapped_phishing_line-walkthrough/redirect.png)
_Redirect URL embedded in the attachment_

**Root domain of the redirection URL:** `kennaroads.buzz`

---

## Following the Redirect

Opening the redirect in an isolated VM browser landed on a spoofed login page.

![Fake login page opened in the VM browser](/assets/img/thm-snapped_phishing_line-walkthrough/after-click.png)
_Landing page reached after following the redirect_

![Impersonated login page](/assets/img/thm-snapped_phishing_line-walkthrough/double-login.png)
_Close-up of the branding used on the fake login page_

**Impersonated company:** **Microsoft**

This is the actual credential-harvesting step — any credentials entered here go straight to the attacker, not to Microsoft.

---

## Discovering the Exposed Phishing Kit

Phishing kits are frequently deployed sloppily, and attackers often leave their kit's source files browsable on the same server hosting the fake login page. Navigating to `/data` on the phishing server returned a directory listing with the kit archive visible for download.

![Browsing the exposed /data directory](/assets/img/thm-snapped_phishing_line-walkthrough/data-1.png)
_Directory listing exposed at `/data`_

![Archive file found in the directory listing](/assets/img/thm-snapped_phishing_line-walkthrough/data-2.png)
_Phishing kit archive sitting in the open directory_

**Archive file name:** `Update365.zip`

---

## Hashing and Checking the Kit on VirusTotal

The archive was downloaded to the analysis VM and hashed before any further handling — standard practice before touching any unknown file.

```bash
sha256sum Update365.zip
```

_Downloading `Update365.zip` to the VM_

![SHA256 hash of the archive](/assets/img/thm-snapped_phishing_line-walkthrough/hash.png)
_`sha256sum` output for the downloaded archive_

**SHA256:** `ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686`

Submitting the hash to VirusTotal confirmed community detections and provided further context on the archive.

![VirusTotal detection results for the archive](/assets/img/thm-snapped_phishing_line-walkthrough/screencapture-virustotal-gui-file-ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686-details-2026-07-08-15_59_25.png)
_VirusTotal detail page for the phishing kit hash_

| Field | Value |
|---|---|
| Other threat category assigned (besides phishing) | `Trojan` |
| Number of files in the archive | `49` |

Kits this size often bundle far more than a single fake login page — PHP mailers, config files, and sometimes leftover logs from previous victims, which is exactly what turned up next.

---

## Uncovering Captured Credentials in the Log

Digging into `/data/Update365/` on the server surfaced a log file recording every set of credentials submitted to the fake login page.

![Log file showing captured credential submissions](/assets/img/thm-snapped_phishing_line-walkthrough/data-3.png)
_Log entries showing submitted credentials, including a repeat submission_

**User who submitted credentials more than once:** `michael.ascot@swiftspend.finance`

A repeat submission like this is a common tell — the victim likely re-entered their credentials after the fake page failed to redirect properly, and is a strong indicator that this specific individual was compromised in the campaign.

---

## Tracing the Exfiltration Path (submit.php)

Extracting the phishing kit archive and opening `submit.php` revealed how captured credentials actually leave the attacker's server.

```bash
unzip Update365.zip -d Update365/
cat Update365/submit.php
```

![Extracted phishing kit contents, including submit.php](/assets/img/thm-snapped_phishing_line-walkthrough/filename.png)
_Extracted kit contents showing `submit.php`_

![submit.php source revealing the collection address](/assets/img/thm-snapped_phishing_line-walkthrough/send.png)
_`submit.php` mailing captured credentials to the adversary_

**Adversary's credential collection address:** `m3npat@yandex.com`

This confirms the full loop: victim enters credentials on the spoofed Microsoft page → `submit.php` on the attacker's server emails them directly to a Yandex mailbox.

**MITRE ATT&CK mapping:** T1566.002 (Phishing: Spearphishing Link), T1608 (Stage Capabilities), T1114 (Email Collection — via exfil to attacker-controlled mailbox).

---

## Capturing and Decoding the Flag

The phishing URL also had a `flag.txt` file left exposed.

![flag.txt file found on the phishing site](/assets/img/thm-snapped_phishing_line-walkthrough/flag.png)
_`flag.txt` located on the phishing server_

The contents were encoded, so I ran them through CyberChef to decode:

![Encoded flag content](/assets/img/thm-snapped_phishing_line-walkthrough/secrect-flag-1.png)
_Encoded flag value before decoding_

![Decoded flag in CyberChef](/assets/img/thm-snapped_phishing_line-walkthrough/secret-flag2.png)
_Flag after decoding in CyberChef_

**Secret value:** `THM{pL4y_w1Th_tH3_URL}`

---

## Summary of Findings

| Question | Answer |
|---|---|
| Recipient of "Quote for Services Rendered" email | `William McClean` |
| Adversary's sending address | `Accounts.Payable@groupmarketingonline.icu` |
| Root domain of redirection URL | `kennaroads.buzz` |
| Company impersonated by the login page | `Microsoft` |
| Exposed phishing kit archive name | `Update365.zip` |
| Archive SHA256 | `ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686` |
| Additional VirusTotal threat category | `Trojan` |
| Files contained in the archive | `49` |
| User who submitted credentials twice | `michael.ascot@swiftspend.finance` |
| Adversary's credential collection address | `m3npat@yandex.com` |
| Decoded flag | `THM{pL4y_w1Th_tH3_URL}` |

---

## Attack Chain Reconstruction

```
1. Phishing emails sent from Accounts.Payable@groupmarketingonline.icu
   to multiple SwiftSpend Financial employees
2. Email to Zoe Duncan carries an HTML attachment
   → embedded redirect to kennaroads.buzz
3. Redirect leads to a spoofed Microsoft login page
4. Victim credentials submitted to the fake page
   → logged server-side and mailed out via submit.php
5. Kit source (Update365.zip) and credential log left exposed
   on the same server at /data
6. Investigation recovers: kit archive, VirusTotal verdict (Phishing + Trojan),
   a confirmed repeat victim, and the adversary's exfil mailbox
```

---

## Key Takeaways

- **Follow the chain, not just the first hop.** Confirming an email is phishing is only step one — tracing it through the redirect, the fake login page, and the kit behind it turns a single IOC into a full incident narrative.
- **Attackers get sloppy with their own infrastructure.** An open `/data` directory handed over the entire kit, a victim credential log, and the exfiltration script — none of which should have been exposed.
- **Repeat submissions are a victim signal, not just a data point.** Finding `michael.ascot@swiftspend.finance` in the log turns this from an abstract campaign into an actionable incident with a named target.
- **Kit source code is often the fastest path to the adversary's endpoint.** Reading `submit.php` directly gave the exfiltration address — far faster than trying to infer it from network traffic.
- **Always defang IOCs before sharing.** Domains, the archive hash, and the collection email address should all be defanged before going into a ticket or report to avoid accidental clicks or auto-sandboxing.

---

*Room: [TryHackMe – Snapped Phishing Line](https://tryhackme.com/room/snappedphishingline)*
