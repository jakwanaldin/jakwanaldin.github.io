---
title: "VAPT Case Study: Unrestricted File Upload → Web Shell Deployment"
date: 2025-04-16 09:00:00 +0600
categories: [VAPT, Web Application Security]
tags: [file-upload, webshell, rce, owasp, penetration-testing, arena-web-security]
---

## Context

This writeup documents an unrestricted file upload finding leading to web shell deployment, identified during a structured web application penetration testing engagement I completed as a trainee ethical hacker at **Arena Web Security**. Target details and any live exploit paths have been redacted — the full confidential report, including proof-of-concept evidence, was delivered to Arena Web Security and is retained privately (available on request).

> **Note:** Real target name, live shell URL, and command output are intentionally omitted. This describes methodology and impact at a technical level only.
{: .prompt-warning }

**Finding:** VULN-002 — Unrestricted File Upload / Web Shell Deployment  
**Severity:** Critical  
**CVSS Score:** 9.8  
**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)  
**OWASP Category:** A03:2021 — Injection

---

## Vulnerability Overview

The assessed application's file upload functionality did not validate uploaded file extensions or content type server-side, allowing a `.php` file to be uploaded to a web-accessible directory. Once uploaded, the file could be directly requested via URL, causing the web server to execute it as PHP — resulting in full remote code execution.

## Methodology

1. **Upload functionality discovery** — identified a file upload feature during application mapping
2. **Bypass attempt** — uploaded a PHP web shell disguised with a permissive filename/extension, since the server performed no server-side extension validation
3. **Confirmation** — accessed the uploaded file directly via its predictable upload path, confirming the web shell rendered and accepted commands
4. **Reconnaissance via the shell** — used the shell's built-in system information display to confirm:
   - Operating system: Windows Server (build details visible via `phpinfo`-style output)
   - PHP version in use
   - Web server user context and current working directory

## Impact

A functioning, unauthenticated web shell on a production server represents **complete compromise**:
- Arbitrary command execution as the web server user
- Full read/write/delete access to any file the web server process can reach
- Ability to pivot further into the internal network if the host has additional connectivity
- Potential for data exfiltration, backdoor persistence, or ransomware deployment by any attacker who discovers the shell (not just the original tester)

This is precisely why, per the engagement's rules of engagement, this finding was reported to the client **immediately** rather than held for the final report — active web shells left unpatched present ongoing risk to every visitor and to the organization's infrastructure as a whole.

## Remediation Recommended

- Restrict uploads to an explicit allowlist of safe extensions/MIME types; never permit `.php`, `.asp`, `.jsp`, or similar server-executable extensions
- Store all uploaded files outside the web root, or in a directory configured to never execute scripts
- Rename uploaded files server-side (strip original extension/name) and strip execute permissions
- Deploy a Web Application Firewall (WAF) with signatures for common web shell patterns
- Treat any confirmed web shell as an active incident — remove immediately, audit server logs for the full compromise window, and rotate any credentials the server had access to

---

## MITRE ATT&CK / OWASP Mapping

| Reference | ID |
|---|---|
| MITRE ATT&CK | T1505.003 — Server Software Component: Web Shell |
| CWE | CWE-434 |
| OWASP Top 10 2021 | A03:2021 — Injection |

---

## Key Takeaways

- File upload validation must happen server-side — client-side extension checks (or even MIME-type checks alone) are trivially bypassed.
- A web shell isn't just a "finding" — it's a live backdoor the instant it's uploaded. Time-to-remediation matters more here than almost any other vulnerability class.
- Storing uploads inside the web root with execute permissions intact is one of the most consistently exploited misconfigurations across real-world engagements.

*Full technical evidence, screenshots, and the immediate-notification incident timeline are documented in the confidential Vulnerability Assessment Report retained by Arena Web Security and available privately on request.*
