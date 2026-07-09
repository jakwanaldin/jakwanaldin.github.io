---
title: "VAPT Case Study: Local File Inclusion (LFI) — Multiple Targets"
date: 2026-04-15 09:00:00 +0600
categories: [VAPT, Web Application Security]
tags: [lfi, web-security, owasp, penetration-testing, arena-web-security]
---

## Context

This writeup documents a Local File Inclusion (LFI) finding identified during a structured web application penetration testing engagement I completed as a trainee ethical hacker at **Arena Web Security**. Target details, URLs, and any extracted data have been redacted or generalized — the full confidential report, including proof-of-concept evidence and screenshots, was delivered to Arena Web Security and is retained privately (available on request for verification, e.g. during interviews).

> **Note:** Real target names, live URLs, and any sensitive output are intentionally omitted from this public writeup. This describes methodology and findings at a technical level only.
{: .prompt-warning }

**Finding:** VULN-001 — Local File Inclusion (LFI)  
**Severity:** Critical  
**CVSS Score:** 9.1  
**CWE:** CWE-22 (Path Traversal)  
**OWASP Category:** A01:2021 — Broken Access Control  
**Scope:** Multiple assessed targets (5 sites) within the authorized engagement

---

## Vulnerability Overview

Several assessed web applications accepted a `page` (or similarly named) GET parameter that was passed directly into a file inclusion function without sanitization or validation. This is a classic PHP anti-pattern where user input controls which server-side file gets loaded and rendered.

## Methodology

1. **Parameter identification** — during reconnaissance, identified GET parameters (`?page=`, `?id=`, etc.) used to dynamically load content
2. **Path traversal testing** — supplied a sequence of directory traversal payloads to attempt escaping the intended directory:
   ```
   ../../../../../../../../../etc/passwd
   ```
3. **Confirmation** — a successful LFI returned the contents of `/etc/passwd`, exposing the full list of system user accounts and default shell configurations

## Impact

Reading `/etc/passwd` alone discloses:
- Full list of system and service accounts
- Default shells and home directories
- Indicators of installed services (e.g. presence of `mysql`, `ftp`, `apache` service accounts)

In more severely misconfigured environments, LFI of this type can be escalated further:
- **Log poisoning** — injecting PHP code into a log file (e.g. via a crafted User-Agent) and then including that log file to achieve Remote Code Execution
- **PHP wrapper abuse** — using `php://filter` to read source code of application files, potentially exposing hardcoded credentials or further vulnerabilities
- **Sensitive file disclosure** — reading application config files, `.env` files, or database connection strings if their paths can be guessed or enumerated

## Remediation Recommended

- Never accept raw user input as a direct file path
- Implement a strict allowlist / ID-to-file mapping layer server-side, rather than resolving user input directly to a filesystem path
- Disable `allow_url_include` and `allow_url_fopen` in `php.ini`
- Apply chroot jails or containerized sandboxing to limit the web server process's filesystem access
- Run regular automated + manual scans for path traversal patterns as part of SDLC

---

## MITRE ATT&CK / OWASP Mapping

| Reference | ID |
|---|---|
| CWE | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| OWASP Top 10 2021 | A01:2021 — Broken Access Control |

---

## Key Takeaways

- LFI is trivial to test for but frequently overlooked — a handful of `../` sequences in a URL parameter is often all it takes.
- The `/etc/passwd` read is the textbook "proof of concept" for LFI, but the real risk is what it enables next (RCE via log poisoning, source disclosure).
- Any application still resolving user input directly to a file path in 2026 is a strong signal that a broader code review is needed, not just a single patch.

*This finding was one of five affected targets identified during this engagement. Full technical evidence, screenshots, and per-target detail are documented in the confidential Vulnerability Assessment Report retained by Arena Web Security and available privately on request.*
