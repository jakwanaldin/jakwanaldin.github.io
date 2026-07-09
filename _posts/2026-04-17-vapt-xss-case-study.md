---
title: "VAPT Case Study: Reflected & DOM-Based Cross-Site Scripting (XSS)"
date: 2026-04-17 09:00:00 +0600
categories: [VAPT, Web Application Security]
tags: [xss, dom-xss, owasp, penetration-testing, arena-web-security]
---

## Context

This writeup documents Cross-Site Scripting (XSS) findings identified during a structured web application penetration testing engagement I completed as a trainee ethical hacker at **Arena Web Security**. Target details have been redacted — the full confidential report, including proof-of-concept evidence and screenshots, was delivered to Arena Web Security and is retained privately (available on request).

> **Note:** Real target names and live URLs are intentionally omitted. This describes methodology and technique at a technical level only.
{: .prompt-warning }

**Finding:** VULN-003 — Cross-Site Scripting (Reflected & DOM-based)  
**Severity:** High  
**CVSS Score:** 7.4  
**CWE:** CWE-79  
**OWASP Category:** A03:2021 — Injection  
**Scope:** Multiple assessed targets (3 sites)

---

## Vulnerability Overview

Three assessed applications reflected user-supplied input (from search fields and query parameters) directly into the HTML response without output encoding or sanitization. This allowed injected markup to be parsed and executed as active content by the browser.

## Methodology

1. **Input vector identification** — mapped search boxes, keyword filters, and query parameters that echoed input back into the page
2. **Payload construction** — used an SVG-based XSS payload rather than a traditional `<script>` tag, since `<script>` injection is frequently filtered while event-handler-based vectors on non-script tags are often missed:
   ```html
   <svg/onload=prompt(0)//
   ```
3. **URL-encoded delivery** — for query-string-based injection points, the same payload was URL-encoded to survive transmission:
   ```
   %3Csvg%2Fonload%3Dprompt%280%29%2F%2F
   ```
4. **Confirmation** — successful execution was confirmed via a JavaScript `prompt()` dialog rendering in the browser, proving arbitrary script execution in the application's origin

## Why SVG-based Payloads

Many applications filter obvious `<script>` tags but miss that virtually any HTML element with an event handler attribute (`onload`, `onerror`, `onmouseover`, etc.) can execute JavaScript. `<svg onload=...>` is a common bypass because:
- SVG is a legitimate, commonly-allowed HTML element
- The `onload` event fires automatically on render, requiring no user interaction
- Basic keyword-based filters targeting `<script>` don't catch this pattern

## Impact

Cross-Site Scripting of this type enables:
- **Session hijacking** — theft of session cookies/tokens if not protected by `HttpOnly`
- **Credential theft** — injecting fake login forms to phish credentials in-page
- **Defacement** — arbitrary modification of page content as seen by victims
- **Malware delivery** — using the trusted origin to serve malicious scripts to legitimate visitors

Reflected XSS requires a victim to click a crafted link, but DOM-based XSS (confirmed on one target via a `location.search` sink) can be even more subtle, since the vulnerable code path exists entirely client-side and may not appear in server logs at all.

## Remediation Recommended

- Apply context-aware output encoding on all user-supplied data (HTML entity encoding, JS string encoding, URL encoding as appropriate to the output context)
- Implement a strict Content Security Policy (CSP) that disallows inline scripts and unsafe-eval
- Use a templating engine with auto-escaping enabled by default (rather than relying on developers to remember to encode manually)
- Validate and reject unexpected characters (`<`, `>`, `"`, `'`) server-side on all input, in addition to output encoding

---

## MITRE ATT&CK / OWASP Mapping

| Reference | ID |
|---|---|
| CWE | CWE-79 (Improper Neutralization of Input During Web Page Generation) |
| OWASP Top 10 2021 | A03:2021 — Injection |

---

## Key Takeaways

- Never assume `<script>` tag filtering is sufficient — event-handler-based XSS vectors (SVG, `img onerror`, etc.) routinely bypass naive filters.
- DOM-based XSS is easy to miss in a traditional black-box test since it may leave no server-side trace; testing client-side sinks (`innerHTML`, `document.write`, `location.search`) explicitly is essential.
- A single working `prompt(0)` proof-of-concept is enough to prove the vulnerability class — no need to weaponize further to demonstrate impact to a client.

*Full technical evidence and per-target screenshots are documented in the confidential Vulnerability Assessment Report retained by Arena Web Security and available privately on request.*
