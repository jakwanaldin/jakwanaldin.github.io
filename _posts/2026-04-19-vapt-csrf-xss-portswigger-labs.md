---
title: "VAPT Training: CSRF & XSS — PortSwigger Web Security Academy Labs"
date: 2026-04-19 09:00:00 +0600
categories: [VAPT, Web Application Security]
tags: [csrf, xss, portswigger, owasp, penetration-testing, arena-web-security]
---

## Context

This writeup documents 9 labs (5 XSS, 4 CSRF) completed on **PortSwigger's Web Security Academy** as part of structured offensive security training during my time as a trainee ethical hacker at **Arena Web Security**. Unlike the other case studies in this series, these labs run on PortSwigger's own sanctioned, intentionally vulnerable training environment — so there's no confidentiality concern here; this is standard, publicly documented training infrastructure.

**Finding:** VULN-005 — CSRF & XSS (Training Labs)  
**Severity:** Medium (lab context)  
**CVSS Score:** 6.1  
**CWE:** CWE-352 (CSRF) / CWE-79 (XSS)  
**OWASP Category:** A01:2021 / A03:2021  
**Environment:** [portswigger.net/web-security](https://portswigger.net/web-security) — Controlled lab environment

---

## Part 1 — Cross-Site Scripting (5 Labs Solved)

### Lab 1: Reflected XSS into HTML context with nothing encoded
The simplest XSS case — user input is reflected directly into the page's HTML body with zero encoding. A basic `<script>alert(1)</script>` payload in the vulnerable parameter confirms execution.

### Lab 2: Stored XSS into HTML context with nothing encoded
Same lack of encoding, but the payload persists server-side (e.g. in a comment field) and executes for every subsequent visitor who views the page — a significantly higher-impact variant since no victim interaction with a crafted link is required.

### Lab 3: DOM XSS in `document.write` sink using source `location.search`
Client-side only vulnerability — JavaScript on the page takes a value directly from `location.search` (the URL query string) and passes it into `document.write()` without sanitization. Since this never touches the server, it's invisible to server-side logging and requires reviewing client-side JS to catch.

### Lab 4: DOM XSS in `innerHTML` sink using source `location.search`
Similar sink-and-source pattern, but via `innerHTML` instead of `document.write`. Both sinks parse and render injected HTML/JS, making them equally exploitable once the source (URL parameter) is attacker-controlled.

### Lab 5: DOM XSS in jQuery anchor `href` attribute sink using source `location.search`
A jQuery-specific variant — the vulnerable code sets an anchor tag's `href` attribute using unsanitized input from `location.search`. Using a `javascript:` URI scheme as the payload achieves code execution when the link is clicked.

**All 5 labs marked Solved.**

---

## Part 2 — Cross-Site Request Forgery (4 Labs Solved)

### Lab 1: CSRF vulnerability with no defenses
Baseline case — the target endpoint performs a state-changing action (e.g. email change) based solely on the victim's authenticated session cookie, with no CSRF token or other validation. A simple auto-submitting HTML form hosted on an attacker-controlled page is sufficient to forge the request.

### Lab 2: CSRF where token validation depends on request method
The application validates the CSRF token correctly for POST requests, but the same endpoint also accepts GET requests without token validation — allowing the CSRF protection to be bypassed entirely by switching the HTTP method.

### Lab 3: CSRF where token validation depends on token being present
The server validates the token *if one is supplied*, but doesn't reject the request if the token parameter is omitted entirely. Simply removing the token parameter from the forged request bypasses validation.

### Lab 4: CSRF where token is not tied to user session
The application generates and validates CSRF tokens correctly, but any valid token (not just one issued to the victim's specific session) is accepted. An attacker can obtain their own valid token from their own account and use it in the forged request against a victim's session.

**4 of 6 available CSRF labs solved** (2 additional labs — session-unlinked cookie token and duplicated-in-cookie token variants — were part of the broader module but not completed in this training pass).

---

## Key Takeaways

- **XSS sink diversity matters.** `document.write`, `innerHTML`, and jQuery-specific sinks like `.attr('href', ...)` all behave differently and require distinct payload construction — a single generic XSS payload won't catch all variants.
- **DOM-based XSS requires reading client-side JS, not just testing server responses.** These vulnerabilities never touch the server and won't show up in server-side log review.
- **CSRF token implementations fail in predictable, specific ways.** Almost every CSRF bypass in practice comes down to one of: token not required, token not method-enforced, or token not session-bound — testing all three explicitly against any CSRF-protected endpoint is standard practice.
- These lab patterns map directly onto real-world findings — the same "token not tied to session" logic, for example, is exactly the kind of gap manual testing looks for on live client engagements.

---

*This training was completed via PortSwigger's publicly available Web Security Academy — no confidentiality restrictions apply to this content, unlike the client engagement case studies in this series.*
