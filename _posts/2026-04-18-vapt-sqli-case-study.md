---
title: "VAPT Case Study: Manual Union-Based SQL Injection"
date: 2026-04-18 09:00:00 +0600
categories: [VAPT, Web Application Security]
tags: [sql-injection, union-based, owasp, penetration-testing, arena-web-security]
---

## Context

This writeup documents manual Union-based SQL Injection findings identified during a structured web application penetration testing engagement I completed as a trainee ethical hacker at **Arena Web Security**. Target details and any extracted credentials have been redacted — the full confidential report, including proof-of-concept evidence, was delivered to Arena Web Security and is retained privately (available on request).

> **Note:** Real target names, live URLs, and any extracted data are intentionally omitted. This describes methodology at a technical level only.
{: .prompt-warning }

**Finding:** VULN-004 — SQL Injection (Union-Based, Manual)  
**Severity:** Critical  
**CVSS Score:** 9.4  
**CWE:** CWE-89  
**OWASP Category:** A03:2021 — Injection  
**Scope:** Multiple assessed targets (6 of 10 tested)

---

## Vulnerability Overview

Six of ten assessed applications passed an integer-typed `id` GET parameter directly into a SQL query without parameterization, allowing classic Union-based injection to extract arbitrary data from the backend database — most critically, administrator credentials.

## Methodology

**1. Confirming injectability**

Standard error-based and boolean-based probes (`'`, `id=1 AND 1=1`, `id=1 AND 1=2`) were used first to confirm the parameter was unsanitized and reached the SQL layer.

**2. Determining column count**

Using `ORDER BY` incrementally (or `UNION SELECT NULL,NULL,...`) to determine the exact number of columns returned by the original query — required before a `UNION SELECT` will return cleanly.

**3. Identifying a reflected column**

Once the column count was known, each column position was tested with a marker value to identify which column(s) rendered visibly on the page — this is the column used to exfiltrate data.

**4. Extracting credentials**

With a reflected column identified, the payload was refined to concatenate the target table's username and password fields into that single visible column, using `CONCAT()` with a visible separator for readability:

```sql
id=-77 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,
concat(username,0x3d3d3d3e,password),16,17,18,19,20,21,22,23,24,25
FROM admin_table
```

The `-77` (or similar negative/non-existent ID) forces the original query to return no rows, ensuring only the injected `UNION SELECT` row is displayed — a standard technique to guarantee the injected data renders instead of being buried among real results.

The `0x3d3d3d3e` hex literal renders as `==>` — a simple visual separator making the concatenated username/password pair easy to read directly on the page without needing to inspect raw HTML.

**5. Table/column name enumeration**

Where the exact table or column names were unknown, standard information_schema queries were used to enumerate available tables and columns before building the final extraction payload.

## Impact

Successful extraction of administrator credentials from six separate targets means:
- Direct authentication to admin panels using extracted (and in several cases, cracked) credentials
- Full read/write access to the application's database — customer data, content, configuration
- Depending on database privileges, potential escalation to OS-level command execution via `INTO OUTFILE` (MySQL) or `xp_cmdshell` (MSSQL)
- Any hashed passwords extracted are subject to offline cracking, and any users' credentials reused elsewhere become a broader compromise risk

## Remediation Recommended

- Use parameterized queries / prepared statements for all database interactions — never concatenate user input directly into SQL strings
- Adopt an ORM with built-in injection protections as a structural safeguard
- Apply least-privilege database accounts (the application's DB user should never have permissions beyond what the application strictly needs)
- Deploy a WAF with SQL injection detection rules as a defense-in-depth layer
- Immediately rotate any credentials confirmed to be exposed, and force password resets for affected accounts

---

## MITRE ATT&CK / OWASP Mapping

| Reference | ID |
|---|---|
| CWE | CWE-89 (SQL Injection) |
| OWASP Top 10 2021 | A03:2021 — Injection |

---

## Key Takeaways

- Union-based SQLi is one of the most reliable "quick win" vulnerability classes in manual testing — the column-count-then-reflect methodology is repeatable across almost any vulnerable target.
- `0x3d3d3d3e` (or any hex-encoded separator) is a small trick that makes manual credential extraction dramatically faster to read at a glance.
- Six out of ten tested targets being vulnerable to the same injection class is a strong signal of an industry-wide gap in basic parameterized query hygiene, not an isolated issue.
- Any successful credential extraction should trigger immediate, urgent client notification — this is not a finding to sit on until the final report.

*Full technical evidence, per-target payloads, and extracted-data handling procedures are documented in the confidential Vulnerability Assessment Report retained by Arena Web Security and available privately on request.*
