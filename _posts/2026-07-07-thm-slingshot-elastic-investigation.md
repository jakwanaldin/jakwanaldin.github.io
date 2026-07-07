---
title: "TryHackMe: Slingshot — Elastic Stack Web Attack Investigation"
date: 2026-07-07 10:00:00 +0600
categories: [TryHackMe, DFIR]
tags: [elastic, kibana, siem, log-analysis, web-attack, lfi, brute-force, gobuster, hydra, incident-response]
---

## Overview

**Room:** [Slingshot](https://tryhackme.com/room/slingshot)  
**Difficulty:** Medium  
**Category:** DFIR / Log Analysis / Web Attack Investigation

Slingway Inc., a leading toy company, detected suspicious activity on its e-commerce web server and potential unauthorized modifications to its database. As the investigating analyst, we were given access to an **Elastic Stack (Kibana)** instance containing Apache logs from the suspected compromise period. Slingway's IT team noted the suspicious activity began on **July 26, 2023**.

**Objectives:**
- Identify reconnaissance and enumeration techniques used
- Identify vulnerabilities exploited on the web server
- Determine how the attacker gained administrative access
- Identify what sensitive data was accessed or exfiltrated

**Skills demonstrated:** Elastic/Kibana log analysis, KQL queries, Apache log forensics, web attack chain reconstruction, LFI identification, credential extraction, Base64 decoding with CyberChef.

---

## Environment Setup

Before starting the investigation, two things are essential:

**1. Set the correct Data view** — ensure `apache_logs` is selected as the active Data view in Kibana Discover.

**2. Set the time frame** — configure the time range to `Jul 26, 2023 @ 00:00:00.000 → now` to capture all activity from the date Slingway's IT team flagged as the start of suspicious behaviour.

![Setting the date and time range in Kibana to July 26 2023](/assets/img/thm-slingshot-walkthrough/Setting date and time.png)
_Time range set to July 26, 2023 onwards — capturing the full suspected attack window_

---

## Question 1: What is the Attacker's IP Address?

The first step is identifying the source of the malicious traffic. The logical first instinct is to look for a `source.ip` field — but checking the available fields reveals there is no `source.ip` in this dataset.

![Checking for a source IP field in Kibana — field not available](/assets/img/thm-slingshot-walkthrough/no-source-ip.png)
_No `source.ip` field available — need to look elsewhere_

The hint directs us to look for `transaction.remote_address`, which captures the client IP making requests to the web server. Filtering on this field and sorting by frequency immediately surfaces one IP responsible for the overwhelming majority of web traffic.

![Checking transaction.remote_address for any other address](/assets/img/thm-slingshot-walkthrough/so-checking-for-any-other-address.png)
_`transaction.remote_address` field reveals the dominant traffic source_

_`10.0.2.15` dominates traffic — confirmed as the attacker's IP address_

**Answer: `10.0.2.15`**

---

## Question 2: What is the First Scanner the Attacker Ran?

With the attacker's IP confirmed, the next step is understanding what they did first. The `request.header.UserAgent` field exposes what tools were making requests. Selecting this field and examining the values:

![Selecting the UserAgent field in Kibana](/assets/img/thm-slingshot-walkthrough/select-useragent.png)
_Selecting `request.header.UserAgent` to inspect tool signatures_

Sorting by oldest timestamp first (to find the first tool used), a distinctive User-Agent string stands out — **Nmap Scripting Engine**. This confirms the attacker started with an Nmap scan to identify open ports and services before moving to any exploitation phase.

![Kibana UserAgent field table showing Nmap Scripting Engine](/assets/img/thm-slingshot-walkthrough/useragent-as-table.png)
_Nmap Scripting Engine appears first — the attacker's initial reconnaissance tool_

![Found scanning tool — Nmap Scripting Engine in the logs](/assets/img/thm-slingshot-walkthrough/found-scanning.png)
_Nmap scan confirmed as the first activity against the web server_

**Answer: `Nmap Scripting Engine`**

---

## Question 3: What is the User Agent of the Directory Enumeration Tool?

After the initial Nmap scan, the attacker moved to directory enumeration. Examining the `request.header.UserAgent` field further reveals a second distinct tool:

![Checking UserAgent field for enumeration tool](/assets/img/thm-slingshot-walkthrough/emuration-tool.png)
_Directory enumeration tool User-Agent identified_

The User-Agent string **`Mozilla/5.0 (Gobuster)`** confirms the attacker used Gobuster — a popular directory/file brute-forcing tool — to map out the web server's content structure.

**Answer: `Mozilla/5.0 (Gobuster)`**

---

## Question 4: How Many 404 Responses Did the Attacker Receive?

During Gobuster directory enumeration, the majority of requests return `404 Not Found` responses (paths that don't exist). Filtering on `response.status` and selecting `404`:

![Checking the response status field in Kibana](/assets/img/thm-slingshot-walkthrough/response-status.png)
_Filtering `response.status` to isolate 404 responses_

![Filter showing 404 status responses only](/assets/img/thm-slingshot-walkthrough/filter-status.png)
_404 filter applied — counting the enumeration misses_

The filter returns **1,867 events** — confirming the scale of the Gobuster scan. The attacker tried nearly 2,000 paths before finding valid directories.

**Answer: `1,867`**

---

## Question 5: What Flag Was Discovered During Enumeration?

With Gobuster identified as the enumeration tool, filtering the logs to show only Gobuster traffic lets us see exactly which URLs the tool successfully found (200 responses among the 404 noise):

![Filtering logs by Gobuster User-Agent](/assets/img/thm-slingshot-walkthrough/filter-gobuster.png)
_Filtering to Gobuster requests only_

Switching to full-screen view for better visibility across the URL field:

![Fullscreen view of Kibana for better URL visibility](/assets/img/thm-slingshot-walkthrough/fullscreen.png)
_Fullscreen mode for clearer URL inspection_

Examining the `http.url` field in the Gobuster results reveals a URL containing a flag value embedded in a directory path:

![Flag found in the directory enumeration results](/assets/img/thm-slingshot-walkthrough/flag.png)
_Flag discovered in one of the enumerated directories_

**Answer: `flag=a76637b62ea99acda12f5859313f539a`**

---

## Question 6: What Login Page Did the Attacker Discover?

The attacker used Gobuster to map the web application structure, which led them to a login page. The hint directs us to filter for **401 Unauthorized** responses — these indicate pages that exist but require authentication:

![Login page discovered via directory enumeration](/assets/img/thm-slingshot-walkthrough/login-page.png)
_Filtering for 401 responses surfaces the protected admin login page_

A 401 response on `/admin-login.php` confirms the attacker found the admin panel during enumeration.

**Answer: `/admin-login.php`**

---

## Question 7: What is the User-Agent of the Brute-Force Tool?

After discovering `/admin-login.php`, the attacker pivoted to credential brute-forcing. Examining the `request.header.UserAgent` field for requests targeting the login page reveals a new tool signature:

![Checking UserAgent for brute force tool](/assets/img/thm-slingshot-walkthrough/brute-force.png)
_New User-Agent string associated with login page attack traffic_

The User-Agent **`Mozilla/4.0 (Hydra)`** confirms the attacker used THC-Hydra — one of the most widely used credential brute-forcing tools — against the admin login panel.

**Answer: `Mozilla/4.0 (Hydra)`**

---

## Question 8: What Username:Password Combination Did the Attacker Use?

To find the successful credential, we need to identify the single Hydra request that received a `200 OK` response (successful login) rather than a `401` or `403` (failed attempt). Applying a chain of filters:

- `request.header.UserAgent` contains Hydra
- `http.url` contains `admin-login.php`  
- `response.status` = `200`

![Filters applied for username and password extraction](/assets/img/thm-slingshot-walkthrough/filters-for-usernamepassword.png)
_Stacking filters to isolate the single successful authentication event_

Expanding the matching event and examining the `Authorization` header reveals a Base64-encoded credential string. 
![Results showing 10.0.2.15 as the attacker IP](/assets/img/thm-slingshot-walkthrough/results.png)

Decoding it in CyberChef (`From Base64`) reveals the plaintext credentials:

![Username and password decoded from the authorization header](/assets/img/thm-slingshot-walkthrough/username-password.png)
_Base64-decoded Authorization header revealing the admin credentials_

**Answer: `admin:thx1138`**

---

## Question 9: What Flag Was in the Uploaded File?

With admin access gained via `admin:thx1138`, the attacker moved to the file upload functionality. Filtering for `http.method = POST` and searching for `upload` in the URL field surfaces the upload activity:

![Filtering by POST method and upload in the search bar](/assets/img/thm-slingshot-walkthrough/filter-upload.png)
_POST requests to `/admin/upload.php` identified_

![Upload activity shown in Kibana — upload-1](/assets/img/thm-slingshot-walkthrough/upload-1.png)
_Upload event captured in the logs_

Expanding the event and examining the request body reveals a flag embedded in the uploaded file content:

![Customized upload PHP showing the flag in the request body](/assets/img/thm-slingshot-walkthrough/Customize-upload-php.png)
_Flag found in the uploaded file content_

**Answer: `THM{ecb012e53a58818cbd17a924769ec447}`**

---

## Question 10: What Was the First Command the Attacker Ran Using the Web Shell?

The hint directs us to check the details of the upload event to identify the web shell filename. Examining the previous event's `filename` field:

![Web shell name found in the upload event details](/assets/img/thm-slingshot-walkthrough/webshell-name.png)
_Web shell filename: `easy-simple-php-webshell.php`_

The uploaded web shell is named **`easy-simple-php-webshell.php`**. Searching for this filename in the logs and sorting by oldest timestamp:

![Searching for the web shell in Kibana logs](/assets/img/thm-slingshot-walkthrough/Search-webshell.png)
_Searching for web shell execution events in the logs_

![Hint 5 confirming to investigate the web shell filename](/assets/img/thm-slingshot-walkthrough/hint-5.png)
_Hint confirming the approach: investigate the web shell filename_

![First command executed via the web shell — whoami](/assets/img/thm-slingshot-walkthrough/first-command.png)
_First command run through the web shell revealed in the URL parameters_

The first command passed to the web shell via the URL `cmd` parameter is `whoami` — a standard attacker first move to confirm the web server's running user and current privileges.

**Answer: `whoami`**

---

## Question 11: Which File Was Accessed via LFI to Retrieve Database Credentials?

After confirming execution capability via the web shell, the attacker used Local File Inclusion (LFI) to read sensitive server files. Examining the logs for LFI-pattern URLs (path traversal sequences like `../` or direct file references):

![Checking other logs for LFI database credential access](/assets/img/thm-slingshot-walkthrough/database.png)
_LFI activity captured — file path traversal in the URL parameters_

The logs show the attacker accessed a database configuration file to retrieve credentials:

**Answer: `config-db`**

---

## Question 12: What Database Did the Attacker Export via /phpmyadmin?

With database credentials obtained via LFI, the attacker accessed phpMyAdmin. Searching the logs for `/phpmyadmin` activity and examining the database-related parameters:

![Database exported via phpmyadmin shown in Kibana](/assets/img/thm-slingshot-walkthrough/database-exported.png)
_phpMyAdmin export activity captured in the logs_

The logs reveal the attacker targeted and exported the **`customer_credit_cards`** database — the most sensitive asset on Slingway Inc.'s e-commerce server, containing customer financial data.

**Answer: `customer_credit_cards`**

---

## Question 13: What Flag Did the Attacker Insert into the Database?

Finally, the attacker used `import.php` to insert data (including a flag) into the database. The hint directs us to URL-decode the `request.body` field value. Searching for `import.php` in the logs:

![Import filter applied to find the import.php request](/assets/img/thm-slingshot-walkthrough/import-filter.png)
_Filtering for `import.php` to find the database insertion event_

Expanding the event and examining the `request.body` field, then applying URL decoding in CyberChef, reveals the SQL INSERT statement containing the flag:

![Insert data showing the flag in the request body](/assets/img/thm-slingshot-walkthrough/insert.png)
_URL-decoded request body revealing the inserted flag value_

**Answer: `c6aa3215a7d519eeb40a660f3b76e64c`**

---

## Summary of Findings

| # | Question | Answer |
|---|---|---|
| 1 | Attacker's IP address | `10.0.2.15` |
| 2 | First scanner used | `Nmap Scripting Engine` |
| 3 | Directory enumeration tool User-Agent | `Mozilla/5.0 (Gobuster)` |
| 4 | Total 404 responses during enumeration | `1,867` |
| 5 | Flag found during enumeration | `flag=a76637b62ea99acda12f5859313f539a` |
| 6 | Login page discovered | `/admin-login.php` |
| 7 | Brute-force tool User-Agent | `Mozilla/4.0 (Hydra)` |
| 8 | Credentials used to access admin panel | `admin:thx1138` |
| 9 | Flag in uploaded file | `THM{ecb012e53a58818cbd17a924769ec447}` |
| 10 | First web shell command | `whoami` |
| 11 | File accessed via LFI | `config-db` |
| 12 | Database exported via phpMyAdmin | `customer_credit_cards` |
| 13 | Flag inserted into database | `c6aa3215a7d519eeb40a660f3b76e64c` |

---

## Attack Chain Reconstruction

```
Phase 1 — Reconnaissance
└── Nmap scan (Nmap Scripting Engine) against the web server
    └── Identifies open HTTP port and running services

Phase 2 — Enumeration
└── Gobuster directory brute-force (1,867 × 404 responses)
    ├── Discovers flag in enumerated directory
    └── Discovers /admin-login.php (via 401 response)

Phase 3 — Credential Attack
└── Hydra brute-force against /admin-login.php
    └── Successful login: admin:thx1138

Phase 4 — Exploitation
└── Accesses /admin/upload.php
    └── Uploads easy-simple-php-webshell.php
        └── First command: whoami

Phase 5 — Post-Exploitation
└── LFI via web shell → reads config-db → obtains DB credentials
    └── Accesses /phpmyadmin
        ├── Exports customer_credit_cards database
        └── Inserts flag via import.php
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Active Scanning | T1595 | Nmap scan against the web server |
| Brute Force: Password Spraying | T1110.003 | Hydra credential brute-force on admin panel |
| Exploit Public-Facing Application | T1190 | File upload vulnerability on `/admin/upload.php` |
| Server Software Component: Web Shell | T1505.003 | `easy-simple-php-webshell.php` deployed for RCE |
| File and Directory Discovery | T1083 | Gobuster directory enumeration |
| Unsecured Credentials: Credentials in Files | T1552.001 | LFI used to read `config-db` for database credentials |
| Exfiltration Over Web Service | T1567 | `customer_credit_cards` database exported via phpMyAdmin |
| Data Manipulation | T1565 | Flag inserted into database via `import.php` |

---

## Key Takeaways

- **Kibana's field-level filtering is the analyst's best friend.** Rather than reading thousands of raw log entries, selecting specific fields (`UserAgent`, `response.status`, `http.url`) and filtering on values lets you reconstruct an entire attack chain in minutes. The `transaction.remote_address` field was the key pivot — not the expected `source.ip`.

- **Tool signatures in User-Agent strings are gold.** Nmap, Gobuster, and Hydra all leave distinctive fingerprints in the `UserAgent` field. Any anomalous or tool-like User-Agent in your web logs is an immediate red flag.

- **Follow the HTTP response codes.** 404s in bulk = enumeration. 401s = protected page discovered. A lone 200 among 401s on a login endpoint = successful brute-force. Response codes tell the story without even reading the request content.

- **LFI → config file → database pivot is a classic chain.** Once an attacker has web shell execution, reading configuration files via LFI to obtain database credentials is a standard next step. `config-db` style filenames are always high-value targets.

- **Always URL-decode request bodies.** Attackers frequently URL-encode POST data to obfuscate their actions. CyberChef's `URL Decode` operation is the fastest way to reveal what was actually submitted.

---

*Room: [TryHackMe – Slingshot](https://tryhackme.com/room/slingshot)*
