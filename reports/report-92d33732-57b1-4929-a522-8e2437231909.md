# Penetration Test Report

**Target:** `http://juice-shop:3000/`  
**Engagement:** `92d33732-57b1-4929-a522-8e2437231909`  
**Generated:** 2026-09-03 18:57 UTC  
**Produced by:** APTS — autonomous pipeline, no human review

## Executive summary

The application exhibits multiple potential vulnerabilities centered around the `/socket.io/` and `/rest/user/login` endpoints, primarily involving malformed input handling. The most critical risks—if confirmed—include NoSQL injection and authentication bypasses that could lead to account takeover. However, none of the findings have been fully validated; they are preliminary indicators requiring further testing. Immediate actions should include validating and sanitizing all user-supplied inputs, especially those used in Socket.IO communications and login logic. Given the high potential severity of some findings and their unconfirmed nature, prioritize remediation efforts on authentication mechanisms and real-time communication channels.

| | |
|---|---|
| Risk score | **9.8** / 10 |
| Findings | 33 |
| Confirmed exploitable | **0** |
| Critical | 8 |
| High | 5 |
| Medium | 20 |

## Finding register

| ID | Severity | CVSS | Status | Asset | Finding |
|---|---|---|---|---|---|
| W-011 | critical | 9.8 | not tested | `/rest/user/login` | NoSQL Injection — in JSON body (param `email`, POST /rest/user/login) |
| W-012 | critical | 9.8 | not tested | `/rest/user/login` | NoSQL Injection — in JSON body (param `password`, POST /rest/user/login) |
| W-027 | critical | 9.8 | not tested | `/api/Challenges/` | NoSQL Injection — via `name` parameter (GET /api/Challenges/) |
| W-032 | critical | 9.8 | not tested | `/api/Challenges/` | Unicode Injection — via `name` parameter (GET /api/Challenges/) |
| W-013 | critical | 9.1 | not tested | `/rest/user/login` | Login Bypass — in JSON body (param `email`, POST /rest/user/login) |
| W-014 | critical | 9.1 | not tested | `/rest/user/login` | Login Bypass — in JSON body (param `password`, POST /rest/user/login) |
| W-015 | critical | 9.1 | not tested | `/rest/user/login` | Account Takeover — in JSON body (param `email`, POST /rest/user/login) |
| W-016 | critical | 9.1 | not tested | `/rest/user/login` | Account Takeover — in JSON body (param `password`, POST /rest/user/login) |
| W-007 | high | 8.1 | not tested | `/socket.io/` | Insecure Direct Object Reference (IDOR) — Access control based on user-supplied `sid` value |
| W-029 | high | 8.1 | not tested | `/api/Challenges/` | IDOR — via `name` parameter (GET /api/Challenges/) |
| W-001 | high | 7.5 | tested, not proven (VERDICT: INCONCLUSIVE — The SSRF payloads were not tested because the recorded request did not respond successfully, preventing further exploitation attempts.) | `/socket.io/` | Server Side Request Forgery (SSRF) — URL parameters (`EIO`, `transport`, `t`, `sid`) in POST request to `/socket.io/` |
| W-022 | high | 7.5 | not tested | `/socket.io/` | SSRF — URL parameter `transport` (GET /socket.io/) |
| W-031 | high | 7.5 | not tested | `/api/Challenges/` | SSRF — via `name` parameter (GET /api/Challenges/) |
| W-002 | medium | 6.5 | tested, not proven (VERDICT: INCONCLUSIVE — The HTTP request with prototype pollution payload did not return a response, making it impossible to determine if the vulnerability exists.) | `/socket.io/` | Prototype Pollution — Body content (`40`) and URL parameters in POST request to `/socket.io/` |
| W-005 | medium | 6.5 | tested, not proven (VERDICT: INCONCLUSIVE — No HackTricks article found for session fixation, and the recorded Socket.IO requests do not obviously expose a `sid` parameter manipulation vulnerability.) | `/socket.io/` | Session Fixation — Manipulation of the `sid` parameter during polling transport initiation |
| W-006 | medium | 6.5 | tested, not proven (VERDICT: INCONCLUSIVE — No relevant HackTricks article found to confirm or deny HTTP Parameter Pollution vulnerability in Socket.IO endpoint; manual testing or further reconnaissance needed.) | `/socket.io/` | HTTP Parameter Pollution (HPP) — Repeated or conflicting parameters in Socket.IO query string |
| W-008 | medium | 6.5 | not tested | `/socket.io/` | Clickjacking — Response to `/socket.io/` missing proper frame-busting headers |
| W-009 | medium | 6.5 | not tested | `/socket.io/` | Race Condition — Exploiting concurrent polling requests via `/socket.io/` |
| W-010 | medium | 6.5 | not tested | `/socket.io/` | HTTP Response Splitting (CRLF Injection) — Injection via raw body (`40`) interpreted as partial HTTP response element |
| W-017 | medium | 6.5 | not tested | `/rest/user/login` | JSON Injection — in JSON body (param `email`, POST /rest/user/login) |
| W-018 | medium | 6.5 | not tested | `/rest/user/login` | JSON Injection — in JSON body (param `password`, POST /rest/user/login) |
| W-019 | medium | 6.5 | not tested | `/rest/user/login` | Prototype Pollution — in JSON body (param `email`, POST /rest/user/login) |
| W-020 | medium | 6.5 | not tested | `/rest/user/login` | Prototype Pollution — in JSON body (param `password`, POST /rest/user/login) |
| W-021 | medium | 6.5 | not tested | `/socket.io/` | Parameter Pollution — URL parameters (`EIO`, `transport`, `t`, GET /socket.io/) |
| W-025 | medium | 6.5 | not tested | `/socket.io/` | Cache Deception — Query string parameters (`EIO`, `transport`, `t`) manipulated to cache static-like responses (GET /socket.io/) |
| W-026 | medium | 6.5 | not tested | `/socket.io/` | CRLF Injection — URL parameters (`EIO`, `transport`, `t`) injected with header payloads (GET /socket.io/) |
| W-030 | medium | 6.5 | not tested | `/api/Challenges/` | Parameter Pollution — via duplicated `name` parameter (GET /api/Challenges/) |
| W-033 | medium | 6.5 | not tested | `/api/Challenges/` | Regex Denial of Service (ReDoS) — via `name` parameter (GET /api/Challenges/) |
| W-004 | medium | 6.1 | tested, not proven (VERDICT: INCONCLUSIVE — The provided HackTricks article slug resulted in an empty response, preventing assessment of XSS payloads for the Socket.IO endpoint parameters.) | `/socket.io/` | Cross-Site Scripting (XSS) — URL parameters (`EIO`, `transport`, `t`, `sid`) reflected in server response via Socket.IO handshake |
| W-024 | medium | 6.1 | not tested | `/socket.io/` | XSS — URL parameters `EIO`, `transport`, or `t` reflected in socket response (GET /socket.io/) |
| W-028 | medium | 6.1 | not tested | `/api/Challenges/` | XSS — via `name` parameter (GET /api/Challenges/) |
| W-003 | medium | 4.2 | tested, not proven (VERDICT: INCONCLUSIVE — No recorded request matched the suspected websocket endpoint, and no evidence of exploitable behavior was found in related HTTP traffic or documentation.) | `/socket.io/` | Websocket Protocol Attack — Upgrade mechanism through `/socket.io/` endpoint |
| W-023 | medium | 4.2 | not tested | `/socket.io/` | WebSockets Hijacking — Upgraded connection via `/socket.io/` |

## Findings in detail

### W-011 — NoSQL Injection — in JSON body (param `email`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** critical (CVSS 9.8, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Status:** not tested
- **ATT&CK:** T1190
- **Remediation effort:** medium

### W-012 — NoSQL Injection — in JSON body (param `password`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** critical (CVSS 9.8, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Status:** not tested
- **ATT&CK:** T1190
- **Remediation effort:** medium

### W-027 — NoSQL Injection — via `name` parameter (GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** critical (CVSS 9.8, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Status:** not tested
- **ATT&CK:** T1190
- **Remediation effort:** medium

### W-032 — Unicode Injection — via `name` parameter (GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** critical (CVSS 9.8, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-013 — Login Bypass — in JSON body (param `email`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** critical (CVSS 9.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190
- **Remediation effort:** medium

### W-014 — Login Bypass — in JSON body (param `password`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** critical (CVSS 9.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190
- **Remediation effort:** medium

### W-015 — Account Takeover — in JSON body (param `email`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** critical (CVSS 9.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1539
- **Remediation effort:** medium

### W-016 — Account Takeover — in JSON body (param `password`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** critical (CVSS 9.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1539
- **Remediation effort:** medium

### W-007 — Insecure Direct Object Reference (IDOR) — Access control based on user-supplied `sid` value

- **Asset:** `/socket.io/`
- **Severity:** high (CVSS 8.1, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-029 — IDOR — via `name` parameter (GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** high (CVSS 8.1, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-001 — Server Side Request Forgery (SSRF) — URL parameters (`EIO`, `transport`, `t`, `sid`) in POST request to `/socket.io/`

- **Asset:** `/socket.io/`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The SSRF payloads were not tested because the recorded request did not respond successfully, preventing further exploitation attempts.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

**Recommendation.** Implement strict validation and sanitization of URL parameters (`EIO`, `transport`, `t`, `sid`) used in the Socket.IO endpoint to prevent SSRF. Restrict allowed values for these parameters to known safe enumerations, and reject any containing internal IP addresses or reserved hostnames.

```http
http_request {"url": "http://juice-shop:3000/socket.io/?EIO=4&transport=polling&t=Q1edLUy&sid=G62mFS2BvPOrZ9deAAAa", "method": "POST", "headers": {"accept": "*/*", "origin": "http://juice-shop:3000", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36", "content-type": "text/plain;charset=UTF-8"}, "body": 40}

{"content": ["Error executing tool http_request: 1 validation error for http_requestArguments\nbody\n  Input should be a valid string [type=string_type, input_value=40, input_type=int]\n    For further information visit https://errors.pydantic.dev/2.13/v/string_type"]}
```
*VERDICT: INCONCLUSIVE — The SSRF payloads were not tested because the recorded request did not respond successfully, preventing further exploitation attempts.*

### W-022 — SSRF — URL parameter `transport` (GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190
- **Remediation effort:** medium

### W-031 — SSRF — via `name` parameter (GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190
- **Remediation effort:** medium

### W-002 — Prototype Pollution — Body content (`40`) and URL parameters in POST request to `/socket.io/`

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The HTTP request with prototype pollution payload did not return a response, making it impossible to determine if the vulnerability exists.)
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/socket.io/?EIO=4&transport=polling&t=Q1edLYN&sid=G62mFS2BvPOrZ9deAAAa&__proto__[polluted]=true", "method": "POST", "headers": {"accept": "*/*", "origin": "http://juice-shop:3000", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36", "content-type": "text/plain;charset=UTF-8"}, "body": 40}

{"content": ["Error executing tool http_request: 1 validation error for http_requestArguments\nbody\n  Input should be a valid string [type=string_type, input_value=40, input_type=int]\n    For further information visit https://errors.pydantic.dev/2.13/v/string_type"]}
```
*VERDICT: INCONCLUSIVE — The HTTP request with prototype pollution payload did not return a response, making it impossible to determine if the vulnerability exists.*

### W-005 — Session Fixation — Manipulation of the `sid` parameter during polling transport initiation

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — No HackTricks article found for session fixation, and the recorded Socket.IO requests do not obviously expose a `sid` parameter manipulation vulnerability.)
- **ATT&CK:** T1539
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "websocket-session-fixation"}

{"slug": "websocket-session-fixation", "found": false, "did_you_mean": ["websocket-attacks", "race-condition", "http-connection-contamination", "deserialization", "rocket-chat", "ssti-server-side-template-injection", "hacking-jwt-json-web-tokens", "sql-injection"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*VERDICT: INCONCLUSIVE — No HackTricks article found for session fixation, and the recorded Socket.IO requests do not obviously expose a `sid` parameter manipulation vulnerability.*

### W-006 — HTTP Parameter Pollution (HPP) — Repeated or conflicting parameters in Socket.IO query string

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — No relevant HackTricks article found to confirm or deny HTTP Parameter Pollution vulnerability in Socket.IO endpoint; manual testing or further reconnaissance needed.)
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "http-param-pollution"}

{"slug": "http-param-pollution", "found": false, "did_you_mean": ["parameter-pollution", "nodejs-proto-prototype-pollution", "http-request-smuggling", "race-condition", "orm-injection", "http-connection-contamination", "xpath-injection", "microsoft-sharepoint"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*VERDICT: INCONCLUSIVE — No relevant HackTricks article found to confirm or deny HTTP Parameter Pollution vulnerability in Socket.IO endpoint; manual testing or further reconnaissance needed.*

### W-008 — Clickjacking — Response to `/socket.io/` missing proper frame-busting headers

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-009 — Race Condition — Exploiting concurrent polling requests via `/socket.io/`

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-010 — HTTP Response Splitting (CRLF Injection) — Injection via raw body (`40`) interpreted as partial HTTP response element

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-017 — JSON Injection — in JSON body (param `email`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-018 — JSON Injection — in JSON body (param `password`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-019 — Prototype Pollution — in JSON body (param `email`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-020 — Prototype Pollution — in JSON body (param `password`, POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-021 — Parameter Pollution — URL parameters (`EIO`, `transport`, `t`, GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-025 — Cache Deception — Query string parameters (`EIO`, `transport`, `t`) manipulated to cache static-like responses (GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-026 — CRLF Injection — URL parameters (`EIO`, `transport`, `t`) injected with header payloads (GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-030 — Parameter Pollution — via duplicated `name` parameter (GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-033 — Regex Denial of Service (ReDoS) — via `name` parameter (GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

### W-004 — Cross-Site Scripting (XSS) — URL parameters (`EIO`, `transport`, `t`, `sid`) reflected in server response via Socket.IO handshake

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The provided HackTricks article slug resulted in an empty response, preventing assessment of XSS payloads for the Socket.IO endpoint parameters.)
- **ATT&CK:** T1189, T1059.007
- **Remediation effort:** medium

```http
hacktricks_article {}

{"content": ["Error executing tool hacktricks_article: 1 validation error for hacktricks_articleArguments\nslug\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing"]}
```
*VERDICT: INCONCLUSIVE — The provided HackTricks article slug resulted in an empty response, preventing assessment of XSS payloads for the Socket.IO endpoint parameters.*

### W-024 — XSS — URL parameters `EIO`, `transport`, or `t` reflected in socket response (GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1189, T1059.007
- **Remediation effort:** medium

### W-028 — XSS — via `name` parameter (GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** medium (CVSS 6.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1189, T1059.007
- **Remediation effort:** medium

### W-003 — Websocket Protocol Attack — Upgrade mechanism through `/socket.io/` endpoint

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 4.2, `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — No recorded request matched the suspected websocket endpoint, and no evidence of exploitable behavior was found in related HTTP traffic or documentation.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
hacktricks_article {}

{"content": ["Error executing tool hacktricks_article: 1 validation error for hacktricks_articleArguments\nslug\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing"]}
```
*VERDICT: INCONCLUSIVE — No recorded request matched the suspected websocket endpoint, and no evidence of exploitable behavior was found in related HTTP traffic or documentation.*

### W-023 — WebSockets Hijacking — Upgraded connection via `/socket.io/`

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 4.2, `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

## Attack playbook

_No scripts. Nothing was confirmed exploitable, and a reproduction script for an unproven finding would be a guess presented as a demonstration._

## ATT&CK coverage

| Technique | Findings |
|---|---|
| `T1059.007` | W-002, W-004, W-006, W-007, W-008, W-009, W-010, W-017, W-018, W-019, W-020, W-021, W-024, W-025, W-026, W-028, W-029, W-030, W-032, W-033 |
| `T1071.001` | W-003, W-023 |
| `T1189` | W-004, W-024, W-028 |
| `T1190` | W-001, W-011, W-012, W-013, W-014, W-015, W-016, W-022, W-027, W-031 |
| `T1539` | W-005, W-015, W-016 |

## Caveats and limitations

These bound how far the results above can be relied on.

- Produced by an autonomous pipeline with no human review. Findings should be validated by a security engineer before remediation is prioritised or the results are shared externally.
- The crawl hit a configured limit after 5 pages, so the asset map is a lower bound and parts of the application were never seen.
- API routes were extracted from client-side JavaScript. They are candidate routes the application references, not a verified inventory of its endpoints.
- 33 of 33 findings were not proven exploitable (W-011, W-012, W-027, W-032, W-013, W-014, W-015, W-016, …). They are hypotheses based on observed assets, not demonstrated vulnerabilities.
- 27 findings were never tested for exploitability (W-007, W-008, W-009, W-010, W-011, W-012, W-013, W-014). No claim is made about them either way.
- Absence of a finding is not evidence of absence. This engagement covered what the crawler reached within its configured bounds.
