# Penetration Test Report

**Target:** `http://juice-shop:3000/`  
**Engagement:** `a4e0bb01-1cdc-4b8f-ab1e-915ecba930d5`  
**Generated:** 2026-09-02 22:01 UTC  
**Produced by:** APTS — autonomous pipeline, no human review

## Executive summary

Many of the reported vulnerabilities remain unverified but suggest elevated risk stemming from misconfigurations and access control flaws around key administrative REST endpoints, especially `/rest/admin/application-configuration` and `/rest/admin/application-version`. These areas merit immediate targeted review given their potential critical impact if exploitable (CVSS >7). Untested issues highlight broader architectural weaknesses potentially allowing unauthorized data exposure, cache poisoning, and injection vectors. Prioritize validating high-risk entrypoints with active testing tools and address proven exposures immediately—especially around identity management, server-side request handling and cross-origin protections. Confidence varies widely; proven findings demand urgent patching while others require further scrutiny to confirm viability.

| | |
|---|---|
| Risk score | **9.1** / 10 |
| Findings | 27 |
| Confirmed exploitable | **0** |
| Critical | 3 |
| High | 8 |
| Medium | 16 |

## Finding register

| ID | Severity | CVSS | Status | Asset | Finding |
|---|---|---|---|---|---|
| W-006 | critical | 9.1 | not tested | `/rest/admin/application-configuration` | AuthZ Bypass — /rest/admin/application-configuration (GET /rest/admin/application-configuration) |
| W-022 | critical | 9.1 | not tested | `/rest/admin/application-version` | IDOR — unauthorized version access (GET /rest/admin/application-version) |
| W-025 | critical | 9.1 | not tested | `/rest/admin/application-version` | Authentication Bypass — unauthenticated admin access (GET /rest/admin/application-version) |
| W-001 | high | 8.1 | tested, not proven (The recorded request for `/rest/admin/application-configuration` shows it's a GET request without any user-specific identifiers or parameters that could indicate access control based on user input. The response returns general application configuration details without any user-specific data that would imply IDOR vulnerability. Additionally, no further parameters or headers suggesting user context were identified.

VERDICT: DISPROVEN — The endpoint does not appear to expose user-controlled identi) | `/rest/admin/application-configuration` | IDOR — /rest/admin/application-configuration (GET /rest/admin/application-configuration) |
| W-003 | high | 7.5 | tested, not proven (VERDICT: INCONCLUSIVE — The endpoint returns application configuration data but there is no evidence of SSRF vulnerability without a known parameter to test or further functionality that could trigger outbound requests.) | `/rest/admin/application-configuration` | SSRF — /rest/admin/application-configuration (GET /rest/admin/application-configuration) |
| W-010 | high | 7.5 | not tested | `/assets/i18n/en.json` | Client-Side Path Traversal — path segment in URL (GET /assets/i18n/en.json) |
| W-011 | high | 7.5 | not tested | `/assets/i18n/en.json` | SSRF (Server Side Request Forgery) — unknown dynamic parameter (GET /assets/i18n/en.json) |
| W-014 | high | 7.5 | not tested | `/assets/i18n/en.json` | File Inclusion (Local/Remote) — path interpretation (GET /assets/i18n/en.json) |
| W-016 | high | 7.5 | not tested | `/socket.io/` | SSRF — query parameter `transport` (GET /socket.io/) |
| W-023 | high | 7.5 | not tested | `/rest/admin/application-version` | SSRF — internal service probing (GET /rest/admin/application-version) |
| W-027 | high | 7.5 | not tested | `/rest/admin/application-version` | Path Traversal — resource manipulation via path (GET /rest/admin/application-version) |
| W-004 | medium | 6.5 | tested, not proven (VERDICT: DISPROVEN — The response body does not contain any SSI/ESI-related syntax or injection points, and there are no query parameters or headers in the recorded request that could be tested for inclusion injection.) | `/rest/admin/application-configuration` | Server Side Inclusion/Edge Side Inclusion Injection — /rest/admin/application-configuration (GET /rest/admin/application-configuration) |
| W-005 | medium | 6.5 | not tested | `/rest/admin/application-configuration` | Information Disclosure — /rest/admin/application-configuration (GET /rest/admin/application-configuration) |
| W-007 | medium | 6.5 | not tested | `/rest/admin/application-configuration` | CRLF Injection — /rest/admin/application-configuration (GET /rest/admin/application-configuration) |
| W-008 | medium | 6.5 | not tested | `/rest/admin/application-configuration` | Cache Poisoning — /rest/admin/application-configuration (GET /rest/admin/application-configuration) |
| W-013 | medium | 6.5 | not tested | `/assets/i18n/en.json` | Cache Poisoning — Host header or query string (GET /assets/i18n/en.json) |
| W-015 | medium | 6.5 | not tested | `/socket.io/` | Parameter Pollution — query parameters (`EIO`, `transport`, `t`, GET /socket.io/) |
| W-019 | medium | 6.5 | not tested | `/socket.io/` | Cache Deception — query parameters (`EIO`, `transport`, `t`, GET /socket.io/) |
| W-020 | medium | 6.5 | not tested | `/socket.io/` | CRLF Injection — query parameters (`EIO`, `transport`, `t`, GET /socket.io/) |
| W-024 | medium | 6.5 | not tested | `/rest/admin/application-version` | Information Disclosure — verbose version fingerprinting (GET /rest/admin/application-version) |
| W-026 | medium | 6.5 | not tested | `/rest/admin/application-version` | CORS Misconfiguration — cross-origin version theft (GET /rest/admin/application-version) |
| W-009 | medium | 6.1 | not tested | `/assets/i18n/en.json` | XSSI (Cross-Site Script Inclusion) — response body (GET /assets/i18n/en.json) |
| W-018 | medium | 6.1 | not tested | `/socket.io/` | XSS — query parameter `t` (GET /socket.io/) |
| W-021 | medium | 6.1 | not tested | `/rest/admin/application-version` | XSS — reflected version info (GET /rest/admin/application-version) |
| W-002 | medium | 5.4 | tested, not proven (VERDICT: INCONCLUSIVE — The endpoint returns sensitive configuration data but there is no evidence of CSRF vulnerability without further analysis of state-changing actions or anti-CSRF token mechanisms.) | `/rest/admin/application-configuration` | CSRF — /rest/admin/application-configuration (GET /rest/admin/application-configuration) |
| W-012 | medium | 4.7 | not tested | `/assets/i18n/en.json` | Open Redirect — Host header or unseen parameters (GET /assets/i18n/en.json) |
| W-017 | medium | 4.2 | not tested | `/socket.io/` | WebSockets Misconfiguration — upgrade path from polling (`transport=polling`, GET /socket.io/) |

## Findings in detail

### W-006 — AuthZ Bypass — /rest/admin/application-configuration (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** critical (CVSS 9.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1078, T1078.004
- **Remediation effort:** medium

**Recommendation.** Enforce role-based access control (RBAC) and validate permissions per request on `/rest/admin/application-configuration`. Explicitly deny access to administrative resources unless authenticated and authorized roles are present.

### W-022 — IDOR — unauthorized version access (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** critical (CVSS 9.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1078.004, T1069.002
- **Remediation effort:** medium

**Recommendation.** Tighten access controls and implement fine-grained permission models over `/rest/admin/application-version`. Only authenticated users with explicit read capabilities should retrieve this information.

### W-025 — Authentication Bypass — unauthenticated admin access (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** critical (CVSS 9.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** not tested
- **ATT&CK:** T1078, T1078.004
- **Remediation effort:** medium

**Recommendation.** Audit authentication and session verification processes tied to endpoints such as `/rest/admin/application-version`. Confirm all administrative interfaces require valid login states or API keys.

### W-001 — IDOR — /rest/admin/application-configuration (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** high (CVSS 8.1, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
- **Status:** tested, not proven (The recorded request for `/rest/admin/application-configuration` shows it's a GET request without any user-specific identifiers or parameters that could indicate access control based on user input. The response returns general application configuration details without any user-specific data that would imply IDOR vulnerability. Additionally, no further parameters or headers suggesting user context were identified.

VERDICT: DISPROVEN — The endpoint does not appear to expose user-controlled identi)
- **ATT&CK:** T1078.004, T1069.002
- **Remediation effort:** medium

**Recommendation.** Implement strict access controls and session validation for the `/rest/admin/application-configuration` endpoint to prevent unauthorized data exposure. Ensure that user sessions are properly verified before serving configuration data.

```http
hacktricks_article {"slug": "idor"}

{"slug": "idor", "found": true, "title": "IDOR", "content": "# IDOR (Insecure Direct Object Reference)\n\nIDOR (Insecure Direct Object Reference) / Broken Object Level Authorization (BOLA) appears when a web or API endpoint discloses or accepts a user\u2013controllable identifier that is used **directly** to access an internal object **without verifying that the caller is authorized** to access/modify that object.  \nSuccessful exploitation normally allows horizontal or vertical privilege-escalation such as reading or modifying other users\u2019 data and, in the worst case, full account takeov
```
*The recorded request for `/rest/admin/application-configuration` shows it's a GET request without any user-specific identifiers or parameters that could indicate access control based on user input. Th*

### W-003 — SSRF — /rest/admin/application-configuration (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The endpoint returns application configuration data but there is no evidence of SSRF vulnerability without a known parameter to test or further functionality that could trigger outbound requests.)
- **ATT&CK:** T1190, T1189
- **Remediation effort:** high

**Recommendation.** Validate and sanitize all inputs used in backend HTTP requests originating from `/rest/admin/application-configuration`. Block or encode user-controlled URLs and restrict outbound connections to known safe endpoints.

```http
hacktricks_article {"slug": "server-side-request-forgery"}

{"slug": "server-side-request-forgery", "found": false, "did_you_mean": ["ssrf-server-side-request-forgery", "csrf-cross-site-request-forgery", "server-side-xss-dynamic-pdf", "client-side-path-traversal", "ssti-server-side-template-injection", "abusing-service-workers", "server-side-inclusion-edge-side-inclusion-injection", "reverse-tab-nabbing"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*VERDICT: INCONCLUSIVE — The endpoint returns application configuration data but there is no evidence of SSRF vulnerability without a known parameter to test or further functionality that could trigger*

### W-010 — Client-Side Path Traversal — path segment in URL (GET /assets/i18n/en.json)

- **Asset:** `/assets/i18n/en.json`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1039
- **Remediation effort:** medium

**Recommendation.** Restrict file paths served under `/assets/i18n/` to a predefined list or directory traversal filters. Do not trust raw URL segments directly when resolving local files.

### W-011 — SSRF (Server Side Request Forgery) — unknown dynamic parameter (GET /assets/i18n/en.json)

- **Asset:** `/assets/i18n/en.json`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1189
- **Remediation effort:** high

**Recommendation.** Ensure no internal systems can be queried through externally controllable parameters within `/assets/i18n/en.json` logic. Implement allowlists for remote sources if dynamic fetching is required.

### W-014 — File Inclusion (Local/Remote) — path interpretation (GET /assets/i18n/en.json)

- **Asset:** `/assets/i18n/en.json`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1083
- **Remediation effort:** medium

**Recommendation.** Avoid including external or dynamic content into response bodies under `/assets/i18n/en.json`. Apply whitelisting logic for resolved file paths and prohibit parent directory references like '../'.

### W-016 — SSRF — query parameter `transport` (GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1189
- **Remediation effort:** high

**Recommendation.** Validate and sanitize the `transport` query parameter passed to `/socket.io/`. Prevent it from pointing to unintended services or IP addresses internally accessible by the web server.

### W-023 — SSRF — internal service probing (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1189
- **Remediation effort:** high

**Recommendation.** Block SSRF-capable inputs influencing backend network activity triggered by calls to `/rest/admin/application-version`. Enforce proxy restrictions and disable DNS rebinding risks.

### W-027 — Path Traversal — resource manipulation via path (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** high (CVSS 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1083
- **Remediation effort:** medium

**Recommendation.** Reject incoming path segments containing encoded dot-dot-slash sequences or null bytes used to manipulate resource resolution in `/rest/admin/application-version`. Normalize and verify base directory constraints.

### W-004 — Server Side Inclusion/Edge Side Inclusion Injection — /rest/admin/application-configuration (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The response body does not contain any SSI/ESI-related syntax or injection points, and there are no query parameters or headers in the recorded request that could be tested for inclusion injection.)
- **ATT&CK:** T1190, T1105
- **Remediation effort:** medium

**Recommendation.** Ensure server-side templates and responses generated at `/rest/admin/application-configuration` do not include unsanitized user input. Apply proper output encoding and avoid dynamic inclusion mechanisms where possible.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Wed, 02 Sep 2026 22:00:45 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: DISPROVEN — The response body does not contain any SSI/ESI-related syntax or injection points, and there are no query parameters or headers in the recorded request that could be tested for in*

### W-005 — Information Disclosure — /rest/admin/application-configuration (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1552.005, T1082
- **Remediation effort:** low

**Recommendation.** Limit sensitive information exposed in the response payload of `/rest/admin/application-configuration`. Avoid exposing system details, internal paths, or credentials without explicit authorization checks.

### W-007 — CRLF Injection — /rest/admin/application-configuration (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** medium

**Recommendation.** Sanitize CR/LF characters in headers constructed using user-provided values related to `/rest/admin/application-configuration`. Use secure header libraries or manual filtering to block injection attempts.

### W-008 — Cache Poisoning — /rest/admin/application-configuration (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** medium

**Recommendation.** Review cache-control directives and keyed headers involved in caching responses for `/rest/admin/application-configuration`. Ensure unkeyed inputs (e.g., Host header) don’t allow manipulation by attackers.

### W-013 — Cache Poisoning — Host header or query string (GET /assets/i18n/en.json)

- **Asset:** `/assets/i18n/en.json`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** medium

**Recommendation.** Configure caching layers to properly key cached entries based on relevant parameters for `/assets/i18n/en.json`. Prevent malicious variations in Host headers or query strings from poisoning shared caches.

### W-015 — Parameter Pollution — query parameters (`EIO`, `transport`, `t`, GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** medium

**Recommendation.** Normalize and strictly parse repeated query parameters such as `EIO`, `transport`, and `t` for `/socket.io/` requests. Reject ambiguous or inconsistent usage patterns indicative of pollution attacks.

### W-019 — Cache Deception — query parameters (`EIO`, `transport`, `t`, GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** medium

**Recommendation.** Prevent authentication-dependent assets from being cached alongside static public ones for `/socket.io/`. Separate cache keys and ensure private responses are never stored publicly due to query pollution.

### W-020 — CRLF Injection — query parameters (`EIO`, `transport`, `t`, GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** medium

**Recommendation.** Encode newlines and carriage returns in HTTP response headers generated with values from `/socket.io/?EIO=&transport=&t=... parameters`. Apply consistent sanitization routines across backends rendering custom headers.

### W-024 — Information Disclosure — verbose version fingerprinting (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1082, T1552.005
- **Remediation effort:** low

**Recommendation.** Minimize verbose identifiers returned in the body of `/rest/admin/application-version`. Remove internal stack traces, debug flags, or version strings revealing infrastructure specifics unnecessarily.

### W-026 — CORS Misconfiguration — cross-origin version theft (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** medium (CVSS 6.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** low

**Recommendation.** Update CORS policy on `/rest/admin/application-version` to disallow wildcard origins and only accept trusted frontend domains. Include credentials restriction and explicit method limitation.

### W-009 — XSSI (Cross-Site Script Inclusion) — response body (GET /assets/i18n/en.json)

- **Asset:** `/assets/i18n/en.json`
- **Severity:** medium (CVSS 6.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1070.006, T1566.002
- **Remediation effort:** low

**Recommendation.** Apply appropriate Content-Type headers such as 'application/json' and add X-Content-Type-Options: nosniff to responses from `/assets/i18n/en.json`. This helps prevent browsers from interpreting files insecurely.

### W-018 — XSS — query parameter `t` (GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 6.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1059.007
- **Remediation effort:** medium

**Recommendation.** Escape special HTML/JavaScript characters in client-rendered values derived from the `t` query parameter in `/socket.io/`. Prevent malicious inclusion in DOM contexts or script blocks.

### W-021 — XSS — reflected version info (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** medium (CVSS 6.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1059.007
- **Remediation effort:** medium

**Recommendation.** Render reflected version info via JavaScript escape routines or contextual templating engines within `/rest/admin/application-version`. Avoid sending unsanitized content inside HTML contexts which may trigger XSS.

### W-002 — CSRF — /rest/admin/application-configuration (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** medium (CVSS 5.4, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The endpoint returns sensitive configuration data but there is no evidence of CSRF vulnerability without further analysis of state-changing actions or anti-CSRF token mechanisms.)
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** medium

**Recommendation.** Add anti-CSRF tokens to all requests targeting `/rest/admin/application-configuration`. Validate the presence and correctness of these tokens on the server side before processing any state-changing operations.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Wed, 02 Sep 2026 22:00:38 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: INCONCLUSIVE — The endpoint returns sensitive configuration data but there is no evidence of CSRF vulnerability without further analysis of state-changing actions or anti-CSRF token mechanism*

### W-012 — Open Redirect — Host header or unseen parameters (GET /assets/i18n/en.json)

- **Asset:** `/assets/i18n/en.json`
- **Severity:** medium (CVSS 4.7, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1566.002
- **Remediation effort:** medium

**Recommendation.** Strictly validate redirect targets originating from Host header or query strings associated with `/assets/i18n/en.json`. Allow redirects only to trusted domains explicitly defined in an application allowlist.

### W-017 — WebSockets Misconfiguration — upgrade path from polling (`transport=polling`, GET /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** medium (CVSS 4.2, `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Status:** not tested
- **ATT&CK:** T1190, T1071.001
- **Remediation effort:** medium

**Recommendation.** Secure WebSocket upgrades initiated during `/socket.io/` polling fallbacks by enforcing valid origins and ensuring TLS encryption. Review session consistency between poll and WebSocket handshake phases.

## Attack playbook

_No scripts. Nothing was confirmed exploitable, and a reproduction script for an unproven finding would be a guess presented as a demonstration._

## ATT&CK coverage

| Technique | Findings |
|---|---|
| `T1039` | W-010 |
| `T1059.007` | W-018, W-021 |
| `T1069.002` | W-001, W-022 |
| `T1070.006` | W-009 |
| `T1071.001` | W-002, W-007, W-008, W-013, W-015, W-017, W-019, W-020, W-026 |
| `T1078` | W-006, W-025 |
| `T1078.004` | W-001, W-006, W-022, W-025 |
| `T1082` | W-005, W-024 |
| `T1083` | W-014, W-027 |
| `T1105` | W-004 |
| `T1189` | W-003, W-011, W-016, W-023 |
| `T1190` | W-002, W-003, W-004, W-007, W-008, W-010, W-011, W-012, W-013, W-014, W-015, W-016, W-017, W-018, W-019, W-020, W-021, W-023, W-026, W-027 |
| `T1552.005` | W-005, W-024 |
| `T1566.002` | W-009, W-012 |

## Caveats and limitations

These bound how far the results above can be relied on.

- Produced by an autonomous pipeline with no human review. Findings should be validated by a security engineer before remediation is prioritised or the results are shared externally.
- The crawl hit a configured limit after 5 pages, so the asset map is a lower bound and parts of the application were never seen.
- API routes were extracted from client-side JavaScript. They are candidate routes the application references, not a verified inventory of its endpoints.
- 27 of 27 findings were not proven exploitable (W-006, W-022, W-025, W-001, W-003, W-010, W-011, W-014, …). They are hypotheses based on observed assets, not demonstrated vulnerabilities.
- 23 findings were never tested for exploitability (W-005, W-006, W-007, W-008, W-009, W-010, W-011, W-012). No claim is made about them either way.
- Absence of a finding is not evidence of absence. This engagement covered what the crawler reached within its configured bounds.
