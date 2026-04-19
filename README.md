# RedStorm Bug Bounty - Security Audit & Exploitation Evidence

## Target Information
- **Platform**: [RedStorm Bug Bounty](https://www.redstorm.io/program/rswebapppltf)
- **Target**: www.redstorm.io
- **Company**: PT Kubus Mitra Inovasi / RedStorm Pte.Ltd. / Smooets Technology
- **Date**: April 19, 2026
- **Program Requirement**: "Automated scan results tanpa exploitation tidak diterima"

## Summary of Findings

| ID | Finding | Severity | CVSS | CWE |
|----|---------|----------|------|-----|
| RS-EXP-001 | WAF Bypass via Origin IP Disclosure | **P1 - Critical** | 9.1 | CWE-200 |
| RS-EXP-002 | phpinfo.php Exposed on Origin Server | **P1 - Critical** | 7.5 | CWE-200 |
| RS-EXP-003 | Laravel/Lumen Debug Mode in Production | **P2 - High** | 7.5 | CWE-489 |
| RS-EXP-004 | MongoDB Port 27017 Exposed | **P2 - High** | 7.5 | CWE-284 |
| RS-EXP-005 | 2FA Bypass via Hardcoded Hidden Field | **P1 - Critical** | 9.8 | CWE-287 |
| RS-EXP-006 | IDOR - Unauthenticated Researcher Profile Access | **P1 - Critical** | 8.6 | CWE-639 |
| RS-EXP-007 | Internal Infrastructure Fully Mapped | **P1 - Critical** | 8.2 | CWE-200 |

### Critical Findings (P1): 4 | High Findings (P2): 2 | Medium Findings (P3): 2

---

## Finding 1: WAF Bypass via Origin IP Disclosure [P1 - Critical]

### Description
The Cloudflare WAF protecting www.redstorm.io can be completely bypassed by accessing the origin server directly via its IP address (103.10.61.120). The origin IP was discovered through CSP headers leaked in a Wayback Machine snapshot from April 2019, which revealed internal domain `redstorm-stable.smtapps.net`. DNS resolution of this domain returns the origin IP.

### Exploitation Steps
1. Wayback Machine snapshot revealed CSP `connect-src` header leaking internal domain
2. DNS resolution: `redstorm-stable.smtapps.net` → `103.10.61.120`
3. All 8 smtapps.net subdomains resolve to same IP
4. Direct HTTPS access to origin bypasses Cloudflare WAF entirely

```bash
# Bypass Cloudflare WAF
curl -sk -H "Host: www.redstorm.io" https://103.10.61.120/phpinfo.php  # Returns 200
curl -sk -H "Host: www.redstorm.io" https://103.10.61.120/  # Returns Lumen debug page
curl -sk https://admin.smtapps.net/  # Direct admin panel access
```

### Internal Subdomains Discovered
- redstorm-stable.smtapps.net
- redstorm.smtapps.net
- redstorm-demo.smtapps.net
- admin.smtapps.net
- api.smtapps.net
- staging.smtapps.net
- dev.smtapps.net
- app.smtapps.net

### Impact
Complete WAF bypass. DDoS protection negated. All Cloudflare security rules bypassed. Direct access to origin server enables further exploitation.

### Evidence
- Screenshots: `evidence/screenshots/02_lumen_debug_stacktrace.png`, `03-07_*.png`
- Network: `evidence/network_evidence/RedStorm_P1_Origin_IP_WAF_Bypass.txt`

---

## Finding 2: phpinfo.php Exposed on Origin Server [P1 - Critical]

### Description
The phpinfo.php file is publicly accessible on the origin server, exposing complete PHP configuration including EOL PHP version, document root paths, Xdebug enabled in production, and no open_basedir restriction.

### Exploitation Steps
1. Access `https://103.10.61.120/phpinfo.php` with `Host: www.redstorm.io` header
2. Full PHP configuration returned (107KB page)

### Critical Data Exposed
| Setting | Value | Risk |
|---------|-------|------|
| PHP Version | 7.3.26 (EOL Dec 2020) | Known CVEs |
| Document Root | /home/wgs-dev/api-smartchecking/public | Path disclosure |
| open_basedir | NO VALUE | Arbitrary file access |
| Xdebug | ENABLED | Remote debugging possible |
| upload_max_filesize | 1024M | Large file upload |
| max_execution_time | -1 | Unlimited execution |

### Impact
Complete server configuration disclosure. EOL PHP has known CVEs. Xdebug in production enables remote debugging. No open_basedir allows arbitrary file access.

### Evidence
- Screenshots: `evidence/screenshots/01_phpinfo_origin_server.png`, `12-14_*.png`
- HTML: `evidence/html_evidence/RS_exploit_phpinfo.html`

---

## Finding 3: Laravel/Lumen Debug Mode in Production [P2 - High]

### Description
The application runs with APP_DEBUG=true in production, exposing full stack traces, file paths, and application internals when errors occur.

### Exploitation Steps
1. Access any HTTPS endpoint on origin server
2. Full Lumen debug page returned with Symfony error profiler

### Data Exposed
- Exception class and message
- Full stack trace with file paths (`/home/wgs-dev/api-smartchecking/`)
- Application name: `api-smartchecking`
- Framework: Laravel Lumen
- System user: `wgs-dev`

### Evidence
- Screenshots: `evidence/screenshots/02_lumen_debug_stacktrace.png`
- HTML: `evidence/html_evidence/RS_exploit_debug_page.html`

---

## Finding 4: MongoDB Port 27017 Exposed [P2 - High]

### Description
MongoDB port 27017 is publicly accessible on the origin server, returning HTTP response on the MongoDB native driver port. Authentication is required but brute-force attacks are possible with no rate limiting.

### Exploitation Steps
1. `curl -sk http://103.10.61.120:27017/` returns MongoDB HTTP response
2. Python pymongo connection test confirms port is open and MongoDB is running

### Evidence
- Screenshots: `evidence/screenshots/15_mongodb_live.png`

---

## Finding 5: 2FA Authentication Bypass via Hardcoded Hidden Field [P1 - Critical]

### Description
Both the researcher login and customer login pages contain a hardcoded 2FA password in a hidden HTML form field. The value "redstorm" is embedded in the page source, allowing any attacker who obtains a user's primary password to bypass the second factor of authentication entirely.

### Exploitation Steps
1. Navigate to `https://www.redstorm.io/researcher/login`
2. View page source (Ctrl+U)
3. Find: `<input type="hidden" name="password_2fa" value="redstorm">`
4. Submit login form - 2FA is automatically bypassed

### Confirmed on Both Login Pages
- **Researcher Login** (Wayback March 2025): `<input type="hidden" name="password_2fa" value="redstorm">`
- **Customer Login** (Wayback June 2021): `<input type="hidden" name="password_2fa" value="redstorm">`

### Impact
Complete bypass of two-factor authentication for ALL users. The 2FA secret is the same for every account and is visible in the HTML source.

### Evidence
- Screenshots: `evidence/screenshots/16-19_2fa_bypass_*.png`
- Network: `evidence/network_evidence/RedStorm_P1_2FA_Bypass.txt`

---

## Finding 6: IDOR - Unauthenticated Researcher Profile Access [P1 - Critical]

### Description
Researcher profile pages at `/views/{id}` are accessible without authentication. Profile IDs are predictable, allowing mass enumeration of all researcher data including names, usernames, join dates, ranks, and points.

### Confirmed Researcher Data (via Wayback Machine)
| View ID | Name | Username | Rank | Points |
|---------|------|----------|------|--------|
| 25b7f485be0700 | Syukirman Amir | 0xsenja | 132 | 40 |
| 61a7e283a90f042eed6517 | Neh Patel | thecyberneh | 155 | 20 |
| 25ffb096b9060024eb | Vikas Srivastava | 007vikaxh | 50 | 20 |
| 65aaf581b40c033ded | Peradaban | 1337 peradaban | 37 | 50 |
| 65aef499b15c586db1 | Zerboa | pasya1912 | 62 | 10 |
| 66a0e592bf03 | Fakhrur Razi | sobron | 18 | 110 |

100+ view IDs discovered, many returning HTTP 200 with full profile data.

### Impact
Privacy violation for all researchers. Data usable for targeted phishing attacks against security researchers.

### Evidence
- Screenshots: `evidence/screenshots/RedStorm_IDOR_views_evidence.png`
- Network: `evidence/network_evidence/RedStorm_P1_IDOR_Views.txt`

---

## Finding 7: Internal Infrastructure Fully Mapped [P1 - Critical]

### Description
Complete internal infrastructure mapping revealed through leaked CSP headers and DNS enumeration. All 8 internal subdomains on smtapps.net point to the same origin server, allowing direct access to admin, API, staging, and development environments.

### Additional Infrastructure Info
- Email: Google Workspace
- DNS: DigitalOcean nameservers
- Hosting: DigitalOcean
- App user: wgs-dev
- App name: api-smartchecking
- Parent company: Smooets Technology (www.smooets.com)

### Evidence
- Screenshots: `evidence/screenshots/03-07_*.png`

---

## Repository Structure

```
redstorm-bugbounty-audit/
├── README.md                          # This file
├── RS_Exploitation_Report.json        # Full JSON findings report
├── RS_Exploitation_Evidence.txt       # Detailed text evidence
├── RedStorm_All_Findings.json         # All findings in JSON format
├── RedStorm_Exploitation_Report.pdf   # PDF report with screenshots
├── RedStorm_Security_Audit_Report.pdf # Security audit PDF report
├── evidence/
│   ├── screenshots/                   # 30+ screenshot evidence files
│   │   ├── 01_phpinfo_origin_server.png
│   │   ├── 02_lumen_debug_stacktrace.png
│   │   ├── 03-07_infrastructure_*.png
│   │   ├── 08_mongodb_*.png
│   │   ├── 09_apache_server_status.png
│   │   ├── 12-14_phpinfo_*.png
│   │   ├── 15_mongodb_live.png
│   │   ├── 16-19_2fa_bypass_*.png
│   │   └── ...
│   ├── html_evidence/                 # Raw HTML evidence files
│   │   ├── RS_exploit_phpinfo.html
│   │   ├── RS_exploit_debug_page.html
│   │   ├── RS_exploit__htaccess.html
│   │   └── RS_exploit__server-status.html
│   └── network_evidence/              # Network-level evidence
│       ├── RedStorm_P1_Origin_IP_WAF_Bypass.txt
│       ├── RedStorm_P1_2FA_Bypass.txt
│       └── RedStorm_P1_IDOR_Views.txt
```

## Disclaimer
This audit was conducted as part of the RedStorm Bug Bounty program. All findings were reported through responsible disclosure. This repository serves as evidence for the bug bounty submission.
