# 🎯 Web Application Security Automation Tool

**The Ultimate OWASP Top 10 Security Testing Suite**

Comprehensive web application security testing framework with 90+ automated tools, covering all OWASP Top 10 vulnerabilities.

## 🚀 Features

### 🎨 Beautiful GUI
- **Dark terminal-style interface** - Hacker aesthetic
- **Live terminal output** - Real-time command execution
- **Progress tracking** - Per-phase and overall completion
- **OWASP coverage indicators** - Visual representation of all Top 10
- **Findings panel** - Instant vulnerability alerts
- **One-click tool execution** - Run any tool with single button

### 🔥 90+ Security Tools

**Phase 1: Reconnaissance (12 tools)**
- Subfinder, Sublist3r, Assetfinder, Amass
- SubBrute, X-Recon, SubRabbit
- theHarvester, SpiderFoot, Shodan
- Httpx, Wappalyzer

**Phase 2: Directory Discovery (10 tools)**
- FFUF, Gobuster, Dirsearch
- Dirb, DirBuster, Feroxbuster
- Katana, GAU, Paramspider, Arjun

**Phase 3: Vulnerability Scanning (11 tools)**
- Nuclei (Templates, CVEs, Exposures)
- Nikto, Wapiti, WPScan
- RapidScan, Sn1per, Skipfish
- Argus, Yuki, Nessus support

**Phase 4: SQL Injection (10 tools)**
- SQLMap (Auto, Forms, POST, Headers, Cookies)
- Manual SQLi (Error, Union, Boolean, Time-based)
- NoSQLMap

**Phase 5: XSS Testing (9 tools)**
- XSStrike, PwnXSS, XSS_Vibes
- Dalfox, Kxss
- Manual XSS (Reflected, DOM, Stored)
- XSS Polyglot testing

**Phase 6: IDOR & Access Control (8 tools)**
- Manual IDOR (Numeric, UUID, Parameter Tampering)
- HTTP Methods, Authorization Bypass
- CORS, JWT Analysis, Session Fixation

**Phase 7: Other OWASP Top 10 (12 tools)**
- SSRF, XXE, LFI, RFI
- CSRF, Open Redirect
- Command Injection, SSTI
- Security Headers, Sensitive Data Exposure

**Phase 8: Authentication (8 tools)**
- Hydra (HTTP Form, Basic Auth, SSH, FTP)
- FFUF (Parameter Fuzzing, Username Enum)
- Wapiti Auth Testing, Default Credentials

**Phase 9: Exploit Search (7 tools)**
- SearchSploit (Local, Update, CVE)
- Nuclei CVE Verification
- Manual CVE testing

### 🎯 Complete OWASP Top 10 Coverage

1. **A01:2021 - Broken Access Control**
   - ✅ IDOR testing (Numeric, UUID, Parameter manipulation)
   - ✅ Authorization bypass techniques
   - ✅ JWT token analysis
   - ✅ Session security testing

2. **A02:2021 - Cryptographic Failures**
   - ✅ CORS misconfiguration
   - ✅ Security headers check
   - ✅ Sensitive data exposure

3. **A03:2021 - Injection**
   - ✅ SQL Injection (Error, Union, Boolean, Time-based)
   - ✅ NoSQL Injection
   - ✅ XSS (Reflected, DOM, Stored)
   - ✅ XXE, LFI, RFI, Command Injection, SSTI

4. **A04:2021 - Insecure Design**
   - ✅ Manual testing methodologies
   - ✅ Logic flaw detection

5. **A05:2021 - Security Misconfiguration**
   - ✅ Nuclei misconfiguration templates
   - ✅ Default credentials testing
   - ✅ Exposed files (.git, .env, web.config)

6. **A06:2021 - Vulnerable Components**
   - ✅ SearchSploit integration
   - ✅ Nuclei CVE templates
   - ✅ Technology detection

7. **A07:2021 - Authentication Failures**
   - ✅ Hydra brute force
   - ✅ Username enumeration
   - ✅ Session fixation

8. **A08:2021 - Software & Data Integrity**
   - ✅ File upload testing
   - ✅ Integrity verification

9. **A09:2021 - Logging Failures**
   - ✅ Manual verification required

10. **A10:2021 - SSRF**
    - ✅ AWS metadata exploitation
    - ✅ Internal network access
    - ✅ URL parameter testing

## 📦 Installation

### Quick Install (Recommended)
```
# 1. Download all files to a directory
cd ~
mkdir WebSec_Automation
cd WebSec_Automation
chmod +x install_web.sh
chmod +x WebSecMaster.sh
./install_web.sh
source ~/.bashrc
```

### Manual Installation
```bash
# System dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-tk git golang-go
```
## 🎮 Usage

### GUI Mode (Recommended)
```
python3 WebSec.py
sudo ./WebSecMaster.sh -t target.com
```

**Features:**
1. **Enter target** in the input field
2. **Click phase cards** to expand tool lists
3. **Click ▶ RUN** button to execute individual tools
4. **Monitor live output** in terminal panel
5. **View findings** in real-time
6. **Export reports** when complete

### CLI Full Automation Mode
```bash
# Basic scan
./WebSecMaster.sh -t target.com

# With custom output directory
./WebSecMaster.sh -t target.com -o ~/scans/target_scan

# With Discord notifications
./WebSecMaster.sh -t target.com \
    -d "https://discord.com/api/webhooks/YOUR_WEBHOOK"

# Full automation with all options
./WebSecMaster.sh -t target.com \
    -o ~/results/target \
    -d "https://discord.com/api/webhooks/..." \
    -T "TELEGRAM_BOT_TOKEN:CHAT_ID"
``````
results/
├── subdomains/
│   ├── subfinder.txt
│   ├── sublist3r.txt
│   ├── amass.txt
│   ├── all_subdomains.txt      # Merged & deduplicated
│   └── live_hosts.txt           # Active hosts only
├── urls/
│   ├── katana.txt
│   ├── gau.txt
│   ├── paramspider.txt
│   └── all_urls.txt
├── vulns/
│   ├── nuclei_all.txt           # All Nuclei findings
│   ├── nuclei_cve.txt           # CVE-specific
│   ├── nikto.txt
│   └── wpscan.txt
├── sqli/
│   ├── target_urls.txt
│   ├── sqlmap_results/
│   └── possible_sqli.txt
├── xss/
│   ├── dalfox.txt
│   ├── kxss.txt
│   └── reflected_xss.txt
├── idor/
│   └── test_results/
├── misc/
│   ├── ssrf_tests.html
│   ├── lfi_tests.html
│   ├── security_headers.txt
│   └── exposed_files/
└── reports/
    └── scan_report_YYYYMMDD_HHMMSS.html
```

## 🤖 Automation Examples

### Cronjob (Daily Scans)
```bash
# Edit crontab
crontab -e

# Run 
 ./WebSecMaster.sh -t target.com -d "DISCORD_WEBHOOK" >> ~/scan.log 2>&1
```

### Multiple Targets
```bash
# Create targets file
cat > targets.txt <<EOF
target1.com
target2.com
target3.com
EOF

# Scan all targets
while read target; do
    ./WebSecMaster.sh -t "$target" -o "results_$target"
    sleep 300  # Wait 5 minutes between scans
done < targets.txt
```
## 🎯 Pro Tips

### Time Management Strategy
- **2-4 hours**: Phase 1-3 only (Recon + Vuln Scan)
- **4-6 hours**: Phase 1-5 (Add SQLi + XSS)
- **8+ hours**: Full pipeline (all 9 phases)
- **Weekend project**: Full scan + manual verification

### High-Value Targets
1. **Admin panels**: `/admin`, `/wp-admin`, `/administrator`
2. **Exposed configs**: `/.git/config`, `/.env`, `/web.config`
3. **API endpoints**: `/api/v1/`, `/graphql`, `/rest/`
4. **Upload pages**: File upload with improper validation
5. **Password reset**: Password reset token manipulation

### False Positive Filtering
```bash
# Remove low-severity findings
cat results/vulns/nuclei_all.txt | \
    grep -v "info" | \
    grep -v "low" > results/vulns/filtered_findings.txt

# Extract only critical/high
grep -E "critical|high" results/vulns/nuclei_all.txt > results/vulns/priority_findings.txt
```

### Reporting Priority
1. **Critical**: RCE, SQLi (with data access), Auth Bypass
2. **High**: Stored XSS, CSRF, IDOR (sensitive data)
3. **Medium**: Reflected XSS, Information Disclosure
4. **Low**: Missing headers, Version disclosure

## 🔧 Troubleshooting

### Tools Not Found
```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify Go installation
go version
which subfinder httpx nuclei
```

### GUI Not Opening
```bash
# Install tkinter
sudo apt install python3-tk

# Check Python version (needs 3.7+)
python3 --version

# Test tkinter
python3 -c "import tkinter"
```

### Nuclei Templates Not Updating
```bash
# Manual update
nuclei -update-templates

# Force update
rm -rf ~/nuclei-templates
nuclei -update-templates
```

## 📝 Database Queries

The GUI stores all results in SQLite. Query them:

```bash
# Open database
sqlite3 web_v3.db

# Get all scans
SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT 10;

# Get vulnerabilities by severity
SELECT severity, COUNT(*) FROM vulnerabilities 
GROUP BY severity 
ORDER BY CASE severity 
    WHEN 'critical' THEN 1 
    WHEN 'high' THEN 2 
    WHEN 'medium' THEN 3 
    ELSE 4 
END;

# Get recent critical findings
SELECT * FROM vulnerabilities 
WHERE severity='critical' 
ORDER BY timestamp DESC;

# Get findings by OWASP category
SELECT owasp_cat, COUNT(*) FROM vulnerabilities 
GROUP BY owasp_cat;
```
### Legal Use Cases:
- ✅ Bug bounty programs with clear scope
- ✅ Your own websites and applications
- ✅ Client pentests with written authorization
- ✅ Educational purposes in isolated lab environments

### ILLEGAL Activities:
- ❌ Scanning websites without permission
- ❌ Exploiting vulnerabilities without authorization
- ❌ Accessing data you don't own
- ❌ Using tools for malicious purposes

### Learning Materials
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)

## 📊 Statistics

**Total Tools**: 90+
**OWASP Coverage**: 100% (All Top 10)
**Phases**: 9
**Estimated Scan Time**: 8-20 hours (full pipeline)
**False Positive Rate**: ~15% (varies by target)

## 💬 Support
- **Linkedin**: https://www.linkedin.com/in/rasitsezginn/



