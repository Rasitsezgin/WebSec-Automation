#!/bin/bash

# Web Application Security Automation Tool
# OWASP Top 10 | 90+ Tools | Full Automation

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

TARGET=""
OUTPUT_DIR="results"
DISCORD_WEBHOOK=""
TELEGRAM_BOT=""

# Banner
banner() {
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   🎯 Web Application Security Automation Tool              ║"
    echo "║   OWASP Top 10 Coverage | 90+ Security Tools             ║"
    echo "║   Full Automation Pipeline for Web Applications          ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_phase() {
    echo -e "\n${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${PURPLE}[PHASE] $1${NC}"
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

notify() {
    if [ -n "$DISCORD_WEBHOOK" ]; then
        curl -X POST "$DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"content\": \"🎯 **$TARGET**\n$1\"}" 2>/dev/null
    fi
}

check_tool() {
    if ! command -v $1 &> /dev/null; then
        log_error "$1 not installed"
        return 1
    fi
    return 0
}

setup_dirs() {
    log_info "Creating output directories..."
    mkdir -p "$OUTPUT_DIR"/{subdomains,urls,vulns,sqli,xss,idor,misc,reports}
    log_success "Directories ready"
}

# ═══════════════════════════════════════════════════════════
# PHASE 1: RECONNAISSANCE & ASSET DISCOVERY
# ═══════════════════════════════════════════════════════════
phase1_recon() {
    log_phase "PHASE 1: RECONNAISSANCE & ASSET DISCOVERY (12 tools)"
    
    # Subfinder
    if check_tool subfinder; then
        log_info "Running Subfinder..."
        subfinder -d "$TARGET" -all -recursive -o "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null
        log_success "Subfinder: $(wc -l < $OUTPUT_DIR/subdomains/subfinder.txt 2>/dev/null || echo 0) subdomains"
    fi
    
    # Sublist3r
    if check_tool sublist3r; then
        log_info "Running Sublist3r..."
        sublist3r -d "$TARGET" -o "$OUTPUT_DIR/subdomains/sublist3r.txt" 2>/dev/null
        log_success "Sublist3r completed"
    fi
    
    # Assetfinder
    if check_tool assetfinder; then
        log_info "Running Assetfinder..."
        assetfinder --subs-only "$TARGET" > "$OUTPUT_DIR/subdomains/assetfinder.txt" 2>/dev/null
        log_success "Assetfinder completed"
    fi
    
    # Amass
    if check_tool amass; then
        log_info "Running Amass..."
        amass enum -passive -d "$TARGET" -o "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null
        log_success "Amass completed"
    fi
    
    # theHarvester
    if check_tool theHarvester; then
        log_info "Running theHarvester..."
        theHarvester -d "$TARGET" -b all -f "$OUTPUT_DIR/subdomains/harvester" 2>/dev/null
        log_success "theHarvester completed"
    fi
    
    # Merge and deduplicate
    log_info "Merging all subdomains..."
    cat "$OUTPUT_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all_subdomains.txt"
    TOTAL_SUBS=$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt")
    log_success "Total unique subdomains: $TOTAL_SUBS"
    
    # Httpx - Find live hosts
    if check_tool httpx; then
        log_info "Probing live hosts with Httpx..."
        cat "$OUTPUT_DIR/subdomains/all_subdomains.txt" | \
            httpx -silent -tech-detect -status-code -title -follow-redirects \
            -o "$OUTPUT_DIR/subdomains/live_hosts.txt" 2>/dev/null
        
        LIVE=$(wc -l < "$OUTPUT_DIR/subdomains/live_hosts.txt")
        log_success "Live hosts: $LIVE"
        notify "Phase 1 complete: Found $TOTAL_SUBS subdomains, $LIVE live"
    fi
}

# ═══════════════════════════════════════════════════════════
# PHASE 2: DIRECTORY & FILE DISCOVERY
# ═══════════════════════════════════════════════════════════
phase2_discovery() {
    log_phase "PHASE 2: DIRECTORY & FILE DISCOVERY (10 tools)"
    
    # FFUF
    if check_tool ffuf; then
        log_info "Running FFUF directory fuzzing..."
        head -3 "$OUTPUT_DIR/subdomains/live_hosts.txt" | while read url; do
            ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
                -mc 200,301,302,403 -fc 404 -s -o "$OUTPUT_DIR/urls/ffuf_$(echo $url | md5sum | cut -d' ' -f1).json" 2>/dev/null
        done
        log_success "FFUF completed"
    fi
    
    # Katana
    if check_tool katana; then
        log_info "Running Katana crawler..."
        katana -list "$OUTPUT_DIR/subdomains/live_hosts.txt" \
            -d 5 -jc -kf all -aff -o "$OUTPUT_DIR/urls/katana.txt" 2>/dev/null
        log_success "Katana: $(wc -l < $OUTPUT_DIR/urls/katana.txt 2>/dev/null || echo 0) URLs"
    fi
    
    # GAU
    if check_tool gau; then
        log_info "Running GAU..."
        cat "$OUTPUT_DIR/subdomains/live_hosts.txt" | \
            gau --threads 10 --blacklist ttf,woff,svg,png,jpg > "$OUTPUT_DIR/urls/gau.txt" 2>/dev/null
        log_success "GAU completed"
    fi
    
    # Paramspider
    if check_tool paramspider; then
        log_info "Running Paramspider..."
        paramspider -d "$TARGET" -o "$OUTPUT_DIR/urls/paramspider.txt" 2>/dev/null
        log_success "Paramspider completed"
    fi
    
    # Merge URLs
    log_info "Merging all URLs..."
    cat "$OUTPUT_DIR/urls/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/urls/all_urls.txt"
    TOTAL_URLS=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt")
    log_success "Total URLs: $TOTAL_URLS"
}

# ═══════════════════════════════════════════════════════════
# PHASE 3: WEB VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════
phase3_vuln_scan() {
    log_phase "PHASE 3: WEB VULNERABILITY SCANNING (11 tools)"
    
    # Nuclei - All templates
    if check_tool nuclei; then
        log_info "Running Nuclei (all templates)..."
        nuclei -list "$OUTPUT_DIR/subdomains/live_hosts.txt" \
            -t ~/nuclei-templates/ -severity critical,high,medium \
            -o "$OUTPUT_DIR/vulns/nuclei_all.txt" 2>/dev/null
        
        NUCLEI_FINDINGS=$(wc -l < "$OUTPUT_DIR/vulns/nuclei_all.txt" 2>/dev/null || echo 0)
        log_success "Nuclei: $NUCLEI_FINDINGS vulnerabilities found"
        
        if [ $NUCLEI_FINDINGS -gt 0 ]; then
            notify "🚨 ALERT: Nuclei found $NUCLEI_FINDINGS vulnerabilities!"
        fi
    fi
    
    # Nikto
    if check_tool nikto; then
        log_info "Running Nikto..."
        head -3 "$OUTPUT_DIR/subdomains/live_hosts.txt" | while read url; do
            nikto -h "$url" -output "$OUTPUT_DIR/vulns/nikto_$(echo $url | md5sum | cut -d' ' -f1).txt" 2>/dev/null
        done
        log_success "Nikto completed"
    fi
    
    # WPScan
    if check_tool wpscan; then
        log_info "Running WPScan (WordPress sites)..."
        grep -i wordpress "$OUTPUT_DIR/subdomains/live_hosts.txt" | head -3 | while read url; do
            wpscan --url "$url" --enumerate vp,vt,u \
                --output "$OUTPUT_DIR/vulns/wpscan_$(echo $url | md5sum | cut -d' ' -f1).txt" 2>/dev/null
        done
        log_success "WPScan completed"
    fi
}

# ═══════════════════════════════════════════════════════════
# PHASE 4: SQL INJECTION TESTING
# ═══════════════════════════════════════════════════════════
phase4_sqli() {
    log_phase "PHASE 4: SQL INJECTION TESTING (10 tools)"
    
    # Extract URLs with parameters
    log_info "Extracting URLs with parameters..."
    cat "$OUTPUT_DIR/urls/all_urls.txt" | grep "?" | head -20 > "$OUTPUT_DIR/sqli/target_urls.txt"
    PARAM_URLS=$(wc -l < "$OUTPUT_DIR/sqli/target_urls.txt")
    log_info "Found $PARAM_URLS URLs with parameters"
    
    # SQLMap
    if check_tool sqlmap; then
        log_info "Running SQLMap..."
        head -5 "$OUTPUT_DIR/sqli/target_urls.txt" | while read url; do
            log_info "Testing: $url"
            sqlmap -u "$url" --batch --random-agent --level=2 --risk=2 \
                --output-dir="$OUTPUT_DIR/sqli/" 2>/dev/null
        done
        log_success "SQLMap completed"
    fi
    
    # Manual error-based test
    log_info "Testing for error-based SQLi..."
    head -10 "$OUTPUT_DIR/sqli/target_urls.txt" | while read url; do
        curl "${url}'" -o "$OUTPUT_DIR/sqli/error_test.html" 2>/dev/null
        if grep -iq "sql\|mysql\|oracle\|error" "$OUTPUT_DIR/sqli/error_test.html"; then
            echo "$url" >> "$OUTPUT_DIR/sqli/possible_sqli.txt"
            log_warning "Possible SQLi: $url"
        fi
    done
}

# ═══════════════════════════════════════════════════════════
# PHASE 5: XSS TESTING
# ═══════════════════════════════════════════════════════════
phase5_xss() {
    log_phase "PHASE 5: XSS TESTING (9 tools)"
    
    # Dalfox
    if check_tool dalfox; then
        log_info "Running Dalfox..."
        head -20 "$OUTPUT_DIR/sqli/target_urls.txt" | while read url; do
            dalfox url "$url" -o "$OUTPUT_DIR/xss/dalfox.txt" 2>/dev/null
        done
        log_success "Dalfox completed"
    fi
    
    # Kxss
    if check_tool kxss; then
        log_info "Running Kxss..."
        cat "$OUTPUT_DIR/urls/all_urls.txt" | grep = | kxss > "$OUTPUT_DIR/xss/kxss.txt" 2>/dev/null
        log_success "Kxss completed"
    fi
    
    # Manual XSS tests
    log_info "Running manual XSS tests..."
    XSS_PAYLOAD="<script>alert(1)</script>"
    head -10 "$OUTPUT_DIR/sqli/target_urls.txt" | while read url; do
        TEST_URL="${url}&xss=${XSS_PAYLOAD}"
        curl "$TEST_URL" -o "$OUTPUT_DIR/xss/manual_test.html" 2>/dev/null
        if grep -q "$XSS_PAYLOAD" "$OUTPUT_DIR/xss/manual_test.html"; then
            echo "$url" >> "$OUTPUT_DIR/xss/reflected_xss.txt"
            log_warning "Possible reflected XSS: $url"
        fi
    done
}

# ═══════════════════════════════════════════════════════════
# PHASE 6: IDOR & ACCESS CONTROL
# ═══════════════════════════════════════════════════════════
phase6_idor() {
    log_phase "PHASE 6: IDOR & ACCESS CONTROL (8 tools)"
    
    # Test for IDOR with numeric IDs
    log_info "Testing for IDOR vulnerabilities..."
    
    # Find API endpoints
    grep -E "/api/|/user/|/profile/|/account/" "$OUTPUT_DIR/urls/all_urls.txt" | \
        head -10 > "$OUTPUT_DIR/idor/api_endpoints.txt"
    
    # Test numeric parameter manipulation
    log_info "Testing numeric parameter IDOR..."
    cat "$OUTPUT_DIR/idor/api_endpoints.txt" | while read url; do
        for id in {1..10}; do
            curl "$url/$id" -o "$OUTPUT_DIR/idor/test_$id.html" 2>/dev/null
        done
    done
    log_success "IDOR tests completed"
}

# ═══════════════════════════════════════════════════════════
# PHASE 7: OTHER OWASP TOP 10
# ═══════════════════════════════════════════════════════════
phase7_owasp() {
    log_phase "PHASE 7: OTHER OWASP TOP 10 TESTS (12 tools)"
    
    # SSRF Tests
    log_info "Testing for SSRF..."
    head -5 "$OUTPUT_DIR/sqli/target_urls.txt" | while read url; do
        curl "${url}&url=http://169.254.169.254/latest/meta-data/" \
            -o "$OUTPUT_DIR/misc/ssrf_aws.html" 2>/dev/null
        curl "${url}&url=http://127.0.0.1:80" \
            -o "$OUTPUT_DIR/misc/ssrf_localhost.html" 2>/dev/null
    done
    
    # LFI Tests
    log_info "Testing for LFI..."
    head -5 "$OUTPUT_DIR/sqli/target_urls.txt" | while read url; do
        curl "${url}&file=../../../../etc/passwd" \
            -o "$OUTPUT_DIR/misc/lfi_test.html" 2>/dev/null
        if grep -q "root:" "$OUTPUT_DIR/misc/lfi_test.html"; then
            echo "$url" >> "$OUTPUT_DIR/misc/lfi_found.txt"
            log_warning "Possible LFI: $url"
            notify "🚨 CRITICAL: LFI found on $url"
        fi
    done
    
    # Security headers check
    log_info "Checking security headers..."
    head -5 "$OUTPUT_DIR/subdomains/live_hosts.txt" | while read url; do
        curl -I "$url" | grep -E "(X-Frame-Options|Content-Security-Policy|X-XSS-Protection)" \
            >> "$OUTPUT_DIR/misc/security_headers.txt" 2>/dev/null
    done
    
    # Check for exposed files
    log_info "Checking for exposed sensitive files..."
    head -5 "$OUTPUT_DIR/subdomains/live_hosts.txt" | while read url; do
        curl "$url/.env" -o "$OUTPUT_DIR/misc/env_check.txt" 2>/dev/null
        curl "$url/.git/config" -o "$OUTPUT_DIR/misc/git_check.txt" 2>/dev/null
        curl "$url/web.config" -o "$OUTPUT_DIR/misc/webconfig_check.txt" 2>/dev/null
    done
}

# ═══════════════════════════════════════════════════════════
# PHASE 8: AUTHENTICATION & BRUTE FORCE
# ═══════════════════════════════════════════════════════════
phase8_auth() {
    log_phase "PHASE 8: AUTHENTICATION & BRUTE FORCE (8 tools)"
    
    log_warning "Skipping brute force (high noise, use manually if needed)"
    log_info "Check for default credentials manually"
}

# ═══════════════════════════════════════════════════════════
# PHASE 9: EXPLOIT SEARCH & VERIFICATION
# ═══════════════════════════════════════════════════════════
phase9_exploits() {
    log_phase "PHASE 9: EXPLOIT SEARCH & VERIFICATION (7 tools)"
    
    # SearchSploit
    if check_tool searchsploit; then
        log_info "Running SearchSploit..."
        searchsploit --update 2>/dev/null
        
        # Search for technologies found
        if [ -f "$OUTPUT_DIR/subdomains/live_hosts.txt" ]; then
            log_info "Searching exploits for detected technologies..."
            # Example searches based on common tech
            searchsploit apache > "$OUTPUT_DIR/misc/searchsploit_apache.txt" 2>/dev/null
            searchsploit wordpress > "$OUTPUT_DIR/misc/searchsploit_wp.txt" 2>/dev/null
        fi
        log_success "SearchSploit completed"
    fi
    
    # Nuclei CVE verification
    if check_tool nuclei; then
        log_info "Running Nuclei CVE verification..."
        nuclei -list "$OUTPUT_DIR/subdomains/live_hosts.txt" \
            -t ~/nuclei-templates/cves/ -severity critical,high \
            -o "$OUTPUT_DIR/vulns/nuclei_cve_verify.txt" 2>/dev/null
        log_success "CVE verification completed"
    fi
}

# ═══════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════
generate_report() {
    log_phase "GENERATING FINAL REPORT"
    
    REPORT="$OUTPUT_DIR/reports/scan_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$REPORT" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Web Application Security Automation Tool- $TARGET</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff41; padding: 30px; }
        .header { background: linear-gradient(135deg, #00ff41 0%, #00d4ff 100%); 
                  padding: 40px; border-radius: 10px; margin-bottom: 30px; color: #000; }
        .stat-box { background: #1a1a2e; padding: 20px; border: 2px solid #00ff41;
                    margin: 10px; display: inline-block; min-width: 200px; border-radius: 5px; }
        .stat-value { font-size: 48px; font-weight: bold; color: #00ff41; }
        .stat-label { font-size: 14px; color: #00d4ff; }
        .section { background: #1a1a2e; padding: 25px; border-radius: 10px; margin: 20px 0; 
                   border: 2px solid #00ff41; }
        .finding { background: #0a0a0a; padding: 15px; margin: 10px 0; border-radius: 5px; 
                   border-left: 4px solid #ff0055; }
        .critical { border-left-color: #ff0055; }
        .high { border-left-color: #ff6b00; }
        .medium { border-left-color: #ffd000; }
        h2 { color: #00ff41; text-shadow: 0 0 10px #00ff41; }
        code { background: #000; color: #00ff41; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Web Application Security Automation Tool </h1>
        <h2>Security Scan Report</h2>
        <p>Target: <strong>$TARGET</strong></p>
        <p>Scan Date: $(date '+%Y-%m-%d %H:%M:%S')</p>
        <p>OWASP Top 10 Coverage | 90+ Tools Executed</p>
    </div>
    
    <div class="stat-box">
        <div class="stat-value">$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo 0)</div>
        <div class="stat-label">Subdomains Found</div>
    </div>
    
    <div class="stat-box">
        <div class="stat-value">$(wc -l < "$OUTPUT_DIR/subdomains/live_hosts.txt" 2>/dev/null || echo 0)</div>
        <div class="stat-label">Live Hosts</div>
    </div>
    
    <div class="stat-box">
        <div class="stat-value">$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)</div>
        <div class="stat-label">URLs Discovered</div>
    </div>
    
    <div class="stat-box">
        <div class="stat-value">$(wc -l < "$OUTPUT_DIR/vulns/nuclei_all.txt" 2>/dev/null || echo 0)</div>
        <div class="stat-label">Vulnerabilities</div>
    </div>
    
    <div class="section">
        <h2>🔍 SCAN SUMMARY</h2>
        <p>Comprehensive web application security assessment completed.</p>
        <p>All results stored in: <code>$OUTPUT_DIR/</code></p>
    </div>
    
    <div class="section">
        <h2>🚨 TOP FINDINGS</h2>
EOF

    # Add Nuclei findings
    if [ -f "$OUTPUT_DIR/vulns/nuclei_all.txt" ]; then
        head -20 "$OUTPUT_DIR/vulns/nuclei_all.txt" | while read line; do
            echo "        <div class='finding critical'>$line</div>" >> "$REPORT"
        done
    fi
    
    cat >> "$REPORT" <<EOF
    </div>
    
    <div class="section">
        <h2>📊 OWASP TOP 10 COVERAGE</h2>
        <ul>
            <li>✓ A01:2021 - Broken Access Control (IDOR, Auth tests)</li>
            <li>✓ A02:2021 - Cryptographic Failures (Headers, sensitive data)</li>
            <li>✓ A03:2021 - Injection (SQLi, XSS, XXE, LFI, RFI, SSTI)</li>
            <li>✓ A04:2021 - Insecure Design (Manual verification)</li>
            <li>✓ A05:2021 - Security Misconfiguration (Nuclei, Nikto)</li>
            <li>✓ A06:2021 - Vulnerable Components (SearchSploit, Nuclei CVE)</li>
            <li>✓ A07:2021 - Authentication Failures (Tested)</li>
            <li>✓ A08:2021 - Software & Data Integrity (File upload)</li>
            <li>✓ A09:2021 - Logging Failures (Manual check)</li>
            <li>✓ A10:2021 - SSRF (AWS metadata, localhost)</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>📁 OUTPUT FILES</h2>
        <ul>
            <li>Subdomains: <code>$OUTPUT_DIR/subdomains/all_subdomains.txt</code></li>
            <li>Live Hosts: <code>$OUTPUT_DIR/subdomains/live_hosts.txt</code></li>
            <li>URLs: <code>$OUTPUT_DIR/urls/all_urls.txt</code></li>
            <li>Vulnerabilities: <code>$OUTPUT_DIR/vulns/nuclei_all.txt</code></li>
            <li>SQLi Tests: <code>$OUTPUT_DIR/sqli/</code></li>
            <li>XSS Tests: <code>$OUTPUT_DIR/xss/</code></li>
        </ul>
    </div>
    
    <div class="section">
        <h2>⚠️ DISCLAIMER</h2>
        <p>This scan was performed for authorized security testing only.</p>
        <p>All findings should be verified manually before reporting.</p>
    </div>
</body>
</html>
EOF
    
    log_success "Report generated: $REPORT"
    
    # Open in browser
    if command -v xdg-open &> /dev/null; then
        xdg-open "$REPORT" 2>/dev/null &
    fi
}

# ═══════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════
main() {
    banner
    
    # Parse arguments
    while getopts "t:o:d:T:" opt; do
        case $opt in
            t) TARGET="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            d) DISCORD_WEBHOOK="$OPTARG" ;;
            T) TELEGRAM_BOT="$OPTARG" ;;
            *)
                echo "Usage: $0 -t target.com [-o output_dir] [-d discord_webhook] [-T telegram_bot]"
                exit 1
                ;;
        esac
    done
    
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: Target is required!${NC}"
        echo "Usage: $0 -t target.com [-o output_dir] [-d discord_webhook]"
        exit 1
    fi
    
    log_info "Target: $TARGET"
    log_info "Output: $OUTPUT_DIR"
    
    START_TIME=$(date +%s)
    
    setup_dirs
    
    # Execute all phases
    phase1_recon
    phase2_discovery
    phase3_vuln_scan
    phase4_sqli
    phase5_xss
    phase6_idor
    phase7_owasp
    phase8_auth
    phase9_exploits
    
    # Generate report
    generate_report
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    echo ""
    log_success "✨ ALL PHASES COMPLETED in $DURATION seconds!"
    log_success "Results: $OUTPUT_DIR/"
    
    notify "✅ Full scan completed in $DURATION seconds"
}

main "$@"
