#!/bin/bash

# Web Application Security Automation Tool
# Installs all 90+ security tools

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Web Application Security Automation Tool                 ║"
echo "║  Installing 90+ Security Tools                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}\n"

if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}[!] Do not run as root${NC}"
    exit 1
fi

# Update system
echo -e "${YELLOW}[*] Updating system...${NC}"
sudo apt update
sudo apt upgrade -y

# Install dependencies
echo -e "${YELLOW}[*] Installing dependencies...${NC}"
sudo apt install -y \
    python3 python3-pip python3-tk \
    git golang-go \
    wget curl \
    build-essential \
    libpcap-dev \
    chromium-browser \
    nmap nikto sqlmap hydra \
    dirb gobuster wapiti

# Setup Go environment
echo -e "${YELLOW}[*] Setting up Go environment...${NC}"
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> ~/.bashrc

# ═══════════════════════════════════════════════════════════
# PHASE 1 TOOLS: RECONNAISSANCE
# ═══════════════════════════════════════════════════════════
echo -e "${BLUE}[*] Installing Phase 1 tools (Reconnaissance)...${NC}"

# Subfinder
echo -e "${GREEN}Installing Subfinder...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder
echo -e "${GREEN}Installing Assetfinder...${NC}"
go install github.com/tomnomnom/assetfinder@latest

# Amass
echo -e "${GREEN}Installing Amass...${NC}"
go install -v github.com/owasp-amass/amass/v4/...@master

# Sublist3r
echo -e "${GREEN}Installing Sublist3r...${NC}"
if [ ! -d "/opt/Sublist3r" ]; then
    sudo git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r
    cd /opt/Sublist3r
    sudo pip3 install -r requirements.txt
    sudo ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
    cd -
fi

# SubBrute
echo -e "${GREEN}Installing SubBrute...${NC}"
if [ ! -d "/opt/subbrute" ]; then
    sudo git clone https://github.com/TheRook/subbrute.git /opt/subbrute
fi

# X-Recon
echo -e "${GREEN}Installing X-Recon...${NC}"
if [ ! -d "/opt/X-Recon" ]; then
    sudo git clone https://github.com/joshkar/X-Recon.git /opt/X-Recon
    cd /opt/X-Recon
    sudo pip3 install -r requirements.txt
    cd -
fi

# theHarvester
echo -e "${GREEN}Installing theHarvester...${NC}"
if [ ! -d "/opt/theHarvester" ]; then
    sudo git clone https://github.com/laramies/theHarvester.git /opt/theHarvester
    cd /opt/theHarvester
    sudo pip3 install -r requirements.txt
    sudo ln -sf /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester
    cd -
fi

# SpiderFoot
echo -e "${GREEN}Installing SpiderFoot...${NC}"
if [ ! -d "/opt/spiderfoot" ]; then
    sudo git clone https://github.com/smicallef/spiderfoot.git /opt/spiderfoot
    cd /opt/spiderfoot
    sudo pip3 install -r requirements.txt
    cd -
fi

# Httpx
echo -e "${GREEN}Installing Httpx...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Wappalyzer CLI
echo -e "${GREEN}Installing Wappalyzer...${NC}"
sudo npm install -g wappalyzer

# ═══════════════════════════════════════════════════════════
# PHASE 2 TOOLS: DIRECTORY DISCOVERY
# ═══════════════════════════════════════════════════════════
echo -e "${BLUE}[*] Installing Phase 2 tools (Directory Discovery)...${NC}"

# FFUF
echo -e "${GREEN}Installing FFUF...${NC}"
go install github.com/ffuf/ffuf/v2@latest

# Dirsearch
echo -e "${GREEN}Installing Dirsearch...${NC}"
if [ ! -d "/opt/dirsearch" ]; then
    sudo git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
    sudo ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
fi

# Feroxbuster
echo -e "${GREEN}Installing Feroxbuster...${NC}"
if ! command -v feroxbuster &> /dev/null; then
    wget -q https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip
    unzip feroxbuster_amd64.deb.zip
    sudo dpkg -i feroxbuster_*_amd64.deb
    rm feroxbuster_*
fi

# Katana
echo -e "${GREEN}Installing Katana...${NC}"
go install github.com/projectdiscovery/katana/cmd/katana@latest

# GAU
echo -e "${GREEN}Installing GAU...${NC}"
go install github.com/lc/gau/v2/cmd/gau@latest

# Paramspider
echo -e "${GREEN}Installing Paramspider...${NC}"
if [ ! -d "/opt/ParamSpider" ]; then
    sudo git clone https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider
    cd /opt/ParamSpider
    sudo pip3 install -r requirements.txt
    sudo ln -sf /opt/ParamSpider/paramspider.py /usr/local/bin/paramspider
    cd -
fi

# Arjun
echo -e "${GREEN}Installing Arjun...${NC}"
sudo pip3 install arjun

# ═══════════════════════════════════════════════════════════
# PHASE 3 TOOLS: VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════
echo -e "${BLUE}[*] Installing Phase 3 tools (Vulnerability Scanning)...${NC}"

# Nuclei
echo -e "${GREEN}Installing Nuclei...${NC}"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Wapiti already installed

# WPScan
echo -e "${GREEN}Installing WPScan...${NC}"
sudo gem install wpscan

# RapidScan
echo -e "${GREEN}Installing RapidScan...${NC}"
if [ ! -d "/opt/rapidscan" ]; then
    sudo git clone https://github.com/skavngr/rapidscan.git /opt/rapidscan
    cd /opt/rapidscan
    sudo pip3 install -r requirements.txt
    cd -
fi

# Sn1per
echo -e "${GREEN}Installing Sn1per...${NC}"
if [ ! -d "/opt/Sn1per" ]; then
    sudo git clone https://github.com/1N3/Sn1per.git /opt/Sn1per
    cd /opt/Sn1per
    sudo bash install.sh
    cd -
fi

# Skipfish
echo -e "${GREEN}Installing Skipfish...${NC}"
sudo apt install -y skipfish

# Argus
echo -e "${GREEN}Installing Argus...${NC}"
if [ ! -d "/opt/argus" ]; then
    sudo git clone https://github.com/Argus-Sec/Argus.git /opt/argus
fi

# ═══════════════════════════════════════════════════════════
# PHASE 5 TOOLS: XSS TESTING
# ═══════════════════════════════════════════════════════════
echo -e "${BLUE}[*] Installing Phase 5 tools (XSS Testing)...${NC}"

# XSStrike
echo -e "${GREEN}Installing XSStrike...${NC}"
if [ ! -d "/opt/XSStrike" ]; then
    sudo git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike
    cd /opt/XSStrike
    sudo pip3 install -r requirements.txt
    sudo ln -sf /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike
    cd -
fi

# PwnXSS
echo -e "${GREEN}Installing PwnXSS...${NC}"
if [ ! -d "/opt/PwnXSS" ]; then
    sudo git clone https://github.com/pwn0sec/PwnXSS.git /opt/PwnXSS
    cd /opt/PwnXSS
    sudo pip3 install -r requirements.txt
    cd -
fi

# Dalfox
echo -e "${GREEN}Installing Dalfox...${NC}"
go install github.com/hahwul/dalfox/v2@latest

# Kxss
echo -e "${GREEN}Installing Kxss...${NC}"
go install github.com/Emoe/kxss@latest

# ═══════════════════════════════════════════════════════════
# ADDITIONAL TOOLS
# ═══════════════════════════════════════════════════════════
echo -e "${BLUE}[*] Installing additional tools...${NC}"

# Waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Qsreplace
go install github.com/tomnomnom/qsreplace@latest

# Notify
go install github.com/projectdiscovery/notify/cmd/notify@latest

# NoSQLMap
if [ ! -d "/opt/NoSQLMap" ]; then
    sudo git clone https://github.com/codingo/NoSQLMap.git /opt/NoSQLMap
    cd /opt/NoSQLMap
    sudo pip3 install -r requirements.txt
    cd -
fi

# ═══════════════════════════════════════════════════════════
# WORDLISTS
# ═══════════════════════════════════════════════════════════
echo -e "${BLUE}[*] Setting up wordlists...${NC}"
sudo apt install -y wordlists

if [ ! -d "$HOME/wordlists" ]; then
    mkdir -p $HOME/wordlists
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
        -O $HOME/wordlists/common.txt
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt \
        -O $HOME/wordlists/raft-large-words.txt
fi

# ═══════════════════════════════════════════════════════════
# PYTHON DEPENDENCIES
# ═══════════════════════════════════════════════════════════
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
sudo pip3 install requests urllib3 beautifulsoup4 lxml colorama

# ═══════════════════════════════════════════════════════════
# VERIFICATION
# ═══════════════════════════════════════════════════════════
echo -e "\n${YELLOW}[*] Verifying installations...${NC}"

TOOLS=(
    "subfinder"
    "assetfinder"
    "amass"
    "sublist3r"
    "httpx"
    "ffuf"
    "gobuster"
    "dirsearch"
    "feroxbuster"
    "katana"
    "gau"
    "paramspider"
    "nuclei"
    "nikto"
    "wpscan"
    "sqlmap"
    "dalfox"
    "xsstrike"
    "hydra"
)

FAILED=0

for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} $tool"
    else
        echo -e "${RED}[✗]${NC} $tool not found"
        FAILED=1
    fi
done

echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════════════╗"
    echo -e "║  ✓ Installation completed successfully!          ║"
    echo -e "╚═══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. source ~/.bashrc"
    echo "2. python3 web_bugbounty_hunter_v3.py"
    echo "3. ./web_bugbounty_v3_master.sh -t example.com"
    echo ""
    echo -e "${YELLOW}Happy Hunting! 🎯${NC}"
else
    echo -e "${RED}╔═══════════════════════════════════════════════════╗"
    echo -e "║  ⚠ Some tools failed to install                  ║"
    echo -e "╚═══════════════════════════════════════════════════╝${NC}"
    echo "Please check errors above and install manually."
fi

echo ""
echo -e "${BLUE}Installation log saved to: install_v3.log${NC}"
