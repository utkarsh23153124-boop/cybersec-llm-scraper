"""
Configuration module for the Cybersecurity LLM Data Ingestion & Web Scraping Pipeline.
Contains target topics, certification keywords, open data source URLs, crawler settings,
and LLM dataset formatting rules.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "cybersec_dataset"
OUTPUT_DIR = DATA_DIR / "output"
CACHE_DIR = DATA_DIR / "cache"
STATE_DB_PATH = CACHE_DIR / "crawler_state.db"

# Ensure runtime directories exist
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Target Partition Size (e.g. 500 MB per JSONL chunk file)
DEFAULT_CHUNK_SIZE_MB = 500

# Default target volume limit in Gigabytes
DEFAULT_MAX_GB = 300

# Concurrency & Networking
DEFAULT_CONCURRENCY = 40
REQUEST_TIMEOUT_SECONDS = 20
REQUEST_RETRIES = 3
PER_DOMAIN_DELAY_SECONDS = 0.5  # Polite delay per host

# User-Agent pool for crawler
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# Comprehensive Keyword Taxonomy (Used for topic scoring & tagging)
TARGET_CERTIFICATIONS = [
    "OSWE", "OffSec Web Expert",
    "BSCP", "Burp Suite Certified Practitioner",
    "eWPT", "eWPTX", "Web Application Penetration Tester", "Web Application Penetration Tester eXtreme",
    "CEH", "Certified Ethical Hacker", "CEH Practical", "C|EH AI",
    "CPT", "Certified Penetration Tester", "CEPT", "Certified Expert Penetration Tester",
    "CPENT", "Certified Penetration Testing Professional",
    "OSCP", "OSCP+", "OffSec Certified Professional",
    "OSWA", "OffSec Web Assessor",
    "OSED", "OffSec Exploit Developer",
    "OSCE3", "OffSec Certified Expert 3",
    "WEB-200", "Foundational Web Application Assessments",
    "WEB-300", "Advanced Web Attacks and Exploitation",
    "GWAPT", "GIAC Web Application Penetration Tester",
    "GWEB", "SEC542", "SEC522",
    "GPEN", "GIAC Penetration Tester",
    "GXPN", "GIAC Exploit Researcher and Advanced Penetration Tester",
    "GPYC", "GIAC Python Coder",
    "eCPPT", "Certified Professional Penetration Tester",
    "CBBH", "Certified Bug Bounty Hunter",
    "CWES", "Certified Web Exploitation Specialist",
    "CPTS", "Certified Penetration Testing Specialist",
    "PNPT", "Practical Network Penetration Tester",
    "PJWT", "Practical Junior Web Tester",
    "PWA", "Practical Web Assessor",
    "CREST CRT", "CREST CPSA", "CREST CCT APP", "CREST CCT INF", "CREST CSTM",
    "ECSA", "CSA", "OSWP", "OSDA", "OSIR", "OSCC", "OSMR", "OSEP",
    "CPEH", "CPTE", "CPHA", "C|SA", "C|TIA", "C|ND", "C|NDA", "C|CISO", "C|PMA"
]

TARGET_TOPICS = [
    "Practical Web Hacking",
    "Web Application Penetration Testing",
    "Advanced Web Application Penetration Testing",
    "Web Application Security Testing",
    "Web Application Security",
    "Web Hacking",
    "Advanced Web Hacking",
    "Web Exploitation",
    "Advanced Web Exploitation",
    "Web Security Academy",
    "API Security",
    "Advanced API Security",
    "Web API Penetration Testing",
    "GraphQL Security Testing",
    "Bug Bounty Hunting",
    "Advanced Bug Bounty Hunting",
    "Web Application Bug Bounty",
    "Web Application Security Testing with Burp Suite",
    "Advanced Burp Suite",
    "Web Application Source Code Review",
    "Advanced Web Application Source Code Review",
    "Secure Code Review",
    "Application Security",
    "Advanced Application Security",
    "DevSecOps",
    "Secure Software Development",
    "OWASP Application Security Verification Standard", "ASVS",
    "OWASP Web Security Testing Guide", "WSTG",
    "OWASP Top 10",
    "SANS SWAT", "Secure Web Application Technologies",
    "ISO/IEC 27034", "Application Security",
    "NIST Secure Software Development Framework", "SSDF",
    "MITRE CWE", "Common Weakness Enumeration",
    "MITRE CAPEC", "Common Attack Pattern Enumeration and Classification",
    "Web Application Threat Modeling",
    "Advanced Web Application Threat Modeling",
    "Authentication and Authorization Security",
    "Cloud Web Application Security",
    "Web Application Security Architecture",
    "Advanced Web Application Security Engineering",
    "SQL Injection", "Cross-Site Scripting", "XSS", "CSRF", "SSRF",
    "Server-Side Request Forgery", "Insecure Deserialization", "IDOR",
    "Broken Object Level Authorization", "BOLA", "JWT security", "OAuth security",
    "XML External Entity", "XXE", "Remote Code Execution", "RCE",
    "Prototype Pollution", "Race Conditions", "Business Logic Vulnerabilities",
    "Path Traversal", "File Inclusion", "LFI", "RFI"
]

# Combined normalized set for keyword scoring
ALL_KEYWORDS_LOWER = set(k.lower() for k in TARGET_CERTIFICATIONS + TARGET_TOPICS)

# Official Bulk Open-Source Datasets (Massive, authoritative technical data)
BULK_DATA_FEEDS = {
    "mitre_cwe": {
        "name": "MITRE Common Weakness Enumeration (CWE)",
        "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "description": "Complete dictionary of software security weaknesses, code examples, and mitigations."
    },
    "mitre_capec": {
        "name": "MITRE Common Attack Pattern Enumeration and Classification (CAPEC)",
        "url": "https://capec.mitre.org/data/xml/capec_latest.xml.zip",
        "description": "Complete catalog of attack patterns, execution flow, and attacker prerequisites."
    },
    "owasp_wstg": {
        "name": "OWASP Web Security Testing Guide (WSTG)",
        "git_url": "https://github.com/OWASP/wstg.git",
        "raw_tree_url": "https://api.github.com/repos/OWASP/wstg/contents/document",
        "description": "Premier testing guide for web application security & penetration testing."
    },
    "owasp_asvs": {
        "name": "OWASP Application Security Verification Standard (ASVS)",
        "git_url": "https://github.com/OWASP/ASVS.git",
        "raw_tree_url": "https://api.github.com/repos/OWASP/ASVS/contents/4.0",
        "description": "Basis for testing web application technical security controls."
    },
    "owasp_cheatsheets": {
        "name": "OWASP Cheat Sheet Series",
        "git_url": "https://github.com/OWASP/CheatSheetSeries.git",
        "raw_tree_url": "https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets",
        "description": "High-value, concise secure software engineering and pentesting guides."
    },
    "owasp_top10": {
        "name": "OWASP Top 10 Documentation",
        "git_url": "https://github.com/OWASP/Top10.git",
        "description": "Standard awareness document for web application developers and security analysts."
    },
    "nist_ssdf": {
        "name": "NIST Secure Software Development Framework (SP 800-218)",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-218/final",
        "description": "NIST guidelines for mitigating software vulnerabilities."
    }
}

# High-Signal Seed URLs for Async Web Crawler
CRAWLER_SEEDS = [
    # PortSwigger Web Security Academy (Research & Topic Overviews)
    "https://portswigger.net/web-security/all-topics",
    "https://portswigger.net/web-security/sql-injection",
    "https://portswigger.net/web-security/cross-site-scripting",
    "https://portswigger.net/web-security/csrf",
    "https://portswigger.net/web-security/ssrf",
    "https://portswigger.net/web-security/file-path-traversal",
    "https://portswigger.net/web-security/cors",
    "https://portswigger.net/web-security/xxe",
    "https://portswigger.net/web-security/deserialization",
    "https://portswigger.net/web-security/os-command-injection",
    "https://portswigger.net/web-security/business-logic-vulnerabilities",
    "https://portswigger.net/web-security/authentication",
    "https://portswigger.net/web-security/jwt",
    "https://portswigger.net/web-security/oauth",
    "https://portswigger.net/web-security/graphql",
    "https://portswigger.net/web-security/api-testing",
    "https://portswigger.net/web-security/race-conditions",
    "https://portswigger.net/web-security/prototype-pollution",
    "https://portswigger.net/web-security/llm-attacks",
    "https://portswigger.net/web-security/web-cache-poisoning",
    "https://portswigger.net/web-security/http-request-smuggling",
    "https://portswigger.net/web-security/host-header-attacks",
    "https://portswigger.net/research",
    
    # OWASP Documentation & Projects
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://owasp.org/www-project-top-ten/",
    "https://owasp.org/www-project-api-security/",
    "https://owasp.org/www-project-threat-dragon/",
    "https://owasp.org/www-project-juice-shop/",
    "https://owasp.org/www-project-application-security-verification-standard/",
    "https://cheatsheetseries.owasp.org/",

    # Public Vulnerability Writeups & Educational Materials
    "https://infosecwriteups.com/",
    "https://pentesterland.com/list-of-bug-bounty-writeups.html",
    "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web",
    "https://payatu.com/blog/",
    "https://blog.projectdiscovery.io/",
    "https://hackerone.com/hacktivity",
    "https://learn.microsoft.com/en-us/security/",
    "https://attack.mitre.org/matrices/enterprise/",
    
    # Certification Syllabi & Guides
    "https://www.offsec.com/courses/web-200/",
    "https://www.offsec.com/courses/web-300/",
    "https://www.offsec.com/courses/pen-200/",
    "https://academy.tcm-sec.com/",
    "https://academy.hackthebox.com/catalogue"
]

# Domains allowed for deep crawling
ALLOWED_DOMAINS = [
    "portswigger.net",
    "owasp.org",
    "cheatsheetseries.owasp.org",
    "cwe.mitre.org",
    "capec.mitre.org",
    "attack.mitre.org",
    "nist.gov",
    "csrc.nist.gov",
    "infosecwriteups.com",
    "pentesterland.com",
    "book.hacktricks.xyz",
    "payatu.com",
    "projectdiscovery.io",
    "offsec.com",
    "tcm-sec.com",
    "hackthebox.com",
    "tryhackme.com"
]
