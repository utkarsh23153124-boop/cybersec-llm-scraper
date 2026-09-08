# 🔐 CyberSec-LLM-Scraper

> **High-throughput cybersecurity data ingestion & web scraping pipeline for LLM training.**
> Designed to harvest 200–300 GB of clean, deduplicated cybersecurity knowledge across certifications, attack methodologies, secure software standards, and penetration testing domains — formatted as **JSONL for LLM pre-training or fine-tuning**.

---

## 📋 Coverage

### Certifications & Syllabi
`OSWE` `BSCP` `eWPT` `eWPTX` `CEH` `OSCP` `OSCP+` `CPENT` `GWAPT` `GWEB` `SEC542` `SEC522` `GPEN` `GXPN` `PNPT` `PJWT` `PWA` `CBBH` `CWES` `CPTS` `CREST CRT/CPSA/CCT APP` `CPT` `CEPT` `OSED` `OSCE3` `OSDA` `OSEP` `OSWP` `eCPPT` `ECSA` `C|EH AI` `C|SA` `C|TIA` `C|ND` `C|CISO`

### Knowledge Bases & Standards
`MITRE CWE` `MITRE CAPEC` `OWASP WSTG` `OWASP ASVS` `OWASP Cheat Sheets` `OWASP Top 10` `NIST SSDF (SP 800-218)` `ISO/IEC 27034` `PortSwigger Web Security Academy`

### Technical Domains
`SQL Injection` `XSS` `CSRF` `SSRF` `IDOR/BOLA` `XXE` `Deserialization` `Prototype Pollution` `Race Conditions` `HTTP Request Smuggling` `Web Cache Poisoning` `JWT Security` `OAuth 2.0` `GraphQL Security` `API Pentesting` `Secure Code Review` `Threat Modeling` `DevSecOps` `Bug Bounty Hunting`

---

## ⚙️ Architecture

```
┌──────────────────────────────────────────────────┐
│         Target Certifications & Topics           │
└────────────────────┬─────────────────────────────┘
                     │
       ┌─────────────┴─────────────┐
       ▼                           ▼
┌─────────────────┐       ┌──────────────────────┐
│  Bulk Ingestion │       │  Async Web Crawler   │
│ MITRE CWE/CAPEC │       │  PortSwigger Academy │
│ OWASP (GitHub)  │       │  Bug Bounty Writeups │
│ NIST / ISO docs │       │  Cert Syllabi & Docs │
└───────┬─────────┘       └──────────┬───────────┘
        └─────────────┬──────────────┘
                      ▼
           ┌────────────────────┐
           │ Extraction Engine  │
           │ trafilatura + BS4  │
           │ Markdown / Code    │
           └────────┬───────────┘
                      ▼
           ┌────────────────────┐
           │  Deduplication     │
           │  xxhash64 + SQLite │
           │  URL Canonicalize  │
           └────────┬───────────┘
                      ▼
           ┌────────────────────────────────────┐
           │  Chunked JSONL Streaming Writer    │
           │  cybersec_train_0001.jsonl         │
           │  cybersec_train_0002.jsonl         │
           │  Optional: .jsonl.gz (Gzip)        │
           └────────────────────────────────────┘
```

---

## 🚀 Server Deployment (Ubuntu / Debian — Recommended)

> **Note**: This is designed to run on a server. Data is written directly to disk on the server. Expect 200–300 GB of JSONL output (or ~35–50 GB with Gzip compression).

### Step 1 — Clone the Repository
```bash
git clone https://github.com/utkarsh23153124-boop/cybersec-llm-scraper.git
cd cybersec-llm-scraper
```

### Step 2 — Install Python & Dependencies
```bash
# Install Python 3.10+ if not already present
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git

# Create isolated virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all required libraries
pip install -r requirements.txt
```

### Step 3 — Configure Storage Path
Edit `config.py` to set where data will be stored on your server:
```python
# In config.py — change this to your preferred server storage path:
DATA_DIR = Path("/data/cybersec_dataset")        # e.g. mounted volume or large disk
```
Or simply keep the default — data will be stored in `./cybersec_dataset/output/` inside the cloned folder.

### Step 4 — Run the Full Pipeline
```bash
# Full pipeline — bulk official sources + async crawler, with Gzip compression
# (Recommended: run in a screen/tmux session or systemd service so it keeps running after SSH disconnect)
python main.py --mode all --compress --max-gb 300 --concurrency 40 --chunk-size-mb 500
```

### Step 5 — Keep Running After SSH Disconnect (screen)
```bash
# Start a detached screen session
screen -S scraper
source venv/bin/activate
python main.py --mode all --compress --max-gb 300 --concurrency 40

# Detach without killing: Ctrl+A then D
# Reattach later with:
screen -r scraper
```

---

## 🔧 Run as a Systemd Service (Production — Auto-restart on crash)

Create a service file so the scraper runs as a background daemon and auto-restarts on server reboots or crashes:

```bash
sudo nano /etc/systemd/system/cybersec-scraper.service
```

Paste the following (replace `/home/youruser/cybersec-llm-scraper` with your actual clone path):
```ini
[Unit]
Description=CyberSec LLM Dataset Scraper
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/cybersec-llm-scraper
ExecStart=/home/youruser/cybersec-llm-scraper/venv/bin/python main.py --mode all --compress --max-gb 300 --concurrency 40
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable cybersec-scraper
sudo systemctl start cybersec-scraper

# Monitor live logs
sudo journalctl -u cybersec-scraper -f
```

---

## 📖 CLI Reference

```bash
python main.py [OPTIONS]

Options:
  --mode          {all, bulk, crawl}       Ingestion strategy (default: all)
  --max-gb        FLOAT                    Target volume cap in GB (default: 300)
  --chunk-size-mb INT                      JSONL partition size in MB (default: 500)
  --concurrency   INT                      Async worker threads (default: 40)
  --compress                               Enable .jsonl.gz Gzip output (saves ~80% disk)
  --test-sample                            Quick smoke test: verify pipeline health with small sample
```

### Examples
```bash
# Bulk only: Download MITRE CWE/CAPEC, OWASP WSTG, ASVS, CheatSheets, Top 10
python main.py --mode bulk

# Async crawler only: Crawl PortSwigger, OWASP wikis, bug bounty writeups
python main.py --mode crawl --concurrency 50

# Full pipeline with Gzip, targeting 100 GB
python main.py --mode all --compress --max-gb 100 --concurrency 40

# Quick smoke test to verify everything works before a full run
python main.py --test-sample
```

---

## 📊 JSONL Output Schema (LLM-Ready)

Every line is a self-contained JSON document:

```json
{
  "id": "csec_3a812f4b9e10",
  "text": "# Testing for SQL Injection (WSTG-INPV-05)\n\n## Summary\nSQL Injection vulnerabilities occur when user-supplied input is directly concatenated...",
  "metadata": {
    "title": "WSTG: Testing for SQL Injection",
    "source": "https://github.com/OWASP/wstg/blob/master/document/...",
    "topics": ["OWASP WSTG", "Web Application Penetration Testing", "OSWE", "BSCP", "SQL INJECTION"],
    "token_estimate": 2450,
    "created_at": "2026-09-08T15:20:00+00:00"
  }
}
```

---

## 🤖 Loading into LLM Training Frameworks

### Hugging Face `datasets`
```python
from datasets import load_dataset

dataset = load_dataset("json", data_files="cybersec_dataset/output/*.jsonl*")
print(f"Total documents: {len(dataset['train'])}")
```

### Axolotl / Unsloth / Llama-Factory
```yaml
datasets:
  - path: /data/cybersec_dataset/output/
    type: completion
    field: text
```

### Tokenizing for Pre-training
```python
from datasets import load_dataset
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3-8B")
dataset = load_dataset("json", data_files="cybersec_dataset/output/*.jsonl*", split="train")

def tokenize(example):
    return tokenizer(example["text"], truncation=True, max_length=4096)

tokenized = dataset.map(tokenize, batched=True, remove_columns=["text", "metadata"])
```

---

## 🗂️ Project Structure

```
cybersec-llm-scraper/
├── main.py                    # CLI entry point
├── config.py                  # All settings: topics, seeds, limits, paths
├── requirements.txt           # Python dependencies
├── test_pipeline.py           # Unit & integration test suite
├── README.md
├── core/
│   ├── extractor.py           # HTML → clean markdown/text extractor
│   ├── dedup.py               # xxhash64 + SQLite deduplication engine
│   └── writer.py              # Partitioned async JSONL streaming writer
└── ingestion/
    ├── bulk_sources.py        # MITRE, OWASP, NIST bulk downloaders
    └── async_crawler.py       # High-speed aiohttp async web crawler
```

---

## ⚠️ Notes

- Scraping targets **publicly accessible** security documentation, open MITRE/OWASP repositories, and public research — no paywalled content.
- Run with `--compress` on servers with limited disk space (reduces 200–300 GB to ~35–50 GB).
- The SQLite state DB (`cybersec_dataset/cache/crawler_state.db`) allows safe resume if the process is interrupted.
- Recommended: **16+ GB RAM server** for full 40-worker concurrent crawl. Can reduce `--concurrency 10` for lower-spec servers.

---

## 📜 License

MIT License — free to use, modify, and distribute.
