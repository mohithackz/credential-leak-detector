# 🔓 Credential Leak Detector

> **Automated OSINT pipeline that discovers leaked credentials for any domain.**  
> Enter a domain → get emails, breach data, and dark web mentions — all in one JSON report.

---

## 🎯 What It Does

This tool automates the entire credential leak detection process:

```
Domain (e.g., example.com)
    │
    ▼
┌──────────────────────────────────┐
│  Phase 1: Email Harvesting       │  ← theHarvester
│  Passive OSINT to find emails    │
└──────────────┬───────────────────┘
               │ emails found
               ▼
┌──────────────────────────────────┐
│  Phase 2: Breach Detection       │  ← SpiderFoot
│  Check emails against breach DBs │
└──────────────┬───────────────────┘
               │ breach data
               ▼
┌──────────────────────────────────┐
│  Phase 3: Dark Web Investigation │  ← Darkdump + Tor
│  Search .onion sites for leaks   │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│  📊 JSON Report                  │
│  Emails + Breaches + Dark Web    │
│  Threat Level Assessment         │
└──────────────────────────────────┘
```

---

## ⚡ Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/credential-leak-detector.git
cd credential-leak-detector

# 2. Run setup (creates venv, installs dependencies)
chmod +x setup.sh
./setup.sh

# 3. Activate virtual environment
source venv/bin/activate

# 4. Start Tor (for dark web scanning)
sudo service tor start

# 5. Run the tool
python3 main.py
```

---

## 🛠️ Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| **Python 3.8+** | Runtime | `sudo apt install python3 python3-pip python3-venv` |
| **theHarvester** | Email discovery | `sudo apt install theharvester` |
| **SpiderFoot** | Breach detection | `pip3 install spiderfoot` |
| **Tor** | Dark web routing | `sudo apt install tor` |
| **Darkdump** | Dark web search | Auto-installed by `setup.sh` |

> **Note:** This tool is designed for **Linux** (tested on Kali Linux / Ubuntu).

---

## 📁 Project Structure

```
credential-leak-detector/
├── main.py                      # Entry point — run this
├── modules/
│   ├── env_check.py             # Auto-detects installed tools
│   ├── harvester.py             # theHarvester wrapper
│   ├── spiderfoot_scan.py       # SpiderFoot breach scanner
│   ├── darkdump_scan.py         # Dark web scanner via Tor
│   └── report_generator.py      # JSON report builder
├── tools/
│   └── darkdump/                # Darkdump (auto-cloned by setup.sh)
├── config/
│   └── api_keys.json            # Optional API keys
├── output/                      # Scan results saved here
├── setup.sh                     # One-command setup
├── requirements.txt             # Python dependencies
├── LICENSE                      # MIT License
└── README.md                    # You are here
```

---

## 📊 Sample Output

The tool generates a JSON report like this:

```json
{
  "scan_info": {
    "tool": "Credential Leak Detector",
    "domain": "example.com",
    "timestamp": "2026-04-28T23:30:00",
    "duration_seconds": 145.2
  },
  "summary": {
    "emails_harvested": 12,
    "breach_sources_found": 3,
    "darkweb_mentions": 2,
    "threat_level": "HIGH",
    "critical_breaches": true
  },
  "results": [
    {
      "email": "admin@example.com",
      "breaches": {
        "sources": ["cit0day.in", "collection-1"],
        "count": 2,
        "is_critical": true
      },
      "darkweb": {
        "mentions": [...],
        "count": 1
      }
    }
  ]
}
```

**Threat Levels:**
- 🔴 `CRITICAL` — Credentials found in known major breach databases
- 🔴 `HIGH` — Breach sources or dark web mentions detected
- 🟡 `MEDIUM` — Emails found but no breaches detected
- 🟢 `LOW` — No emails found, domain-only scan performed
- ⚪ `NONE` — Scan complete, nothing found

---

## 🔧 How It Works

### Phase 1: Email Harvesting
Uses **theHarvester** to passively discover email addresses associated with the target domain. Sources include Bing, DuckDuckGo, crt.sh, and VirusTotal.

### Phase 2: Breach Detection
Takes discovered emails and runs them through **SpiderFoot** with breach-focused modules (Citadel, HaveIBeenPwned, LeakIX). Identifies which emails appear in known data breaches.

### Phase 3: Dark Web Investigation
Routes queries through **Tor** and uses **Darkdump** to search `.onion` sites for any mentions of the target emails or domain.

### Report Generation
Aggregates all findings into a single JSON report with threat level assessment.

---

## ⚠️ Disclaimer

This tool is built for **educational and authorized security testing purposes only**.

- Only scan domains you own or have explicit permission to test
- The author is not responsible for any misuse of this tool
- Always follow applicable laws and ethical guidelines

---

## 🧠 Skills Demonstrated

- **OSINT (Open Source Intelligence)** — Passive reconnaissance
- **Python Automation** — Multi-tool pipeline orchestration
- **Cybersecurity** — Breach detection, dark web monitoring
- **Tor Network** — Anonymous routing for dark web access
- **Modular Design** — Clean, extensible code architecture
- **Parallel Processing** — ThreadPoolExecutor for concurrent scans

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
