# 🎣 PhishHunter Pro — SOC Phishing IOC Analyzer

![Version](https://img.shields.io/badge/version-1.0.0-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)
![SOC](https://img.shields.io/badge/Tool-SOC%20Analyst-orange?style=flat-square)
![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%204%25-red?style=flat-square)
![MSLearn](https://img.shields.io/badge/Microsoft%20Learn-Level%209%20%7C%2064%20Badges-0078D4?style=flat-square)

> **Built by a SOC analyst, for SOC analysts.**
> Paste any suspicious email → auto-extract all IOCs → cross-reference
> VirusTotal & AbuseIPDB → generate Splunk / Sentinel / CrowdStrike / MDE
> detection queries → get prioritised security controls. All in one dark
> terminal-style tool.

---

## 🔴 Live Demo
🌐 **[Coming Soon — Deploying to GitHub Pages]**

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 IOC Extraction | Auto-extracts IPs, Domains, URLs, Emails, MD5/SHA1/SHA256 hashes, Attachments |
| ⚡ Threat Enrichment | VirusTotal (90 AV engines) + AbuseIPDB reputation cross-reference |
| 🗺️ MITRE ATT&CK | Auto-maps to techniques: T1566, T1071, T1078, T1059, T1027 |
| 📊 SIEM/EDR Queries | Splunk SPL, Microsoft Sentinel KQL, CrowdStrike, MDE — copy-paste ready |
| 🛡️ Security Controls | CRITICAL/HIGH/MEDIUM/LOW prioritised remediation with tool recommendations |
| 📈 Risk Scoring | Automated 0–100 phishing risk meter with visual indicator |
| 🎯 Spoof Detection | Detects mismatched headers, URL shorteners, high-risk attachment types |

---

## 🚀 Quick Start
```bash
git clone https://github.com/subhankarbhndr211/phishunter-pro-soc-tool.git
cd phishunter-pro-soc-tool
npm install
npm start
```

Open **http://localhost:3000** — click **"LOAD SAMPLE"** to test instantly. No API keys needed to run.

---

## 🔑 API Keys Setup (Optional — Enables Real Enrichment)

Create `.env.local` in the root folder:
```
REACT_APP_VT_API_KEY=your_virustotal_api_key
REACT_APP_ABUSE_API_KEY=your_abuseipdb_api_key
```

| Service | Free Tier | Get Key |
|---|---|---|
| VirusTotal | 4 lookups/min | [virustotal.com](https://virustotal.com) |
| AbuseIPDB | 1000/day | [abuseipdb.com](https://abuseipdb.com) |

---

## 📊 SIEM Queries Generated

| Platform | Language | Queries Included |
|---|---|---|
| Splunk Enterprise Security | SPL | 5 queries |
| Microsoft Sentinel | KQL | 4 queries |
| CrowdStrike Falcon | Event Search | 4 queries |
| Microsoft Defender for Endpoint | KQL | 4 queries |

---

## 🗂️ Project Structure
```
phishunter-pro-soc-tool/
├── src/
│   ├── components/
│   │   └── PhishingAnalyzer.jsx   ← Main IOC analyzer tool
│   ├── utils/
│   │   ├── iocExtractor.js        ← Regex-based IOC parsing
│   │   ├── enrichment.js          ← VT + AbuseIPDB API calls
│   │   └── queryGenerator.js      ← SIEM query templates
│   └── App.js
├── .env.example                   ← API key template (safe to commit)
├── .env.local                     ← Real API keys (never committed)
└── README.md
```

---

## 🛠️ Tech Stack

`React 18` · `JavaScript ES6+` · `VirusTotal API` · `AbuseIPDB API` · `MITRE ATT&CK` · `Regex IOC Engine` · `Splunk SPL` · `Microsoft Sentinel KQL`

---

## 👤 Author

**Subhankar Bhandari** — SOC Analyst | 8 Years IT | 5+ Years SOC Operations

| Platform | Details |
|---|---|
| 🎮 TryHackMe | [Top 4% Global](https://tryhackme.com/p/subhankarbhndr21) · Rank 57,907 · 75 rooms · 12 badges · SOC Level 1 |
| 🏅 Microsoft Learn | [Level 9](https://learn.microsoft.com/users/subhankarbhandari-9854) · 100,025 XP · 64 Badges |
| 📝 Medium | [Malware Analysis](https://medium.com/@subhankarbhndr211/malware-analysis-with-virus-total-1630f1d1f19e) · [MITRE ATT&CK](https://medium.com/@subhankarbhndr211/mitre-att-ck-framework-friend-of-all-5f1b6f96aeef) |
| 🏆 Certifications | ISC2 CC · SANS OSINT · CISA ICS · Splunk SOC Essentials · Fortinet NSE 1-3 |

---

## 📜 License

MIT License — Free to use, modify, and share with attribution.

---

⭐ **If this tool helped you, please star the repo — it helps other SOC analysts find it!**