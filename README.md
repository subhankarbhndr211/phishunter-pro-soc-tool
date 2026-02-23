# 🎣 PhishHunter Pro — SOC Phishing IOC Analyzer

![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)
![SOC](https://img.shields.io/badge/Tool-SOC%20Analyst-orange?style=flat-square)
![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%204%25-red?style=flat-square)
![MSLearn](https://img.shields.io/badge/Microsoft%20Learn-Level%209-0078D4?style=flat-square)

> **Built by a SOC analyst, for SOC analysts.**  
> Paste any suspicious email → auto-extract all IOCs → cross-reference  
> VirusTotal & AbuseIPDB → generate Splunk / Sentinel / CrowdStrike / MDE  
> detection queries → get prioritised security controls. All in one tool.

---

## 🔴 Live Demo
🌐 **[Coming Soon — GitHub Pages]**

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 IOC Extraction | Auto-extracts IPs, Domains, URLs, Emails, MD5/SHA1/SHA256 hashes, Attachments |
| ⚡ Threat Enrichment | VirusTotal (90 AV engines) + AbuseIPDB reputation cross-reference |
| 🗺️ MITRE ATT&CK | Auto-maps techniques: T1566, T1071, T1078, T1059, T1027 |
| 📊 SIEM/EDR Queries | Splunk SPL, Sentinel KQL, CrowdStrike, MDE — copy-paste ready |
| 🛡️ Security Controls | CRITICAL/HIGH/MEDIUM/LOW prioritised remediation recommendations |
| 📈 Risk Scoring | Automated 0–100 phishing risk meter |
| 🎯 Spoof Detection | Detects mismatched headers, URL shorteners, dangerous attachments |

---

## 🚀 Quick Start
```bash
git clone https://github.com/subhankarbhndr211/phishunter-pro-soc-tool.git
cd phishunter-pro-soc-tool
npm install
npm start
```

Open **http://localhost:3000** → Click **"LOAD SAMPLE"** to test instantly.

---

## 🔑 API Keys (Optional)

Create `.env.local` in root folder:
```
REACT_APP_VT_API_KEY=your_virustotal_key
REACT_APP_ABUSE_API_KEY=your_abuseipdb_key
```

| Service | Free Tier | Link |
|---|---|---|
| VirusTotal | 4 lookups/min | [virustotal.com](https://virustotal.com) |
| AbuseIPDB | 1000 checks/day | [abuseipdb.com](https://abuseipdb.com) |

---

## 📊 SIEM Queries Generated

| Platform | Language | Queries |
|---|---|---|
| Splunk Enterprise Security | SPL | 5 queries |
| Microsoft Sentinel | KQL | 4 queries |
| CrowdStrike Falcon | Event Search | 4 queries |
| Microsoft Defender (MDE) | KQL | 4 queries |

---

## 🛠️ Tech Stack

`React 18` · `JavaScript ES6+` · `VirusTotal API` · `AbuseIPDB API` · `MITRE ATT&CK` · `Splunk SPL` · `KQL`

---

## 👤 Author — Subhankar Bhandari

**SOC Analyst | 8 Years IT | 5+ Years SOC Operations**

| Platform | Details |
|---|---|
| 🎮 TryHackMe | [Top 4% Global](https://tryhackme.com/p/subhankarbhndr21) · Rank 57,907 · 75 rooms · SOC Level 1 Complete |
| 🏅 Microsoft Learn | [Level 9](https://learn.microsoft.com/users/subhankarbhandari-9854) · 100,025 XP · 64 Badges |
| 📝 Medium | [Malware Analysis](https://medium.com/@subhankarbhndr211/malware-analysis-with-virus-total-1630f1d1f19e) · [MITRE ATT&CK](https://medium.com/@subhankarbhndr211/mitre-att-ck-framework-friend-of-all-5f1b6f96aeef) |
| 🏆 Certs | ISC2 CC · SANS OSINT Summit · CISA ICS · Splunk SOC Essentials · Fortinet NSE 1-3 |

---

## 📜 License

MIT — Free to use, modify and share with attribution.

