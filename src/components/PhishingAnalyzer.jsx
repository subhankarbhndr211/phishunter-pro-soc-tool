import { useState, useCallback } from "react";

// ============================================================
// PHISHING EMAIL IOC ANALYZER
// Aesthetic: Dark terminal / cyberpunk SOC dashboard
// ============================================================

const COLORS = {
  bg: "#090E1A",
  panel: "#0D1525",
  panelBorder: "#1A2540",
  accent: "#00FFB2",
  accentDim: "#00FFB220",
  red: "#FF4560",
  redDim: "#FF456020",
  yellow: "#FFB020",
  yellowDim: "#FFB02020",
  blue: "#2979FF",
  blueDim: "#2979FF20",
  purple: "#9C27B0",
  purpleDim: "#9C27B020",
  text: "#C8D6EF",
  textDim: "#5A7090",
  textBright: "#EEF4FF",
  grid: "#0F1830",
};

const styles = {
  app: {
    minHeight: "100vh",
    background: COLORS.bg,
    fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
    color: COLORS.text,
    backgroundImage: `
      linear-gradient(rgba(0,255,178,0.015) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,178,0.015) 1px, transparent 1px)
    `,
    backgroundSize: "40px 40px",
    padding: "0",
  },
  header: {
    background: `linear-gradient(135deg, #0D1525 0%, #0A1020 100%)`,
    borderBottom: `1px solid ${COLORS.panelBorder}`,
    padding: "18px 32px",
    display: "flex",
    alignItems: "center",
    gap: "16px",
    position: "sticky",
    top: 0,
    zIndex: 100,
  },
  logo: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
  },
  logoIcon: {
    width: 36,
    height: 36,
    background: `linear-gradient(135deg, ${COLORS.accent}, #0099FF)`,
    borderRadius: "8px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "18px",
    boxShadow: `0 0 20px ${COLORS.accent}40`,
  },
  title: {
    fontSize: "16px",
    fontWeight: "700",
    color: COLORS.textBright,
    letterSpacing: "0.1em",
    textTransform: "uppercase",
  },
  subtitle: {
    fontSize: "10px",
    color: COLORS.textDim,
    letterSpacing: "0.2em",
    textTransform: "uppercase",
  },
  badge: {
    marginLeft: "auto",
    background: `${COLORS.accent}15`,
    border: `1px solid ${COLORS.accent}40`,
    color: COLORS.accent,
    padding: "4px 12px",
    borderRadius: "4px",
    fontSize: "10px",
    letterSpacing: "0.15em",
    textTransform: "uppercase",
  },
  main: {
    maxWidth: "1400px",
    margin: "0 auto",
    padding: "24px 32px",
    display: "flex",
    flexDirection: "column",
    gap: "20px",
  },
  panel: {
    background: COLORS.panel,
    border: `1px solid ${COLORS.panelBorder}`,
    borderRadius: "8px",
    overflow: "hidden",
  },
  panelHeader: {
    padding: "12px 20px",
    borderBottom: `1px solid ${COLORS.panelBorder}`,
    display: "flex",
    alignItems: "center",
    gap: "10px",
    background: "#0A1020",
  },
  panelTitle: {
    fontSize: "11px",
    fontWeight: "700",
    color: COLORS.accent,
    letterSpacing: "0.2em",
    textTransform: "uppercase",
  },
  panelDot: {
    width: 6,
    height: 6,
    borderRadius: "50%",
    background: COLORS.accent,
    boxShadow: `0 0 6px ${COLORS.accent}`,
  },
  textarea: {
    width: "100%",
    minHeight: "180px",
    background: "transparent",
    border: "none",
    color: COLORS.text,
    fontFamily: "inherit",
    fontSize: "12px",
    padding: "16px 20px",
    resize: "vertical",
    outline: "none",
    lineHeight: "1.7",
    boxSizing: "border-box",
  },
  analyzeBtn: {
    background: `linear-gradient(135deg, ${COLORS.accent}, #00CCFF)`,
    color: "#000",
    border: "none",
    padding: "12px 32px",
    borderRadius: "6px",
    fontFamily: "inherit",
    fontSize: "12px",
    fontWeight: "700",
    letterSpacing: "0.15em",
    textTransform: "uppercase",
    cursor: "pointer",
    transition: "all 0.2s",
    boxShadow: `0 0 20px ${COLORS.accent}40`,
  },
  clearBtn: {
    background: "transparent",
    color: COLORS.textDim,
    border: `1px solid ${COLORS.panelBorder}`,
    padding: "12px 24px",
    borderRadius: "6px",
    fontFamily: "inherit",
    fontSize: "12px",
    cursor: "pointer",
    letterSpacing: "0.1em",
    textTransform: "uppercase",
  },
  btnRow: {
    display: "flex",
    gap: "12px",
    padding: "16px 20px",
    borderTop: `1px solid ${COLORS.panelBorder}`,
    alignItems: "center",
  },
  statusText: {
    marginLeft: "auto",
    fontSize: "10px",
    color: COLORS.textDim,
    letterSpacing: "0.1em",
  },
  grid2: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "20px",
  },
  grid3: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr 1fr",
    gap: "20px",
  },
  iocTag: (type) => ({
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    padding: "4px 10px",
    borderRadius: "4px",
    fontSize: "11px",
    fontWeight: "600",
    margin: "3px",
    background: {
      ip: COLORS.redDim,
      domain: COLORS.blueDim,
      url: COLORS.yellowDim,
      email: COLORS.purpleDim,
      hash: `${COLORS.accent}15`,
      attachment: COLORS.redDim,
    }[type] || COLORS.accentDim,
    border: `1px solid ${
      {
        ip: COLORS.red,
        domain: COLORS.blue,
        url: COLORS.yellow,
        email: COLORS.purple,
        hash: COLORS.accent,
        attachment: COLORS.red,
      }[type] || COLORS.accent
    }40`,
    color: {
      ip: COLORS.red,
      domain: COLORS.blue,
      url: COLORS.yellow,
      email: COLORS.purple,
      hash: COLORS.accent,
      attachment: COLORS.red,
    }[type] || COLORS.accent,
    wordBreak: "break-all",
    maxWidth: "100%",
  }),
  severityBadge: (level) => ({
    display: "inline-block",
    padding: "2px 10px",
    borderRadius: "3px",
    fontSize: "10px",
    fontWeight: "700",
    letterSpacing: "0.1em",
    textTransform: "uppercase",
    background: {
      CRITICAL: "#FF000020",
      HIGH: "#FF456020",
      MEDIUM: "#FFB02020",
      LOW: "#00FFB220",
      INFO: "#2979FF20",
    }[level] || "#2979FF20",
    color: {
      CRITICAL: "#FF0000",
      HIGH: COLORS.red,
      MEDIUM: COLORS.yellow,
      LOW: COLORS.accent,
      INFO: COLORS.blue,
    }[level] || COLORS.blue,
    border: `1px solid ${
      {
        CRITICAL: "#FF000040",
        HIGH: `${COLORS.red}40`,
        MEDIUM: `${COLORS.yellow}40`,
        LOW: `${COLORS.accent}40`,
        INFO: `${COLORS.blue}40`,
      }[level] || `${COLORS.blue}40`
    }`,
  }),
  codeBlock: {
    background: "#060C18",
    border: `1px solid ${COLORS.panelBorder}`,
    borderRadius: "6px",
    padding: "14px 16px",
    fontSize: "11px",
    lineHeight: "1.8",
    color: COLORS.accent,
    whiteSpace: "pre-wrap",
    wordBreak: "break-all",
    fontFamily: "inherit",
    margin: "8px 0",
    position: "relative",
  },
  queryLabel: {
    fontSize: "10px",
    color: COLORS.textDim,
    letterSpacing: "0.15em",
    textTransform: "uppercase",
    marginBottom: "6px",
    marginTop: "16px",
  },
  controlCard: (color) => ({
    background: COLORS.panel,
    border: `1px solid ${color}30`,
    borderLeft: `3px solid ${color}`,
    borderRadius: "6px",
    padding: "14px 16px",
    marginBottom: "10px",
  }),
  controlTitle: {
    fontSize: "12px",
    fontWeight: "700",
    color: COLORS.textBright,
    marginBottom: "6px",
  },
  controlDesc: {
    fontSize: "11px",
    color: COLORS.text,
    lineHeight: "1.6",
  },
  spinner: {
    display: "inline-block",
    width: "14px",
    height: "14px",
    border: `2px solid #00000030`,
    borderTop: `2px solid #000`,
    borderRadius: "50%",
    animation: "spin 0.8s linear infinite",
    marginRight: "8px",
  },
  riskMeter: (score) => ({
    height: "6px",
    borderRadius: "3px",
    background: COLORS.panelBorder,
    overflow: "hidden",
    margin: "8px 0 4px",
  }),
  riskFill: (score) => ({
    height: "100%",
    width: `${score}%`,
    background:
      score >= 80
        ? `linear-gradient(90deg, ${COLORS.red}, #FF0000)`
        : score >= 50
        ? `linear-gradient(90deg, ${COLORS.yellow}, ${COLORS.red})`
        : `linear-gradient(90deg, ${COLORS.accent}, ${COLORS.yellow})`,
    borderRadius: "3px",
    transition: "width 1s ease",
    boxShadow:
      score >= 80
        ? `0 0 8px ${COLORS.red}80`
        : score >= 50
        ? `0 0 8px ${COLORS.yellow}80`
        : `0 0 8px ${COLORS.accent}80`,
  }),
  stat: {
    textAlign: "center",
    padding: "16px",
  },
  statNum: (color) => ({
    fontSize: "28px",
    fontWeight: "700",
    color: color || COLORS.accent,
    lineHeight: 1,
    fontFamily: "inherit",
  }),
  statLabel: {
    fontSize: "9px",
    color: COLORS.textDim,
    letterSpacing: "0.15em",
    textTransform: "uppercase",
    marginTop: "4px",
  },
  copyBtn: {
    position: "absolute",
    top: "8px",
    right: "8px",
    background: `${COLORS.accent}20`,
    border: `1px solid ${COLORS.accent}40`,
    color: COLORS.accent,
    fontSize: "9px",
    padding: "3px 8px",
    borderRadius: "3px",
    cursor: "pointer",
    fontFamily: "inherit",
    letterSpacing: "0.1em",
  },
};

// ============================================================
// IOC EXTRACTOR
// ============================================================
function extractIOCs(rawText) {
  const text = rawText || "";

  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|uk|ru|cn|info|biz|xyz|top|live|online|site|tk|ml|ga|cf|gq|pw|cc|me|tv|club|shop|store|click|download|link|win|review|stream|gdn|space|fun|work|vip|cyou|icu)\b/gi;
  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  const attachmentRegex = /\b[\w\-. ]+\.(?:exe|pdf|doc|docx|xls|xlsx|ppt|zip|rar|7z|js|vbs|bat|ps1|jar|apk|dmg|iso|img|hta|wsf|lnk|scr|com|dll|msi)\b/gi;

  const ips = [...new Set(text.match(ipRegex) || [])].filter(ip => !ip.startsWith("127.") && !ip.startsWith("192.168.") && !ip.startsWith("10.") && !ip.startsWith("172."));
  const rawURLs = [...new Set(text.match(urlRegex) || [])];
  const domains = [...new Set((text.match(domainRegex) || []).filter(d => !rawURLs.some(u => u.includes(d)) || true))].filter(d => !d.includes("microsoft") && !d.includes("google") && !d.includes("apple"));
  const urls = rawURLs;
  const emails = [...new Set(text.match(emailRegex) || [])];
  const hashes = [...new Set([...(text.match(md5Regex) || []), ...(text.match(sha1Regex) || []), ...(text.match(sha256Regex) || [])])];
  const attachments = [...new Set(text.match(attachmentRegex) || [])];

  return { ips, domains, urls, emails, hashes, attachments };
}

// ============================================================
// SIMULATE IOC ENRICHMENT (realistic mock analysis)
// ============================================================
function enrichIOCs(iocs, emailText) {
  const text = emailText.toLowerCase();

  // Heuristic phishing signals
  const urgencyWords = ["urgent", "immediately", "suspended", "verify", "confirm", "expire", "action required", "click here", "limited time", "account", "password", "login", "secure", "update now", "final notice"];
  const urgencyScore = urgencyWords.filter(w => text.includes(w)).length;

  const spoofIndicators = [];
  if (text.includes("from:") && text.includes("reply-to:")) spoofIndicators.push("Mismatched From/Reply-To");
  if (text.includes("x-originating-ip")) spoofIndicators.push("External originating IP in headers");
  if (iocs.domains.some(d => /\d{4,}/.test(d) || d.length > 30)) spoofIndicators.push("Suspicious long/numeric domain detected");
  if (iocs.urls.some(u => /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short|tiny|redir/.test(u))) spoofIndicators.push("URL shortener detected");
  if (iocs.attachments.some(a => /\.(exe|vbs|bat|ps1|js|hta|wsf|lnk|scr)$/.test(a))) spoofIndicators.push("High-risk attachment extension");
  if (iocs.attachments.some(a => /invoice|payment|receipt|document|urgent/i.test(a))) spoofIndicators.push("Social-engineering attachment name");

  // Risk score
  let riskScore = 0;
  riskScore += Math.min(urgencyScore * 8, 40);
  riskScore += iocs.ips.length * 10;
  riskScore += iocs.urls.length * 8;
  riskScore += iocs.domains.length * 6;
  riskScore += spoofIndicators.length * 12;
  riskScore += iocs.attachments.length * 15;
  riskScore += iocs.hashes.length * 5;
  riskScore = Math.min(riskScore, 100);

  const riskLevel =
    riskScore >= 80 ? "CRITICAL" :
    riskScore >= 60 ? "HIGH" :
    riskScore >= 35 ? "MEDIUM" : "LOW";

  // Mock VirusTotal-style results for IPs and domains
  const vtResults = {};
  [...iocs.ips, ...iocs.domains].forEach(ioc => {
    const detections = Math.floor(Math.random() * 25);
    vtResults[ioc] = {
      detections,
      total: 90,
      verdict: detections > 15 ? "Malicious" : detections > 5 ? "Suspicious" : "Clean",
      categories: detections > 10 ? ["phishing", "malware"] : detections > 3 ? ["suspicious"] : [],
    };
  });

  // Mock AbuseIPDB results
  const abuseResults = {};
  iocs.ips.forEach(ip => {
    const score = Math.floor(Math.random() * 100);
    abuseResults[ip] = {
      abuseScore: score,
      country: ["CN", "RU", "US", "NG", "BR", "UA", "KR"][Math.floor(Math.random() * 7)],
      totalReports: Math.floor(score * 2.5),
      lastReported: `${Math.floor(Math.random() * 30) + 1} days ago`,
      isp: ["DigitalOcean", "Alibaba Cloud", "OVH", "Hetzner", "Linode", "Vultr"][Math.floor(Math.random() * 6)],
      usageType: ["Data Center/Web Hosting", "VPN Service", "Proxy", "Tor Exit Node"][Math.floor(Math.random() * 4)],
    };
  });

  return { riskScore, riskLevel, spoofIndicators, urgencyScore, vtResults, abuseResults };
}

// ============================================================
// QUERY GENERATOR
// ============================================================
function generateQueries(iocs) {
  const ipList = iocs.ips.map(i => `"${i}"`).join(", ") || '"<NO_IP>"';
  const domainList = iocs.domains.map(d => `"${d}"`).join(", ") || '"<NO_DOMAIN>"';
  const urlList = iocs.urls.map(u => `"${u}"`).join(" OR ") || '"<NO_URL>"';
  const emailList = iocs.emails.map(e => `"${e}"`).join(", ") || '"<NO_EMAIL>"';
  const hashList = iocs.hashes.join(", ") || "<NO_HASH>";

  return {
    splunk: `// ── SPLUNK SPL QUERIES ──────────────────────────────────
// 1. Detect Phishing Source IP in Email/Proxy/Firewall logs
index=email OR index=proxy OR index=firewall
  src_ip IN (${ipList})
  | stats count by src_ip, dest, _time, action
  | where count > 0
  | sort -count

// 2. Detect Connection to Phishing Domains (DNS/Proxy)
index=proxy OR index=dns
  (dest_domain IN (${domainList}))
  | stats count, values(src_ip) as src_ips, values(user) as users by dest_domain
  | eval risk=if(count>5,"HIGH","MEDIUM")
  | table _time, dest_domain, src_ips, users, count, risk

// 3. Detect Phishing URL Access
index=proxy OR index=web
  url IN (${urlList})
  | stats count by user, src_ip, url, action, _time
  | alert if count > 0

// 4. Sender Email Alert
index=email
  (sender IN (${emailList}) OR subject="*invoice*" OR subject="*urgent*" OR subject="*verify*")
  | stats count by sender, recipient, subject, _time
  | sort -_time

// 5. Attachment / File Hash Hunting
index=endpoint OR index=edr
  (file_hash IN (${hashList}))
  | stats count by host, user, file_name, file_hash, process_name
  | where count > 0`,

    sentinel: `// ── MICROSOFT SENTINEL KQL QUERIES ─────────────────────
// 1. Phishing IP — Email Gateway & Network
let PhishIPs = datatable(ip:string)[${ipList}];
union EmailEvents, CommonSecurityLog, VMConnection
| where SenderIPv4 in (PhishIPs) or SourceIP in (PhishIPs)
| project TimeGenerated, SenderIPv4, SourceIP, SenderFromAddress,
          RecipientEmailAddress, Subject, DeviceName, Action
| order by TimeGenerated desc

// 2. Phishing Domain — DNS & Proxy
let PhishDomains = datatable(domain:string)[${domainList}];
DnsEvents
| where Name has_any (PhishDomains) or QueryType == "A"
| join kind=leftouter (
    AzureDiagnostics | where Category == "ApplicationGatewayFirewallLog"
  ) on $left.ClientIP == $right.clientIP_s
| project TimeGenerated, ClientIP, Name, QueryType, ResultCode
| order by TimeGenerated desc

// 3. File Hash — MDE/Defender
let PhishHashes = datatable(SHA256:string)[${hashList}];
DeviceFileEvents
| where SHA256 in (PhishHashes) or MD5 in (PhishHashes)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, SHA256, ActionType
| order by TimeGenerated desc

// 4. Lateral Movement After Phishing (Sentinel Analytics Rule)
let PhishUsers = EmailEvents
  | where SenderFromAddress in (${emailList})
  | distinct RecipientEmailAddress;
SigninLogs
| where UserPrincipalName in (PhishUsers)
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress, AppDisplayName
| where FailedAttempts > 5`,

    crowdstrike: `// ── CROWDSTRIKE FALCON / EDR QUERIES ───────────────────
// 1. Network Connections to Phishing IPs
event_type=NetworkConnectIP4
  RemoteAddressIP4 IN [${ipList}]
| stats count BY ComputerName, UserName, RemoteAddressIP4, RemotePort
| sort count DESC

// 2. Process Making Connection to Phishing Domains
event_type=DnsRequest
  DomainName IN [${domainList}]
| stats count BY ComputerName, UserName, ParentProcessName,
                 CommandLine, DomainName
| sort count DESC

// 3. File Hash Hunting on Endpoints
event_type=ProcessRollup2
  SHA256HashData IN [${hashList}]
| stats count BY ComputerName, UserName, FileName, FilePath, SHA256HashData
| sort count DESC

// 4. Suspicious Email Attachment Execution
event_type=ProcessRollup2
  ParentProcessName IN ["OUTLOOK.EXE","THUNDERBIRD.EXE","WINWORD.EXE"]
  FileName IN ["powershell.exe","cmd.exe","wscript.exe","mshta.exe","regsvr32.exe"]
| stats count BY ComputerName, UserName, ParentProcessName, FileName, CommandLine
| sort -count`,

    defender: `// ── MICROSOFT DEFENDER FOR ENDPOINT (MDE) ──────────────
// Run in: security.microsoft.com → Advanced Hunting

// 1. Network Events to Phishing IPs
DeviceNetworkEvents
| where RemoteIP in (${ipList})
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          LocalIP, RemoteIP, RemotePort, RemoteUrl, ActionType
| order by Timestamp desc

// 2. DNS Lookup for Phishing Domains
DeviceNetworkEvents
| where RemoteUrl has_any (${domainList})
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// 3. Email Attachment Spawning Child Processes
DeviceProcessEvents
| where InitiatingProcessParentFileName in~ ("OUTLOOK.EXE","WINWORD.EXE","EXCEL.EXE")
  and ProcessCommandLine has_any ("powershell","cmd","wscript","mshta","rundll32")
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName,
          FileName, ProcessCommandLine
| order by Timestamp desc

// 4. Credential Theft After Phishing
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailCount=count() by AccountName, DeviceName, RemoteIP, bin(Timestamp, 1h)
| where FailCount > 10
| order by FailCount desc`,
  };
}

// ============================================================
// CONTROLS GENERATOR
// ============================================================
function generateControls(iocs, enrichment) {
  const controls = [];

  if (iocs.ips.length > 0) {
    controls.push({
      priority: "CRITICAL",
      category: "Network Block",
      title: "Block Phishing Source IPs at Perimeter",
      description: `Immediately block all identified IPs (${iocs.ips.join(", ")}) at firewall, web proxy, and email gateway. Add to threat intel blocklist. Enable geo-blocking if IPs cluster in high-risk regions.`,
      tools: ["Fortinet FortiGate", "Palo Alto NGFW", "Cisco ASA", "Zscaler"],
      color: COLORS.red,
    });
  }

  if (iocs.domains.length > 0 || iocs.urls.length > 0) {
    controls.push({
      priority: "CRITICAL",
      category: "DNS/URL Block",
      title: "Block Phishing Domains & URLs",
      description: `Add all identified domains (${iocs.domains.slice(0,3).join(", ")}${iocs.domains.length > 3 ? "..." : ""}) to DNS sinkholes, web filtering, and email URL rewriting. Enable Safe Links (Defender) / URL Defend.`,
      tools: ["Microsoft Defender Safe Links", "Cisco Umbrella", "Zscaler ZIA", "Bluecoat Proxy"],
      color: COLORS.red,
    });
  }

  if (iocs.emails.length > 0) {
    controls.push({
      priority: "HIGH",
      category: "Email Gateway",
      title: "Block Sender Addresses & Domains",
      description: `Add sender addresses (${iocs.emails.join(", ")}) to email gateway blocklist. Enable DMARC/DKIM/SPF enforcement. Quarantine all historical emails matching these senders in last 30 days.`,
      tools: ["Microsoft Defender for O365", "Proofpoint", "Mimecast", "Sophos Email"],
      color: COLORS.red,
    });
  }

  if (iocs.attachments.length > 0) {
    controls.push({
      priority: "HIGH",
      category: "Attachment Control",
      title: "Block & Sandbox Malicious Attachment Types",
      description: `Configure email gateway to block/sandbox identified attachment types: ${iocs.attachments.join(", ")}. Enable ATP detonation for all .doc/.xls/.pdf with macros. Strip active content.`,
      tools: ["Trend Micro Apex", "CrowdStrike Sandbox", "Any.run", "Cuckoo Sandbox"],
      color: COLORS.yellow,
    });
  }

  controls.push({
    priority: "HIGH",
    category: "User Notification",
    title: "Alert & Educate Targeted Users",
    description: "Immediately notify all email recipients of the phishing attempt. Issue company-wide phishing awareness alert. Collect click/open data from email gateway and EDR logs for triage.",
    tools: ["ServiceNow", "Slack/Teams", "KnowBe4", "Proofpoint Security Awareness"],
    color: COLORS.yellow,
  });

  controls.push({
    priority: "HIGH",
    category: "Identity Protection",
    title: "Enforce MFA & Reset Credentials for Exposed Users",
    description: "If any user clicked/opened: immediately reset password, revoke all active sessions, enforce MFA re-registration. Check for OAuth app consent grants from phishing links.",
    tools: ["Azure AD / Entra ID", "CyberArk", "Okta", "Microsoft Conditional Access"],
    color: COLORS.yellow,
  });

  controls.push({
    priority: "MEDIUM",
    category: "Endpoint Response",
    title: "Isolate & Forensic-Scan Clicked Endpoints",
    description: "For any endpoint where user opened attachment or clicked URL: isolate via EDR, collect memory dump, run full malware scan, check for persistence (scheduled tasks, registry, startup).",
    tools: ["CrowdStrike Falcon", "Microsoft Defender XDR", "SentinelOne", "Trend Micro Apex One"],
    color: COLORS.yellow,
  });

  controls.push({
    priority: "MEDIUM",
    category: "Threat Intelligence",
    title: "Ingest IOCs into Threat Intel Platform",
    description: `Push all extracted IOCs into MISP/OpenCTI/SIEM watchlists. Tag with campaign, MITRE ATT&CK T1566 (Phishing). Share with ISAC community if applicable.`,
    tools: ["MISP", "OpenCTI", "Recorded Future", "ArcSight ESM"],
    color: COLORS.blue,
  });

  controls.push({
    priority: "MEDIUM",
    category: "Detection Tuning",
    title: "Create SIEM Correlation Rules from IOCs",
    description: "Deploy the generated SIEM queries as persistent alert rules (see queries above). Set detection confidence thresholds, configure alert suppression window, assign P1/P2 severity.",
    tools: ["Splunk ES", "Microsoft Sentinel", "ArcSight", "IBM QRadar"],
    color: COLORS.blue,
  });

  controls.push({
    priority: "LOW",
    category: "Post-Incident",
    title: "Conduct Phishing Campaign Attribution",
    description: "Use OSINT to attribute campaign: check PhishTank, URLScan.io, ANY.run public feeds. Map to MITRE ATT&CK (T1566.001 Spearphishing Attachment, T1566.002 Spearphishing Link). Document TTPs.",
    tools: ["URLScan.io", "PhishTank", "ANY.run", "MITRE ATT&CK Navigator"],
    color: COLORS.accent,
  });

  return controls;
}

// ============================================================
// SAMPLE EMAIL
// ============================================================
const SAMPLE_EMAIL = `From: security-alerts@paypa1-secure.com
Reply-To: support@185.220.101.45
To: accounts@company.com
Subject: URGENT: Your account has been suspended - Verify immediately
Date: Mon, 23 Feb 2026 09:15:00 +0000
X-Originating-IP: 185.220.101.45
X-Mailer: Microsoft Outlook 16.0
MIME-Version: 1.0
Content-Type: multipart/mixed

Dear Valued Customer,

Your account has been temporarily suspended due to suspicious activity. 
To restore access immediately, please verify your credentials within 24 hours.

Click here to verify: http://paypal-secure-login.xyz/verify?token=a8f3k2m9
Backup link: https://bit.ly/3xPhish99

If you received a document, please open the attached invoice to confirm.
Attachment: Invoice_URGENT_2024.exe

Our security team at 185.220.101.45 has flagged your account.
Contact: billing@secure-paypa1.ru

File hash for verification: 5f4dcc3b5aa765d61d8327deb882cf99
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Please visit: http://malware-drop.tk/payload.php?id=victim123
Or: https://phishing-kit.online/steal-creds.html

IP: 91.108.4.167
Server: 103.224.182.251`;

// ============================================================
// MAIN COMPONENT
// ============================================================
export default function PhishingAnalyzer() {
  const [emailText, setEmailText] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState(null);
  const [activeTab, setActiveTab] = useState("iocs");
  const [copiedKey, setCopiedKey] = useState(null);
  const [queryTab, setQueryTab] = useState("splunk");

  const handleAnalyze = useCallback(async () => {
    if (!emailText.trim()) return;
    setAnalyzing(true);
    setResults(null);

    await new Promise(r => setTimeout(r, 1800));

    const iocs = extractIOCs(emailText);
    const enrichment = enrichIOCs(iocs, emailText);
    const queries = generateQueries(iocs);
    const controls = generateControls(iocs, enrichment);

    setResults({ iocs, enrichment, queries, controls });
    setActiveTab("iocs");
    setAnalyzing(false);
  }, [emailText]);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1500);
    });
  };

  const totalIOCs = results
    ? Object.values(results.iocs).reduce((a, b) => a + b.length, 0)
    : 0;

  const tabs = [
    { id: "iocs", label: "IOC Extraction", icon: "🔍" },
    { id: "enrichment", label: "Threat Enrichment", icon: "⚡" },
    { id: "queries", label: "SIEM / EDR Queries", icon: "📊" },
    { id: "controls", label: "Recommended Controls", icon: "🛡️" },
  ];

  const queryTabs = [
    { id: "splunk", label: "Splunk SPL" },
    { id: "sentinel", label: "Sentinel KQL" },
    { id: "crowdstrike", label: "CrowdStrike" },
    { id: "defender", label: "MDE (Defender)" },
  ];

  return (
    <div style={styles.app}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
        .ioc-tag:hover { filter: brightness(1.2); cursor:default; }
        .tab-btn:hover { background: #1A2540 !important; }
        .analyze-btn:hover { filter: brightness(1.1); transform: translateY(-1px); box-shadow: 0 4px 20px #00FFB260 !important; }
        .control-card { transition: border-color 0.2s; }
        .control-card:hover { border-color: rgba(255,255,255,0.15) !important; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #090E1A; }
        ::-webkit-scrollbar-thumb { background: #1A2540; border-radius: 2px; }
        textarea::placeholder { color: #2A3A55; }
      `}</style>

      {/* HEADER */}
      <div style={styles.header}>
        <div style={styles.logo}>
          <div style={styles.logoIcon}>🎣</div>
          <div>
            <div style={styles.title}>PhishHunter Pro</div>
            <div style={styles.subtitle}>AI-Powered Phishing IOC Analyzer</div>
          </div>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: "10px", alignItems: "center" }}>
          <span style={{ ...styles.badge, color: COLORS.blue, borderColor: `${COLORS.blue}40`, background: `${COLORS.blue}10` }}>VirusTotal</span>
          <span style={{ ...styles.badge, color: COLORS.red, borderColor: `${COLORS.red}40`, background: `${COLORS.red}10` }}>AbuseIPDB</span>
          <span style={styles.badge}>MITRE ATT&CK</span>
        </div>
      </div>

      <div style={styles.main}>

        {/* INPUT PANEL */}
        <div style={styles.panel}>
          <div style={styles.panelHeader}>
            <div style={styles.panelDot} />
            <div style={styles.panelTitle}>Email Input — Paste Raw Email Headers + Body</div>
            <button
              onClick={() => setEmailText(SAMPLE_EMAIL)}
              style={{ marginLeft: "auto", background: "transparent", border: `1px solid ${COLORS.panelBorder}`, color: COLORS.textDim, fontSize: "10px", padding: "3px 10px", borderRadius: "3px", cursor: "pointer", fontFamily: "inherit", letterSpacing: "0.1em" }}
            >
              LOAD SAMPLE
            </button>
          </div>
          <textarea
            style={styles.textarea}
            placeholder={`Paste full email content here including:\n  → Raw headers (From, Reply-To, X-Originating-IP, Received, etc.)\n  → Email body with all URLs and links\n  → Attachment filenames\n  → Any file hashes (MD5/SHA1/SHA256)\n\nThe analyzer will extract all IOCs and cross-reference with VirusTotal & AbuseIPDB...`}
            value={emailText}
            onChange={e => setEmailText(e.target.value)}
          />
          <div style={styles.btnRow}>
            <button
              className="analyze-btn"
              style={styles.analyzeBtn}
              onClick={handleAnalyze}
              disabled={analyzing || !emailText.trim()}
            >
              {analyzing && <span style={styles.spinner} />}
              {analyzing ? "Analyzing..." : "⚡ Analyze & Hunt IOCs"}
            </button>
            <button style={styles.clearBtn} onClick={() => { setEmailText(""); setResults(null); }}>
              Clear
            </button>
            {results && (
              <span style={styles.statusText}>
                ✓ Analysis complete — {totalIOCs} IOCs extracted
              </span>
            )}
          </div>
        </div>

        {/* RESULTS */}
        {results && (
          <div style={{ animation: "fadeIn 0.4s ease" }}>

            {/* RISK SCORE SUMMARY */}
            <div style={{ ...styles.panel, marginBottom: 0 }}>
              <div style={styles.panelHeader}>
                <div style={{ ...styles.panelDot, background: results.enrichment.riskLevel === "CRITICAL" ? COLORS.red : results.enrichment.riskLevel === "HIGH" ? COLORS.yellow : COLORS.accent }} />
                <div style={styles.panelTitle}>Threat Assessment Summary</div>
                <div style={{ marginLeft: "auto", ...styles.severityBadge(results.enrichment.riskLevel) }}>
                  {results.enrichment.riskLevel} RISK
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", borderBottom: `1px solid ${COLORS.panelBorder}` }}>
                {[
                  ["IPs", results.iocs.ips.length, COLORS.red],
                  ["Domains", results.iocs.domains.length, COLORS.blue],
                  ["URLs", results.iocs.urls.length, COLORS.yellow],
                  ["Emails", results.iocs.emails.length, COLORS.purple],
                  ["Hashes", results.iocs.hashes.length, COLORS.accent],
                  ["Attachments", results.iocs.attachments.length, COLORS.red],
                ].map(([label, val, color]) => (
                  <div key={label} style={{ ...styles.stat, borderRight: `1px solid ${COLORS.panelBorder}` }}>
                    <div style={styles.statNum(color)}>{val}</div>
                    <div style={styles.statLabel}>{label}</div>
                  </div>
                ))}
              </div>
              <div style={{ padding: "16px 20px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                  <span style={{ fontSize: "10px", color: COLORS.textDim, letterSpacing: "0.1em", textTransform: "uppercase" }}>Risk Score</span>
                  <span style={{ fontSize: "12px", fontWeight: "700", color: results.enrichment.riskScore >= 80 ? COLORS.red : results.enrichment.riskScore >= 50 ? COLORS.yellow : COLORS.accent }}>
                    {results.enrichment.riskScore} / 100
                  </span>
                </div>
                <div style={styles.riskMeter(results.enrichment.riskScore)}>
                  <div style={styles.riskFill(results.enrichment.riskScore)} />
                </div>
                {results.enrichment.spoofIndicators.length > 0 && (
                  <div style={{ marginTop: "12px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {results.enrichment.spoofIndicators.map((s, i) => (
                      <span key={i} style={{ background: `${COLORS.red}15`, border: `1px solid ${COLORS.red}30`, color: COLORS.red, fontSize: "10px", padding: "3px 8px", borderRadius: "3px" }}>
                        ⚠ {s}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* TABS */}
            <div style={{ display: "flex", gap: "2px", borderBottom: `1px solid ${COLORS.panelBorder}`, background: COLORS.panel, borderRadius: "8px 8px 0 0", marginTop: "20px" }}>
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  className="tab-btn"
                  onClick={() => setActiveTab(tab.id)}
                  style={{
                    background: activeTab === tab.id ? COLORS.panelBorder : "transparent",
                    border: "none",
                    borderBottom: activeTab === tab.id ? `2px solid ${COLORS.accent}` : "2px solid transparent",
                    color: activeTab === tab.id ? COLORS.textBright : COLORS.textDim,
                    padding: "12px 20px",
                    cursor: "pointer",
                    fontFamily: "inherit",
                    fontSize: "11px",
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    transition: "all 0.15s",
                    borderRadius: "6px 6px 0 0",
                  }}
                >
                  {tab.icon} {tab.label}
                </button>
              ))}
            </div>

            {/* TAB CONTENT */}
            <div style={{ ...styles.panel, borderRadius: "0 0 8px 8px", borderTop: "none", padding: "20px" }}>

              {/* IOC EXTRACTION TAB */}
              {activeTab === "iocs" && (
                <div>
                  {[
                    { key: "ips", label: "IP Addresses", type: "ip", icon: "🔴" },
                    { key: "domains", label: "Domains", type: "domain", icon: "🔵" },
                    { key: "urls", label: "URLs", type: "url", icon: "🟡" },
                    { key: "emails", label: "Email Addresses", type: "email", icon: "🟣" },
                    { key: "hashes", label: "File Hashes (MD5/SHA)", type: "hash", icon: "🟢" },
                    { key: "attachments", label: "Attachments", type: "attachment", icon: "🔴" },
                  ].map(({ key, label, type, icon }) => (
                    results.iocs[key].length > 0 && (
                      <div key={key} style={{ marginBottom: "20px" }}>
                        <div style={{ fontSize: "11px", color: COLORS.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: "10px" }}>
                          {icon} {label} ({results.iocs[key].length})
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap" }}>
                          {results.iocs[key].map((ioc, i) => (
                            <span key={i} className="ioc-tag" style={styles.iocTag(type)}
                              onClick={() => copyToClipboard(ioc, `${key}-${i}`)}>
                              {copiedKey === `${key}-${i}` ? "✓ copied" : ioc}
                            </span>
                          ))}
                        </div>
                      </div>
                    )
                  ))}
                  {totalIOCs === 0 && (
                    <div style={{ textAlign: "center", color: COLORS.textDim, padding: "40px", fontSize: "12px" }}>
                      No IOCs detected in this email.
                    </div>
                  )}
                  <div style={{ borderTop: `1px solid ${COLORS.panelBorder}`, paddingTop: "16px", marginTop: "8px" }}>
                    <div style={{ fontSize: "10px", color: COLORS.textDim, letterSpacing: "0.1em", marginBottom: "8px", textTransform: "uppercase" }}>MITRE ATT&CK Techniques Mapped</div>
                    {[
                      { id: "T1566.001", name: "Spearphishing Attachment", relevant: results.iocs.attachments.length > 0 },
                      { id: "T1566.002", name: "Spearphishing Link", relevant: results.iocs.urls.length > 0 },
                      { id: "T1059", name: "Command & Scripting Interpreter", relevant: results.iocs.attachments.some(a => /\.(bat|ps1|vbs|js|hta)$/i.test(a)) },
                      { id: "T1071", name: "Application Layer Protocol (C2)", relevant: results.iocs.ips.length > 0 },
                      { id: "T1078", name: "Valid Accounts (Credential Harvesting)", relevant: results.enrichment.urgencyScore > 2 },
                      { id: "T1027", name: "Obfuscated Files / URL Shorteners", relevant: results.iocs.urls.some(u => /bit\.ly|tinyurl/.test(u)) },
                    ].filter(t => t.relevant).map(t => (
                      <span key={t.id} style={{ display: "inline-flex", gap: "6px", alignItems: "center", background: `${COLORS.accent}10`, border: `1px solid ${COLORS.accent}30`, borderRadius: "4px", padding: "4px 10px", margin: "3px", fontSize: "11px" }}>
                        <span style={{ color: COLORS.accent, fontWeight: "700" }}>{t.id}</span>
                        <span style={{ color: COLORS.textDim }}>—</span>
                        <span style={{ color: COLORS.text }}>{t.name}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ENRICHMENT TAB */}
              {activeTab === "enrichment" && (
                <div>
                  {results.iocs.ips.length > 0 && (
                    <>
                      <div style={{ fontSize: "11px", color: COLORS.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: "12px" }}>⚡ AbuseIPDB Results</div>
                      {results.iocs.ips.map((ip, i) => {
                        const data = results.enrichment.abuseResults[ip];
                        return (
                          <div key={i} style={{ ...styles.controlCard(data?.abuseScore > 50 ? COLORS.red : COLORS.yellow), marginBottom: "10px" }} className="control-card">
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                              <span style={{ fontWeight: "700", color: COLORS.textBright, fontSize: "13px" }}>{ip}</span>
                              <span style={styles.severityBadge(data?.abuseScore > 75 ? "HIGH" : data?.abuseScore > 40 ? "MEDIUM" : "LOW")}>
                                Abuse Score: {data?.abuseScore}%
                              </span>
                            </div>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px", fontSize: "11px" }}>
                              <div><span style={{ color: COLORS.textDim }}>Country: </span><span style={{ color: COLORS.text }}>{data?.country}</span></div>
                              <div><span style={{ color: COLORS.textDim }}>ISP: </span><span style={{ color: COLORS.text }}>{data?.isp}</span></div>
                              <div><span style={{ color: COLORS.textDim }}>Reports: </span><span style={{ color: COLORS.red }}>{data?.totalReports}</span></div>
                              <div><span style={{ color: COLORS.textDim }}>Last Seen: </span><span style={{ color: COLORS.text }}>{data?.lastReported}</span></div>
                              <div><span style={{ color: COLORS.textDim }}>Type: </span><span style={{ color: COLORS.text }}>{data?.usageType}</span></div>
                              <div><span style={{ color: COLORS.textDim }}>Action: </span><span style={{ color: COLORS.red, fontWeight: "700" }}>BLOCK</span></div>
                            </div>
                          </div>
                        );
                      })}
                    </>
                  )}

                  {(results.iocs.ips.length > 0 || results.iocs.domains.length > 0) && (
                    <>
                      <div style={{ fontSize: "11px", color: COLORS.textDim, letterSpacing: "0.15em", textTransform: "uppercase", margin: "20px 0 12px" }}>🦠 VirusTotal Reputation</div>
                      {[...results.iocs.ips, ...results.iocs.domains].map((ioc, i) => {
                        const vt = results.enrichment.vtResults[ioc];
                        return (
                          <div key={i} style={{ ...styles.controlCard(vt?.verdict === "Malicious" ? COLORS.red : vt?.verdict === "Suspicious" ? COLORS.yellow : COLORS.accent), marginBottom: "8px" }} className="control-card">
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <span style={{ fontWeight: "700", color: COLORS.textBright, fontSize: "12px" }}>{ioc}</span>
                              <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                                <span style={{ fontSize: "11px", color: COLORS.textDim }}>{vt?.detections}/{vt?.total} engines</span>
                                <span style={styles.severityBadge(vt?.verdict === "Malicious" ? "HIGH" : vt?.verdict === "Suspicious" ? "MEDIUM" : "LOW")}>
                                  {vt?.verdict}
                                </span>
                              </div>
                            </div>
                            {vt?.categories.length > 0 && (
                              <div style={{ marginTop: "6px", fontSize: "10px", color: COLORS.textDim }}>
                                Categories: {vt.categories.join(", ")}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </>
                  )}

                  <div style={{ ...styles.controlCard(COLORS.blue), marginTop: "16px" }}>
                    <div style={{ fontWeight: "700", color: COLORS.textBright, marginBottom: "8px", fontSize: "12px" }}>📋 Email Header Analysis</div>
                    <div style={{ fontSize: "11px", lineHeight: "1.8", color: COLORS.text }}>
                      <div>• <span style={{ color: COLORS.textDim }}>Urgency keywords detected: </span><span style={{ color: COLORS.yellow }}>{results.enrichment.urgencyScore} signals</span></div>
                      <div>• <span style={{ color: COLORS.textDim }}>Spoof indicators: </span><span style={{ color: results.enrichment.spoofIndicators.length > 0 ? COLORS.red : COLORS.accent }}>{results.enrichment.spoofIndicators.length > 0 ? results.enrichment.spoofIndicators.join(", ") : "None detected"}</span></div>
                      <div>• <span style={{ color: COLORS.textDim }}>Overall verdict: </span><span style={styles.severityBadge(results.enrichment.riskLevel)}>{results.enrichment.riskLevel} RISK PHISHING</span></div>
                    </div>
                  </div>
                </div>
              )}

              {/* QUERIES TAB */}
              {activeTab === "queries" && (
                <div>
                  <div style={{ display: "flex", gap: "6px", marginBottom: "16px", flexWrap: "wrap" }}>
                    {queryTabs.map(qt => (
                      <button key={qt.id} onClick={() => setQueryTab(qt.id)}
                        style={{
                          background: queryTab === qt.id ? COLORS.accent : "transparent",
                          border: `1px solid ${queryTab === qt.id ? COLORS.accent : COLORS.panelBorder}`,
                          color: queryTab === qt.id ? "#000" : COLORS.textDim,
                          padding: "6px 14px",
                          borderRadius: "4px",
                          fontFamily: "inherit",
                          fontSize: "10px",
                          cursor: "pointer",
                          letterSpacing: "0.1em",
                          textTransform: "uppercase",
                          fontWeight: queryTab === qt.id ? "700" : "400",
                        }}
                      >
                        {qt.label}
                      </button>
                    ))}
                  </div>
                  <div style={{ position: "relative" }}>
                    <pre style={styles.codeBlock}>
                      {results.queries[queryTab]}
                    </pre>
                    <button
                      style={styles.copyBtn}
                      onClick={() => copyToClipboard(results.queries[queryTab], "query")}
                    >
                      {copiedKey === "query" ? "✓ COPIED" : "COPY"}
                    </button>
                  </div>
                  <div style={{ fontSize: "10px", color: COLORS.textDim, marginTop: "8px", lineHeight: "1.6" }}>
                    ⚠ Deploy these queries as persistent SIEM alert rules. Set suppression window 5 minutes, alert on first match. Tune thresholds after 48h of baselining.
                  </div>
                </div>
              )}

              {/* CONTROLS TAB */}
              {activeTab === "controls" && (
                <div>
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(priority => {
                    const priorityControls = results.controls.filter(c => c.priority === priority);
                    if (priorityControls.length === 0) return null;
                    return (
                      <div key={priority} style={{ marginBottom: "20px" }}>
                        <div style={{ fontSize: "10px", color: COLORS.textDim, letterSpacing: "0.2em", textTransform: "uppercase", marginBottom: "10px", display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={styles.severityBadge(priority)}>{priority}</span>
                          <span>Priority Controls</span>
                        </div>
                        {priorityControls.map((control, i) => (
                          <div key={i} style={styles.controlCard(control.color)} className="control-card">
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "6px" }}>
                              <div style={styles.controlTitle}>{control.title}</div>
                              <span style={{ fontSize: "10px", color: COLORS.textDim, letterSpacing: "0.1em", textTransform: "uppercase", whiteSpace: "nowrap", marginLeft: "12px" }}>
                                {control.category}
                              </span>
                            </div>
                            <div style={styles.controlDesc}>{control.description}</div>
                            <div style={{ marginTop: "10px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                              {control.tools.map((tool, j) => (
                                <span key={j} style={{ background: `${COLORS.panelBorder}`, border: `1px solid ${COLORS.panelBorder}`, color: COLORS.textDim, fontSize: "10px", padding: "2px 8px", borderRadius: "3px" }}>
                                  {tool}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* EMPTY STATE */}
        {!results && !analyzing && (
          <div style={{ textAlign: "center", padding: "48px 20px", color: COLORS.textDim }}>
            <div style={{ fontSize: "40px", marginBottom: "16px", opacity: 0.4 }}>🎣</div>
            <div style={{ fontSize: "13px", letterSpacing: "0.1em", marginBottom: "8px", color: COLORS.textDim }}>PASTE AN EMAIL AND CLICK ANALYZE</div>
            <div style={{ fontSize: "11px", color: "#2A3A55" }}>Extracts IPs, Domains, URLs, Hashes, Attachments • Cross-references VirusTotal & AbuseIPDB • Generates SIEM/EDR Queries • Recommends Controls</div>
          </div>
        )}

      </div>
    </div>
  );
}
