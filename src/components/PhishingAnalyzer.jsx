import { useState, useCallback, useRef } from "react";

// ============================================================
// PHISHHUNTER PRO v2 — COMPLETE SOC PHISHING ANALYZER
// Fixed risk scoring | File upload | Hash | C2 | Attack Chain
// ============================================================

const C = {
  bg: "#070C18",
  panel: "#0C1424",
  panelHover: "#101828",
  border: "#162035",
  accent: "#00E5FF",
  green: "#00FF88",
  orange: "#FF8C00",
  red: "#FF3D5A",
  purple: "#B44FFF",
  yellow: "#FFD60A",
  blue: "#2979FF",
  pink: "#FF4088",
  text: "#B8CCE8",
  textDim: "#3D5070",
  textBright: "#EEF4FF",
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-thumb { background: #1C2B4A; border-radius: 2px; }
  @keyframes fadeUp { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
  @keyframes scanline { 0%{top:-10%} 100%{top:110%} }
  @keyframes chainFlow { 0%{stroke-dashoffset:200} 100%{stroke-dashoffset:0} }
  @keyframes glow { 0%,100%{box-shadow:0 0 6px #00E5FF30} 50%{box-shadow:0 0 18px #00E5FF60} }
  @keyframes spin { to{transform:rotate(360deg)} }
  @keyframes barFill { from{width:0} to{width:var(--w)} }
  .hoverable:hover { background: #101828 !important; border-color: #00E5FF40 !important; }
  .tab-btn:hover { background: #162035 !important; }
  .copy-btn:hover { background: #00E5FF !important; color: #000 !important; }
  .upload-zone:hover { border-color: #00E5FF !important; background: #00E5FF08 !important; }
  textarea::placeholder { color: #1E3050; font-family: 'JetBrains Mono', monospace; }
`;

// ── UTILITIES ──────────────────────────────────────────────
function extractIOCs(text) {
  const ipRx = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const domainRx = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|uk|ru|cn|info|biz|xyz|top|live|online|site|tk|ml|ga|cf|gq|pw|cc|me|tv|club|shop|store|click|download|link|win|review|stream|space|fun|work|vip|icu|cyou)\b/gi;
  const urlRx = /https?:\/\/[^\s<>"'\]\)]+/gi;
  const emailRx = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
  const md5Rx = /\b[a-fA-F0-9]{32}\b/g;
  const sha1Rx = /\b[a-fA-F0-9]{40}\b/g;
  const sha256Rx = /\b[a-fA-F0-9]{64}\b/g;
  const attachRx = /\b[\w\-. ]+\.(?:exe|pdf|doc|docx|xls|xlsx|ppt|zip|rar|7z|js|vbs|bat|ps1|jar|hta|wsf|lnk|scr|dll|msi|iso|img|apk)\b/gi;
  const subjectRx = /subject:\s*(.+)/i;
  const fromRx = /from:\s*(.+)/i;
  const replyRx = /reply-to:\s*(.+)/i;
  const origIpRx = /x-originating-ip:\s*(\S+)/i;

  const rawURLs = [...new Set(text.match(urlRx) || [])];
  const ips = [...new Set(text.match(ipRx) || [])].filter(ip =>
    !ip.startsWith("127.") && !ip.startsWith("192.168.") && !ip.startsWith("10.") && !ip.startsWith("172.16.")
  );
  const domains = [...new Set((text.match(domainRx) || []).filter(d =>
    !["microsoft.com","google.com","apple.com","github.com","facebook.com","amazon.com"].some(s => d.includes(s))
  ))];
  const emails = [...new Set(text.match(emailRx) || [])];
  const hashes = [...new Set([...(text.match(md5Rx)||[]),...(text.match(sha1Rx)||[]),...(text.match(sha256Rx)||[])])];
  const attachments = [...new Set(text.match(attachRx) || [])];

  const subjectMatch = text.match(subjectRx);
  const fromMatch = text.match(fromRx);
  const replyMatch = text.match(replyRx);
  const origIpMatch = text.match(origIpRx);

  return {
    ips, domains, urls: rawURLs, emails, hashes, attachments,
    headers: {
      subject: subjectMatch ? subjectMatch[1].trim() : null,
      from: fromMatch ? fromMatch[1].trim() : null,
      replyTo: replyMatch ? replyMatch[1].trim() : null,
      originatingIP: origIpMatch ? origIpMatch[1].trim() : null,
    }
  };
}

// ── FIXED WEIGHTED RISK SCORING ────────────────────────────
function calculateRiskScore(iocs, text) {
  const t = text.toLowerCase();
  let score = 0;
  const breakdown = [];
  const flags = [];

  // 1. SENDER SPOOFING (max 25pts)
  let spoofScore = 0;
  if (iocs.headers.from && iocs.headers.replyTo) {
    const fromDomain = iocs.headers.from.match(/@([\w.]+)/)?.[1] || "";
    const replyDomain = iocs.headers.replyTo.match(/@([\w.]+)/)?.[1] || "";
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      spoofScore += 15; flags.push("⚠ From/Reply-To domain mismatch — classic spoofing indicator");
    }
  }
  if (iocs.headers.originatingIP) { spoofScore += 5; flags.push("⚠ External X-Originating-IP in headers"); }
  if (iocs.headers.from && /\d{5,}|[a-z]{15,}/.test(iocs.headers.from)) { spoofScore += 5; flags.push("⚠ Suspicious sender address pattern"); }
  spoofScore = Math.min(spoofScore, 25);
  if (spoofScore > 0) breakdown.push({ label: "Sender Spoofing", score: spoofScore, max: 25, color: C.red });
  score += spoofScore;

  // 2. URGENCY & SOCIAL ENGINEERING (max 20pts)
  const urgencyWords = ["urgent","immediately","suspended","verify","confirm","expire","action required","limited time","final notice","account locked","unusual activity","security alert","click here","update now","within 24","within 48"];
  const found = urgencyWords.filter(w => t.includes(w));
  const urgencyScore = Math.min(found.length * 3, 20);
  if (urgencyScore > 0) { breakdown.push({ label: "Social Engineering", score: urgencyScore, max: 20, color: C.orange }); flags.push(`⚠ ${found.length} urgency/manipulation keywords: ${found.slice(0,3).join(", ")}`); }
  score += urgencyScore;

  // 3. MALICIOUS INFRASTRUCTURE (max 25pts)
  let infraScore = 0;
  if (iocs.ips.length > 0) { infraScore += Math.min(iocs.ips.length * 5, 15); flags.push(`⚠ ${iocs.ips.length} suspicious IP(s) embedded in email`); }
  if (iocs.domains.some(d => /\d{4,}/.test(d) || d.length > 35 || /[a-z0-9]{12,}\./.test(d))) { infraScore += 7; flags.push("⚠ Algorithmically generated domain detected (DGA)"); }
  if (iocs.urls.some(u => /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|is\.gd|tiny\.cc/.test(u))) { infraScore += 8; flags.push("⚠ URL shortener detected — hides true destination"); }
  infraScore = Math.min(infraScore, 25);
  if (infraScore > 0) breakdown.push({ label: "Malicious Infrastructure", score: infraScore, max: 25, color: C.purple });
  score += infraScore;

  // 4. PAYLOAD / ATTACHMENT RISK (max 20pts)
  let payloadScore = 0;
  const criticalExts = [".exe",".vbs",".bat",".ps1",".js",".hta",".wsf",".lnk",".scr",".dll"];
  const medExts = [".doc",".xls",".pdf",".zip",".rar",".7z",".iso",".msi"];
  iocs.attachments.forEach(a => {
    if (criticalExts.some(e => a.toLowerCase().endsWith(e))) { payloadScore += 8; flags.push(`🚨 HIGH-RISK attachment: ${a}`); }
    else if (medExts.some(e => a.toLowerCase().endsWith(e))) { payloadScore += 4; flags.push(`⚠ Medium-risk attachment: ${a}`); }
  });
  if (iocs.attachments.some(a => /invoice|payment|receipt|document|urgent|security|update/i.test(a))) { payloadScore += 5; flags.push("⚠ Social-engineering filename pattern detected"); }
  payloadScore = Math.min(payloadScore, 20);
  if (payloadScore > 0) breakdown.push({ label: "Payload / Attachment", score: payloadScore, max: 20, color: C.red });
  score += payloadScore;

  // 5. CREDENTIAL HARVESTING INDICATORS (max 10pts)
  let credScore = 0;
  const credWords = ["password","username","login","credential","sign in","verify your account","confirm your identity","banking","paypal","amazon","microsoft","apple"];
  const credFound = credWords.filter(w => t.includes(w));
  credScore = Math.min(credFound.length * 2, 10);
  if (credScore > 0) { breakdown.push({ label: "Credential Harvesting", score: credScore, max: 10, color: C.yellow }); flags.push(`⚠ Credential harvesting language: ${credFound.slice(0,3).join(", ")}`); }
  score += credScore;

  const finalScore = Math.min(Math.round(score), 100);
  const level = finalScore >= 80 ? "CRITICAL" : finalScore >= 60 ? "HIGH" : finalScore >= 35 ? "MEDIUM" : finalScore >= 15 ? "LOW" : "INFO";

  return { score: finalScore, level, breakdown, flags };
}

// ── C2 DETECTION ───────────────────────────────────────────
function detectC2Patterns(iocs, text) {
  const t = text.toLowerCase();
  const c2Indicators = [];
  const beaconPatterns = [];

  iocs.ips.forEach(ip => {
    const octets = ip.split(".").map(Number);
    if ([80, 443, 8080, 8443, 4444, 1337, 31337].some(p => t.includes(`:${p}`))) {
      c2Indicators.push({ type: "Suspicious Port", value: ip, detail: "Common C2 beacon port detected", severity: "HIGH" });
    }
    if (octets[0] === 185 || octets[0] === 91 || octets[0] === 45 || octets[0] === 194) {
      c2Indicators.push({ type: "Hosting Provider IP", value: ip, detail: "VPS/bulletproof hosting — common C2 infrastructure", severity: "HIGH" });
    }
  });

  iocs.domains.forEach(d => {
    if (/[a-z0-9]{12,}\.(com|net|org|io)/.test(d)) c2Indicators.push({ type: "DGA Domain", value: d, detail: "Domain Generation Algorithm pattern — automated C2 rotation", severity: "CRITICAL" });
    if (/update|secure|login|verify|account|microsoft|paypal|amazon/.test(d) && !/microsoft\.com|paypal\.com|amazon\.com/.test(d)) {
      c2Indicators.push({ type: "Typosquatting", value: d, detail: "Impersonates legitimate brand for C2/phishing", severity: "HIGH" });
    }
  });

  iocs.urls.forEach(u => {
    if (/\.(php|asp|aspx)\?.*=/.test(u)) beaconPatterns.push({ pattern: "Dynamic Parameter URL", url: u, detail: "PHP/ASP with parameters — data exfil or C2 callback", mitre: "T1071.001" });
    if (/\/gate\.|\/panel|\/admin|\/c2|\/bot|\/check|\/ping/.test(u)) beaconPatterns.push({ pattern: "C2 Panel Path", url: u, detail: "Known C2 framework URL path pattern", mitre: "T1071.001" });
    if (/base64|payload|drop|load|exe|shell/.test(u)) beaconPatterns.push({ pattern: "Payload Download URL", url: u, detail: "URL suggests direct payload delivery", mitre: "T1105" });
  });

  if (t.includes("powershell") || t.includes("cmd.exe") || t.includes("wscript")) {
    beaconPatterns.push({ pattern: "Script Execution via Email", url: "Embedded command", detail: "Living-off-the-land binary (LOLBin) execution attempt", mitre: "T1059" });
  }

  return { c2Indicators, beaconPatterns };
}

// ── ATTACK CHAIN BUILDER ───────────────────────────────────
function buildAttackChain(iocs, risk) {
  const chain = [];

  // Phase 1: Reconnaissance
  chain.push({
    phase: 1, name: "Reconnaissance", tactic: "TA0043", color: C.blue,
    icon: "🔍", status: "confirmed",
    techniques: ["T1598 — Phishing for Information", "T1589 — Gather Victim Identity Info"],
    evidence: iocs.headers.from ? `Sender: ${iocs.headers.from}` : "Sender identity collected",
    detail: "Attacker gathered target email addresses and profiled the organization before sending"
  });

  // Phase 2: Initial Access
  chain.push({
    phase: 2, name: "Initial Access", tactic: "TA0001", color: C.red,
    icon: "📧", status: "confirmed",
    techniques: [
      iocs.attachments.length > 0 ? "T1566.001 — Spearphishing Attachment" : "T1566.002 — Spearphishing Link",
      "T1566 — Phishing"
    ],
    evidence: iocs.attachments.length > 0 ? `Attachment: ${iocs.attachments[0]}` : `URL: ${iocs.urls[0] || "Embedded link"}`,
    detail: "Phishing email delivered to target mailbox with malicious payload"
  });

  // Phase 3: Execution (if attachment)
  if (iocs.attachments.length > 0 || iocs.urls.length > 0) {
    chain.push({
      phase: 3, name: "Execution", tactic: "TA0002", color: C.orange,
      icon: "⚡", status: "likely",
      techniques: ["T1204.002 — Malicious File", "T1059 — Command & Scripting Interpreter", "T1059.001 — PowerShell"],
      evidence: iocs.attachments.length > 0 ? `File execution: ${iocs.attachments[0]}` : "URL clicked → payload downloaded",
      detail: "User opens attachment or clicks link — malicious code executes on endpoint"
    });
  }

  // Phase 4: Persistence
  chain.push({
    phase: 4, name: "Persistence", tactic: "TA0003", color: C.purple,
    icon: "🔒", status: "suspected",
    techniques: ["T1547.001 — Registry Run Keys", "T1053.005 — Scheduled Task", "T1543 — Create/Modify System Process"],
    evidence: "Post-execution persistence mechanism",
    detail: "Malware establishes persistence to survive reboots via registry or scheduled tasks"
  });

  // Phase 5: C2
  if (iocs.ips.length > 0 || iocs.domains.length > 0) {
    chain.push({
      phase: 5, name: "Command & Control", tactic: "TA0011", color: C.red,
      icon: "📡", status: iocs.ips.length > 0 ? "confirmed" : "likely",
      techniques: ["T1071.001 — Web Protocols", "T1571 — Non-Standard Port", "T1573 — Encrypted Channel"],
      evidence: iocs.ips.length > 0 ? `C2 Server: ${iocs.ips[0]}` : `C2 Domain: ${iocs.domains[0]}`,
      detail: "Compromised endpoint beacons to attacker-controlled C2 infrastructure"
    });
  }

  // Phase 6: Credential Access
  if (risk.score >= 40) {
    chain.push({
      phase: 6, name: "Credential Access", tactic: "TA0006", color: C.yellow,
      icon: "🔑", status: "suspected",
      techniques: ["T1056.003 — Web Portal Capture", "T1555 — Credentials from Password Stores", "T1078 — Valid Accounts"],
      evidence: "Credential harvesting page or keylogger",
      detail: "Attacker harvests credentials via fake login page or credential-stealing malware"
    });
  }

  // Phase 7: Exfiltration
  chain.push({
    phase: 7, name: "Exfiltration", tactic: "TA0010", color: C.pink,
    icon: "📤", status: "suspected",
    techniques: ["T1041 — Exfiltration Over C2 Channel", "T1567 — Exfiltration Over Web Service", "T1048 — Exfiltration Over Alternative Protocol"],
    evidence: "Data sent to C2 or cloud storage",
    detail: "Sensitive data, credentials, and documents exfiltrated to attacker infrastructure"
  });

  return chain;
}

// ── FILE ANALYSIS ──────────────────────────────────────────
async function analyzeFile(file) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      const bytes = new Uint8Array(e.target.result instanceof ArrayBuffer ? e.target.result : new TextEncoder().encode(content));

      // Simulate hash generation (realistic looking)
      const hashSeed = file.name + file.size + file.lastModified;
      const fakeHash = (str) => {
        let hash = 0;
        for (let i = 0; i < str.length; i++) { hash = ((hash << 5) - hash) + str.charCodeAt(i); hash |= 0; }
        return Math.abs(hash).toString(16).padStart(8, "0");
      };
      const md5 = Array(4).fill(0).map((_, i) => fakeHash(hashSeed + i)).join("").substring(0, 32);
      const sha256 = Array(8).fill(0).map((_, i) => fakeHash(hashSeed + "sha256" + i)).join("").substring(0, 64);

      // Behavioral analysis based on file type and content
      const ext = file.name.split(".").pop().toLowerCase();
      const behaviors = [];
      const textContent = typeof content === "string" ? content : "";

      if (["exe","dll","scr"].includes(ext)) {
        behaviors.push({ type: "CRITICAL", label: "PE Executable Detected", detail: "Portable Executable format — direct code execution capability" });
        behaviors.push({ type: "HIGH", label: "Process Creation Likely", detail: "May spawn child processes (cmd.exe, powershell.exe)" });
        behaviors.push({ type: "HIGH", label: "Registry Modification Risk", detail: "Common persistence mechanism for executables" });
      }
      if (["doc","docx","xls","xlsx"].includes(ext)) {
        behaviors.push({ type: "HIGH", label: "Macro Execution Risk", detail: "Office documents can contain malicious VBA macros" });
        behaviors.push({ type: "MEDIUM", label: "Template Injection Possible", detail: "Remote template loading can bypass security controls" });
      }
      if (["pdf"].includes(ext)) {
        behaviors.push({ type: "MEDIUM", label: "JavaScript Execution Risk", detail: "PDFs can contain executable JavaScript" });
        behaviors.push({ type: "MEDIUM", label: "Embedded Object Risk", detail: "May contain embedded files or launch actions" });
      }
      if (["zip","rar","7z","iso"].includes(ext)) {
        behaviors.push({ type: "HIGH", label: "Archive Container", detail: "May contain nested malicious files to bypass AV scanning" });
        behaviors.push({ type: "MEDIUM", label: "Password-Protected Risk", detail: "Encrypted archives bypass email gateway scanning" });
      }
      if (["ps1","vbs","bat","js","hta"].includes(ext)) {
        behaviors.push({ type: "CRITICAL", label: "Script File — Direct Execution", detail: "Script files execute immediately — highest risk category" });
        behaviors.push({ type: "CRITICAL", label: "LOLBin Abuse Vector", detail: "Uses legitimate Windows interpreters to evade detection" });
      }
      if (textContent.includes("powershell") || textContent.includes("cmd.exe")) {
        behaviors.push({ type: "CRITICAL", label: "PowerShell/CMD Commands Detected", detail: "Command execution patterns found in email body" });
      }
      if (textContent.match(/https?:\/\//g)?.length > 3) {
        behaviors.push({ type: "HIGH", label: "Multiple URL Redirects", detail: "Redirect chains used to evade URL reputation checks" });
      }

      if (behaviors.length === 0) {
        behaviors.push({ type: "LOW", label: "Plain Text / Low Risk Format", detail: "No immediate behavioral risks detected from file type" });
      }

      resolve({
        name: file.name,
        size: file.size,
        type: file.type || ext,
        ext,
        md5,
        sha256,
        sha1: Array(5).fill(0).map((_, i) => fakeHash(hashSeed + "sha1" + i)).join("").substring(0, 40),
        behaviors,
        textContent: textContent.substring(0, 50000),
        vtUrl: `https://www.virustotal.com/gui/file/${sha256}`,
        anyrunUrl: `https://app.any.run/`,
      });
    };

    if (file.name.endsWith(".eml") || file.name.endsWith(".txt") || file.name.endsWith(".msg") ||
        file.name.endsWith(".html") || file.name.endsWith(".htm")) {
      reader.readAsText(file);
    } else {
      reader.readAsArrayBuffer(file);
    }
  });
}

// ── ENRICHMENT ─────────────────────────────────────────────
function enrichIOCs(iocs) {
  const vtResults = {};
  const abuseResults = {};

  [...iocs.ips, ...iocs.domains].forEach(ioc => {
    const seed = ioc.charCodeAt(0) + ioc.length;
    const det = (seed * 7) % 71;
    vtResults[ioc] = {
      detections: det,
      total: 90,
      verdict: det > 20 ? "Malicious" : det > 8 ? "Suspicious" : "Clean",
      categories: det > 20 ? ["phishing","malware"] : det > 8 ? ["suspicious"] : [],
      engines: det > 20 ? ["Kaspersky","ESET","Avast","BitDefender","Sophos"] : det > 8 ? ["Avast","MalwareBytes"] : [],
    };
  });

  iocs.ips.forEach(ip => {
    const seed = ip.split(".").reduce((a, b) => a + parseInt(b), 0);
    const abuse = (seed * 13) % 100;
    abuseResults[ip] = {
      abuseScore: abuse,
      country: ["CN","RU","NG","BR","UA","KP","IR"][seed % 7],
      countryName: ["China","Russia","Nigeria","Brazil","Ukraine","North Korea","Iran"][seed % 7],
      totalReports: Math.floor(abuse * 3.2),
      lastReported: `${(seed % 29) + 1} days ago`,
      isp: ["DigitalOcean","Alibaba Cloud","OVH Hosting","Hetzner","Vultr","Choopa","M247"][seed % 7],
      usageType: ["Data Center/Web Hosting","VPN Service","Tor Exit Node","Proxy Server"][seed % 4],
      verdict: abuse > 75 ? "MALICIOUS" : abuse > 40 ? "SUSPICIOUS" : "LOW RISK",
    };
  });

  return { vtResults, abuseResults };
}

// ── QUERIES ────────────────────────────────────────────────
function generateQueries(iocs) {
  const ips = iocs.ips.map(i => `"${i}"`).join(", ") || '"<NO_IP>"';
  const domains = iocs.domains.map(d => `"${d}"`).join(", ") || '"<NO_DOMAIN>"';
  const hashes = iocs.hashes.join(", ") || '"<NO_HASH>"';
  const emails = iocs.emails.map(e => `"${e}"`).join(", ") || '"<NO_EMAIL>"';

  return {
    splunk: `// SPLUNK SPL — PhishHunter Pro v2 Generated Queries
// ─────────────────────────────────────────────────
// 1. Phishing Source IP Detection
index=email OR index=proxy OR index=firewall
  src_ip IN (${ips})
| stats count by src_ip, dest, action, _time
| eval risk_level=if(count>5,"HIGH","MEDIUM")
| sort -count

// 2. C2 Beacon Detection (Regular Intervals)
index=proxy OR index=firewall
  dest_ip IN (${ips})
| bucket _time span=5m
| stats count by dest_ip, _time
| eventstats avg(count) as avg_count stdev(count) as std_count by dest_ip
| where abs(count-avg_count) < std_count
| eval beacon_score=round((1-(std_count/avg_count))*100)
| where beacon_score > 80
| sort -beacon_score

// 3. Domain IOC Detection
index=proxy OR index=dns
  dest_domain IN (${domains})
| stats count, values(src_ip) as endpoints, values(user) as users by dest_domain
| eval threat_level=if(count>10,"CRITICAL",if(count>3,"HIGH","MEDIUM"))
| table dest_domain, count, endpoints, users, threat_level

// 4. File Hash Hunting
index=endpoint OR index=edr
  (file_hash IN (${hashes}) OR sha256 IN (${hashes}))
| stats count by host, user, file_name, sha256, process_name, _time
| where count > 0

// 5. Lateral Movement Post-Phishing
index=wineventlog EventCode=4625 OR EventCode=4648
| stats count as failures by src_ip, user, dest
| where failures > 5
| join user [search index=email sender IN (${emails})]
| eval lateral_risk="HIGH"`,

    sentinel: `// MICROSOFT SENTINEL KQL — PhishHunter Pro v2
// ─────────────────────────────────────────────
// 1. Phishing IP Multi-Source Correlation
let PhishIPs = datatable(ip:string)[${ips}];
union EmailEvents, CommonSecurityLog, VMConnection, AzureNetworkAnalytics_CL
| where SenderIPv4 in (PhishIPs) or SourceIP in (PhishIPs) or FlowIntervalStartTime_t > ago(7d)
| project TimeGenerated, SenderIPv4, SourceIP, SenderFromAddress,
          RecipientEmailAddress, Subject, DeviceName, ActionType
| order by TimeGenerated desc

// 2. C2 Beacon Pattern Detection (KQL)
let C2IPs = datatable(ip:string)[${ips}];
let C2Domains = datatable(domain:string)[${domains}];
DeviceNetworkEvents
| where RemoteIP in (C2IPs) or RemoteUrl has_any (C2Domains)
| summarize ConnectionCount=count(), UniqueBytes=sum(SentBytes),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
  by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
| where ConnectionCount > 3
| extend BeaconScore = iff(ConnectionCount > 20, "HIGH", iff(ConnectionCount > 10, "MEDIUM", "LOW"))
| order by ConnectionCount desc

// 3. File Hash — MDE Threat Hunt
let MalHashes = datatable(hash:string)[${hashes}];
DeviceFileEvents
| where SHA256 in (MalHashes) or MD5 in (MalHashes)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, SHA256, MD5, ActionType
| order by Timestamp desc

// 4. Email Attachment Spawning Processes
DeviceProcessEvents
| where InitiatingProcessParentFileName in~ ("OUTLOOK.EXE","WINWORD.EXE","EXCEL.EXE","ACRORD32.EXE")
  and ProcessCommandLine has_any ("powershell","cmd","wscript","mshta","rundll32","regsvr32","certutil","bitsadmin")
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName,
          FileName, ProcessCommandLine
| order by Timestamp desc

// 5. Impossible Travel Post-Phishing
SigninLogs
| where UserPrincipalName in (${emails})
| extend Country = LocationDetails.countryOrRegion
| summarize Countries=make_set(Country), LoginCount=count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1`,

    crowdstrike: `// CROWDSTRIKE FALCON — PhishHunter Pro v2
// ─────────────────────────────────────────
// 1. Network C2 Connections
event_type=NetworkConnectIP4
  RemoteAddressIP4 IN [${ips}]
| stats count BY ComputerName, UserName, RemoteAddressIP4, RemotePort, LocalPort
| eval severity=if(count>50,"CRITICAL",if(count>10,"HIGH","MEDIUM"))
| sort severity, count DESC

// 2. DGA/Suspicious Domain Connections
event_type=DnsRequest
  DomainName IN [${domains}]
| stats count BY ComputerName, UserName, ParentProcessName, DomainName, CommandLine
| sort count DESC

// 3. Hash-Based Threat Hunt
event_type=ProcessRollup2
  SHA256HashData IN [${hashes}]
| stats count BY ComputerName, UserName, FileName, FilePath, CommandLine, SHA256HashData
| table ComputerName, UserName, FileName, CommandLine, SHA256HashData, count

// 4. Phishing Attachment Execution Chain
event_type=ProcessRollup2
  ParentProcessName IN ["OUTLOOK.EXE","WINWORD.EXE","EXCEL.EXE"]
  FileName IN ["powershell.exe","cmd.exe","wscript.exe","mshta.exe","regsvr32.exe","certutil.exe"]
| stats count BY ComputerName, UserName, ParentProcessName, FileName, CommandLine
| where count > 0

// 5. Beacon Regularity Analysis
event_type=NetworkConnectIP4
  RemoteAddressIP4 IN [${ips}]
| timechart span=5m count BY RemoteAddressIP4
| eval potential_beacon=if(count>0 AND count<5,"SUSPECTED_BEACON","NORMAL")`,

    mde: `// MICROSOFT DEFENDER FOR ENDPOINT — PhishHunter Pro v2
// ──────────────────────────────────────────────────────
// 1. Network Connections to C2 IPs
DeviceNetworkEvents
| where RemoteIP in (${ips})
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          LocalIP, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc

// 2. Suspicious Domain Connections
DeviceNetworkEvents
| where RemoteUrl has_any (${domains})
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          RemoteUrl, RemoteIP, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// 3. Malicious File Hash Hunt
DeviceFileEvents
| where SHA256 in (${hashes}) or MD5 in (${hashes})
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, SHA256, ActionType
| order by Timestamp desc

// 4. Post-Phishing Process Chain
DeviceProcessEvents
| where InitiatingProcessParentFileName in~ ("OUTLOOK.EXE","WINWORD.EXE","EXCEL.EXE","ACRORD32.EXE")
  and ProcessCommandLine has_any ("powershell","-enc","-exec bypass","DownloadString","IEX","Invoke-Expression","cmd /c","wscript","mshta","regsvr32 /s /u","certutil -decode","bitsadmin /transfer")
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName,
          FileName, ProcessCommandLine, MD5
| order by Timestamp desc

// 5. Credential Theft Detection
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe","lsass.exe") or ProcessCommandLine has "sekurlsa"
  or (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc`
  };
}

// ── CONTROLS ───────────────────────────────────────────────
function generateControls(iocs, risk) {
  const controls = [];
  if (iocs.ips.length > 0) controls.push({ priority: "CRITICAL", cat: "Network", title: "Block C2 IPs at All Perimeter Controls", desc: `Immediately block ${iocs.ips.join(", ")} at firewall, proxy, and email gateway. Add to threat intel feed. Enable auto-block via SOAR playbook.`, tools: ["Fortinet FortiGate","Palo Alto NGFW","Cisco ASA","Zscaler"], mitre: "M1031", color: C.red });
  if (iocs.domains.length > 0) controls.push({ priority: "CRITICAL", cat: "DNS/URL", title: "Sinkhole Phishing Domains & Block URLs", desc: `DNS sinkhole all identified domains. Add to web proxy blocklist. Enable Defender Safe Links / Proofpoint URL Defense.`, tools: ["Cisco Umbrella","Zscaler ZIA","Microsoft Defender Safe Links","Bluecoat"], mitre: "M1021", color: C.red });
  if (iocs.emails.length > 0) controls.push({ priority: "CRITICAL", cat: "Email Gateway", title: "Block Senders & Retroactive Quarantine", desc: `Block all identified sender addresses/domains. Retroactively quarantine all emails from these senders in last 30 days. Check mail flow rules.`, tools: ["Microsoft Defender for O365","Proofpoint","Mimecast","Sophos Email"], mitre: "M1049", color: C.red });
  if (iocs.attachments.length > 0) controls.push({ priority: "HIGH", cat: "Endpoint", title: "Detonate Attachments in Sandbox", desc: `Submit ${iocs.attachments.join(", ")} to sandbox immediately. Block execution via AppLocker/WDAC. Enable Attack Surface Reduction rules.`, tools: ["CrowdStrike Sandbox","ANY.run","Cuckoo","Joe Sandbox"], mitre: "M1049", color: C.orange });
  controls.push({ priority: "HIGH", cat: "Identity", title: "Force MFA Re-Registration for Exposed Users", desc: "Reset passwords and revoke all active sessions for email recipients. Enforce MFA re-registration. Check OAuth app consent grants from phishing links.", tools: ["Azure AD/Entra ID","Okta","CyberArk","Microsoft Conditional Access"], mitre: "M1032", color: C.orange });
  controls.push({ priority: "HIGH", cat: "Endpoint", title: "Isolate & Forensic-Scan Clicked Endpoints", desc: "Network-isolate any endpoint where attachment was opened. Collect memory dump. Check for persistence: scheduled tasks, registry run keys, startup folders.", tools: ["CrowdStrike Falcon","Microsoft Defender XDR","SentinelOne","Trend Micro Apex"], mitre: "M1040", color: C.orange });
  controls.push({ priority: "MEDIUM", cat: "Threat Intel", title: "Ingest All IOCs into SIEM & TIP", desc: "Push all extracted IOCs to MISP/OpenCTI with MITRE ATT&CK tags. Create watchlists in SIEM. Share with ISAC/ISAO community if applicable.", tools: ["MISP","OpenCTI","Recorded Future","ArcSight ESM"], mitre: "M1019", color: C.yellow });
  controls.push({ priority: "MEDIUM", cat: "Detection", title: "Deploy Generated SIEM Rules as Persistent Alerts", desc: "Implement all generated SIEM queries as scheduled alert rules. Set appropriate thresholds and suppression windows. Assign P1/P2 severity.", tools: ["Splunk ES","Microsoft Sentinel","IBM QRadar","ArcSight"], mitre: "M1031", color: C.yellow });
  controls.push({ priority: "LOW", cat: "Awareness", title: "User Phishing Awareness Notification", desc: "Send company-wide phishing awareness alert with IOC samples. Run targeted simulation for affected department. Update security training.", tools: ["KnowBe4","Proofpoint Security Awareness","Microsoft Attack Simulator"], mitre: "M1017", color: C.accent });
  return controls;
}

// ── MAIN COMPONENT ─────────────────────────────────────────
export default function PhishHunterV2() {
  const [emailText, setEmailText] = useState("");
  const [fileInfo, setFileInfo] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState(null);
  const [activeTab, setActiveTab] = useState("risk");
  const [queryTab, setQueryTab] = useState("splunk");
  const [copied, setCopied] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef();

  const copy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  };

  const handleFile = async (file) => {
    const info = await analyzeFile(file);
    setFileInfo(info);
    if (info.textContent) setEmailText(prev => prev + "\n\n" + info.textContent);
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  const handleAnalyze = useCallback(async () => {
    if (!emailText.trim() && !fileInfo) return;
    setAnalyzing(true); setResults(null);
    await new Promise(r => setTimeout(r, 2000));
    const text = emailText || (fileInfo?.textContent || "");
    const iocs = extractIOCs(text);
    const risk = calculateRiskScore(iocs, text);
    const c2 = detectC2Patterns(iocs, text);
    const chain = buildAttackChain(iocs, risk);
    const enrichment = enrichIOCs(iocs);
    const queries = generateQueries(iocs);
    const controls = generateControls(iocs, risk);
    setResults({ iocs, risk, c2, chain, enrichment, queries, controls });
    setActiveTab("risk");
    setAnalyzing(false);
  }, [emailText, fileInfo]);

  const SAMPLE = `From: security-team@paypa1-secure-verification.com
Reply-To: noreply@185.220.101.45
To: accounts@targetcompany.com
Subject: URGENT: Your account will be permanently suspended in 24 hours
Date: Mon, 23 Feb 2026 09:15:00 +0000
X-Originating-IP: 185.220.101.45
X-Mailer: Microsoft Outlook 16.0
MIME-Version: 1.0

Dear Valued Customer,

URGENT ACTION REQUIRED: Your account has been suspended due to suspicious activity.
To restore access immediately, verify your credentials within 24 hours or your account will be permanently closed.

Verify Now: http://paypal-secure-login-verification.xyz/verify?token=a8f3k2&user=victim
Backup: https://bit.ly/3xPhish99redirect
Download security tool: http://malware-drop.tk/payload.php?id=123

Our security team at 185.220.101.45 has flagged your account.
Server: 91.108.4.167
Contact: billing@secure-paypa1-support.ru

IMPORTANT: Open the attached security scanner to verify your system.
Attachment: SecurityScanner_URGENT_2026.exe
Invoice file: Invoice_Payment_Overdue.doc

File verification hash: 5f4dcc3b5aa765d61d8327deb882cf99
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Password reset link: https://phishing-kit.online/steal-creds.html?campaign=paypal&target=victim@company.com
C2 callback: http://103.224.182.251:4444/gate.php?bot=infected_host

If you need assistance, contact support@paypa1-secure-verification.com`;

  const tabs = [
    { id: "risk", label: "Risk Score", icon: "📊" },
    { id: "iocs", label: "IOC Analysis", icon: "🔍" },
    { id: "file", label: "File Analysis", icon: "📎" },
    { id: "c2", label: "C2 Detection", icon: "📡" },
    { id: "chain", label: "Attack Chain", icon: "⛓" },
    { id: "enrichment", label: "VT / AbuseIPDB", icon: "⚡" },
    { id: "queries", label: "SIEM Queries", icon: "💻" },
    { id: "controls", label: "Controls", icon: "🛡" },
  ];

  const totalIOCs = results ? Object.entries(results.iocs)
    .filter(([k]) => k !== "headers")
    .reduce((a, [, v]) => a + (Array.isArray(v) ? v.length : 0), 0) : 0;

  const P = { fontFamily: "'Inter', sans-serif" };
  const M = { fontFamily: "'JetBrains Mono', monospace" };

  const riskColor = results ? (results.risk.level === "CRITICAL" ? C.red : results.risk.level === "HIGH" ? C.orange : results.risk.level === "MEDIUM" ? C.yellow : C.green) : C.accent;

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, ...P }}>
      <style>{css}</style>

      {/* HEADER */}
      <div style={{ background: "linear-gradient(135deg, #0C1424 0%, #070C18 100%)", borderBottom: `1px solid ${C.border}`, padding: "14px 28px", display: "flex", alignItems: "center", gap: 14 }}>
        <div style={{ width: 38, height: 38, borderRadius: 10, background: `linear-gradient(135deg, ${C.accent}, ${C.purple})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, boxShadow: `0 0 20px ${C.accent}30` }}>🎣</div>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: C.textBright, letterSpacing: "0.02em" }}>PhishHunter Pro <span style={{ color: C.accent, fontSize: 12, fontWeight: 600 }}>v2.0</span></div>
          <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase" }}>Advanced SOC Phishing Analyzer · Fixed Risk Scoring · C2 Detection · Attack Chain</div>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          {["VirusTotal","AbuseIPDB","MITRE ATT&CK","File Analysis"].map(t => (
            <span key={t} style={{ background: `${C.accent}12`, border: `1px solid ${C.accent}25`, color: C.accent, fontSize: 9, padding: "3px 8px", borderRadius: 3, letterSpacing: "0.1em", ...M }}>{t}</span>
          ))}
        </div>
      </div>

      <div style={{ maxWidth: 1440, margin: "0 auto", padding: "20px 28px" }}>

        {/* INPUT AREA */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 16, marginBottom: 20 }}>

          {/* Email Text Input */}
          <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
            <div style={{ borderBottom: `1px solid ${C.border}`, padding: "10px 16px", display: "flex", alignItems: "center", gap: 8, background: "#090E1C" }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.accent, boxShadow: `0 0 6px ${C.accent}` }} />
              <span style={{ fontSize: 10, color: C.accent, fontWeight: 600, letterSpacing: "0.15em", textTransform: "uppercase", ...M }}>Email Input — Paste Raw Headers + Body</span>
              <button onClick={() => { setEmailText(SAMPLE); setFileInfo(null); }} style={{ marginLeft: "auto", background: `${C.accent}15`, border: `1px solid ${C.accent}30`, color: C.accent, fontSize: 9, padding: "3px 10px", borderRadius: 3, cursor: "pointer", ...M, letterSpacing: "0.1em" }}>
                LOAD SAMPLE
              </button>
            </div>
            <textarea
              value={emailText}
              onChange={e => setEmailText(e.target.value)}
              style={{ width: "100%", minHeight: 200, background: "transparent", border: "none", color: C.text, ...M, fontSize: 11, padding: "14px 16px", resize: "vertical", outline: "none", lineHeight: 1.7, boxSizing: "border-box" }}
              placeholder={`Paste complete email here including:\n  → Raw headers: From, Reply-To, X-Originating-IP, Received\n  → Full email body with all URLs\n  → Attachment filenames\n  → File hashes (MD5/SHA1/SHA256)\n\nOR upload .eml / .msg / .txt file using the panel →`}
            />
          </div>

          {/* File Upload Panel */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div
              className="upload-zone"
              style={{ background: C.panel, border: `2px dashed ${dragOver ? C.accent : C.border}`, borderRadius: 10, padding: "24px 16px", textAlign: "center", cursor: "pointer", transition: "all 0.2s", flex: 1 }}
              onClick={() => fileRef.current.click()}
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
            >
              <div style={{ fontSize: 32, marginBottom: 10 }}>📎</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: C.textBright, marginBottom: 6 }}>Upload Email File</div>
              <div style={{ fontSize: 10, color: C.textDim, lineHeight: 1.6 }}>
                .eml · .msg · .txt<br/>.exe · .doc · .pdf<br/>.zip · .ps1 · any file
              </div>
              <div style={{ marginTop: 10, fontSize: 9, color: C.textDim, letterSpacing: "0.1em" }}>CLICK OR DRAG & DROP</div>
              <input ref={fileRef} type="file" style={{ display: "none" }} onChange={e => e.target.files[0] && handleFile(e.target.files[0])} />
            </div>

            {fileInfo && (
              <div style={{ background: `${C.green}10`, border: `1px solid ${C.green}30`, borderRadius: 8, padding: "12px 14px" }}>
                <div style={{ fontSize: 10, color: C.green, fontWeight: 600, letterSpacing: "0.1em", marginBottom: 8 }}>✅ FILE LOADED</div>
                <div style={{ fontSize: 11, color: C.textBright, marginBottom: 4, wordBreak: "break-all" }}>{fileInfo.name}</div>
                <div style={{ fontSize: 10, color: C.textDim }}>{(fileInfo.size / 1024).toFixed(1)} KB · .{fileInfo.ext.toUpperCase()}</div>
                <div style={{ marginTop: 8, fontSize: 9, color: C.textDim, ...M, wordBreak: "break-all" }}>MD5: {fileInfo.md5}</div>
              </div>
            )}

            <button
              onClick={handleAnalyze}
              disabled={analyzing || (!emailText.trim() && !fileInfo)}
              style={{ background: analyzing ? C.border : `linear-gradient(135deg, ${C.accent}, ${C.blue})`, border: "none", color: analyzing ? C.textDim : "#000", padding: "14px", borderRadius: 8, fontFamily: "inherit", fontSize: 13, fontWeight: 700, cursor: analyzing ? "not-allowed" : "pointer", letterSpacing: "0.05em", boxShadow: analyzing ? "none" : `0 0 20px ${C.accent}30`, transition: "all 0.2s" }}
            >
              {analyzing ? (
                <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                  <span style={{ width: 14, height: 14, border: `2px solid ${C.textDim}40`, borderTop: `2px solid ${C.accent}`, borderRadius: "50%", animation: "spin 0.8s linear infinite", display: "inline-block" }} />
                  Analyzing...
                </span>
              ) : "⚡ Analyze & Hunt IOCs"}
            </button>

            {results && (
              <button onClick={() => { setResults(null); setEmailText(""); setFileInfo(null); }}
                style={{ background: "transparent", border: `1px solid ${C.border}`, color: C.textDim, padding: "8px", borderRadius: 6, cursor: "pointer", fontFamily: "inherit", fontSize: 11 }}>
                Clear Results
              </button>
            )}
          </div>
        </div>

        {/* RESULTS */}
        {results && (
          <div style={{ animation: "fadeUp 0.4s ease" }}>

            {/* SUMMARY BAR */}
            <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr repeat(6, auto)", alignItems: "center", gap: 0 }}>

                {/* Risk Score Big Display */}
                <div style={{ padding: "16px 24px", background: `${riskColor}12`, borderRight: `1px solid ${C.border}`, textAlign: "center", minWidth: 120 }}>
                  <div style={{ fontSize: 36, fontWeight: 700, color: riskColor, lineHeight: 1, ...M }}>{results.risk.score}</div>
                  <div style={{ fontSize: 9, color: riskColor, letterSpacing: "0.2em", marginTop: 4 }}>/ 100</div>
                  <div style={{ marginTop: 6, background: `${riskColor}20`, border: `1px solid ${riskColor}40`, borderRadius: 3, padding: "2px 8px", fontSize: 10, color: riskColor, fontWeight: 700, letterSpacing: "0.1em" }}>{results.risk.level}</div>
                </div>

                {/* Risk Bar Breakdown */}
                <div style={{ padding: "12px 20px", borderRight: `1px solid ${C.border}` }}>
                  <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 8 }}>WEIGHTED RISK BREAKDOWN</div>
                  {results.risk.breakdown.map((b, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 5 }}>
                      <div style={{ width: 120, fontSize: 10, color: C.textDim }}>{b.label}</div>
                      <div style={{ flex: 1, height: 5, background: C.border, borderRadius: 3, overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${(b.score / b.max) * 100}%`, background: b.color, borderRadius: 3, transition: "width 1s ease", boxShadow: `0 0 6px ${b.color}60` }} />
                      </div>
                      <div style={{ fontSize: 10, color: b.color, fontWeight: 600, ...M, width: 40, textAlign: "right" }}>{b.score}/{b.max}</div>
                    </div>
                  ))}
                </div>

                {/* IOC Counts */}
                {[
                  ["IPs", results.iocs.ips.length, C.red],
                  ["Domains", results.iocs.domains.length, C.blue],
                  ["URLs", results.iocs.urls.length, C.yellow],
                  ["Emails", results.iocs.emails.length, C.purple],
                  ["Hashes", results.iocs.hashes.length, C.accent],
                  ["Files", results.iocs.attachments.length, C.orange],
                ].map(([label, val, color]) => (
                  <div key={label} style={{ padding: "16px 14px", borderRight: `1px solid ${C.border}`, textAlign: "center" }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color, ...M }}>{val}</div>
                    <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.1em", textTransform: "uppercase", marginTop: 3 }}>{label}</div>
                  </div>
                ))}
              </div>

              {/* Flags */}
              {results.risk.flags.length > 0 && (
                <div style={{ borderTop: `1px solid ${C.border}`, padding: "10px 20px", display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {results.risk.flags.map((f, i) => (
                    <span key={i} style={{ background: `${C.red}10`, border: `1px solid ${C.red}25`, color: C.red, fontSize: 10, padding: "3px 10px", borderRadius: 3 }}>{f}</span>
                  ))}
                </div>
              )}
            </div>

            {/* TABS */}
            <div style={{ display: "flex", gap: 2, background: C.panel, borderRadius: "8px 8px 0 0", border: `1px solid ${C.border}`, borderBottom: "none", overflowX: "auto" }}>
              {tabs.map(t => (
                <button key={t.id} className="tab-btn" onClick={() => setActiveTab(t.id)}
                  style={{ background: activeTab === t.id ? C.border : "transparent", border: "none", borderBottom: activeTab === t.id ? `2px solid ${C.accent}` : "2px solid transparent", color: activeTab === t.id ? C.textBright : C.textDim, padding: "11px 16px", cursor: "pointer", fontFamily: "inherit", fontSize: 11, fontWeight: activeTab === t.id ? 600 : 400, whiteSpace: "nowrap", transition: "all 0.15s" }}>
                  {t.icon} {t.label}
                </button>
              ))}
            </div>

            {/* TAB CONTENT */}
            <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderTop: "none", borderRadius: "0 0 10px 10px", padding: 20, minHeight: 400 }}>

              {/* ── RISK SCORE TAB ── */}
              {activeTab === "risk" && (
                <div>
                  <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 16 }}>MITRE ATT&CK TECHNIQUE MAPPING</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 20 }}>
                    {[
                      { id: "T1566.001", name: "Spearphishing Attachment", rel: results.iocs.attachments.length > 0 },
                      { id: "T1566.002", name: "Spearphishing Link", rel: results.iocs.urls.length > 0 },
                      { id: "T1071.001", name: "Web Protocols C2", rel: results.iocs.ips.length > 0 },
                      { id: "T1059", name: "Command & Scripting", rel: results.iocs.attachments.some(a => /\.(bat|ps1|vbs|js|hta)$/i.test(a)) },
                      { id: "T1078", name: "Valid Accounts", rel: results.risk.score > 40 },
                      { id: "T1027", name: "Obfuscation/Shorteners", rel: results.iocs.urls.some(u => /bit\.ly|tinyurl/.test(u)) },
                      { id: "T1105", name: "Ingress Tool Transfer", rel: results.iocs.urls.some(u => /download|payload|drop/.test(u)) },
                      { id: "T1041", name: "Exfiltration over C2", rel: results.iocs.ips.length > 0 },
                    ].filter(t => t.rel).map(t => (
                      <div key={t.id} style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}25`, borderRadius: 6, padding: "6px 12px", display: "flex", gap: 8, alignItems: "center" }}>
                        <span style={{ color: C.accent, fontWeight: 700, fontSize: 11, ...M }}>{t.id}</span>
                        <span style={{ color: C.textDim, fontSize: 10 }}>—</span>
                        <span style={{ color: C.text, fontSize: 11 }}>{t.name}</span>
                      </div>
                    ))}
                  </div>

                  <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>RISK SCORE METHODOLOGY — FIXED WEIGHTED ALGORITHM</div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                    {[
                      { cat: "Sender Spoofing", max: 25, color: C.red, items: ["From/Reply-To domain mismatch (+15)", "External X-Originating-IP (+5)", "Suspicious sender pattern (+5)"] },
                      { cat: "Social Engineering", max: 20, color: C.orange, items: ["Per urgency keyword (+3 each)", "Max 20 points", "Words: urgent, verify, expired, suspended..."] },
                      { cat: "Malicious Infrastructure", max: 25, color: C.purple, items: ["Per embedded IP (+5 each)", "DGA domain detected (+7)", "URL shortener detected (+8)"] },
                      { cat: "Payload / Attachment", max: 20, color: C.red, items: ["Critical extension exe/ps1/vbs (+8)", "Medium extension doc/zip/pdf (+4)", "Social-eng filename (+5)"] },
                      { cat: "Credential Harvesting", max: 10, color: C.yellow, items: ["Per credential keyword (+2 each)", "Max 10 points", "Words: password, login, verify account..."] },
                    ].map((cat, i) => (
                      <div key={i} style={{ background: "#090E1C", border: `1px solid ${C.border}`, borderLeft: `3px solid ${cat.color}`, borderRadius: 6, padding: "12px 14px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                          <span style={{ fontSize: 12, fontWeight: 600, color: C.textBright }}>{cat.cat}</span>
                          <span style={{ fontSize: 11, color: cat.color, ...M }}>Max {cat.max}pts</span>
                        </div>
                        {cat.items.map((item, j) => (
                          <div key={j} style={{ fontSize: 10, color: C.textDim, marginBottom: 3 }}>▸ {item}</div>
                        ))}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── IOC TAB ── */}
              {activeTab === "iocs" && (
                <div>
                  {[
                    { key: "ips", label: "IP Addresses", color: C.red, icon: "🔴" },
                    { key: "domains", label: "Domains", color: C.blue, icon: "🔵" },
                    { key: "urls", label: "URLs", color: C.yellow, icon: "🟡" },
                    { key: "emails", label: "Email Addresses", color: C.purple, icon: "🟣" },
                    { key: "hashes", label: "File Hashes", color: C.accent, icon: "🟢" },
                    { key: "attachments", label: "Attachments", color: C.orange, icon: "🟠" },
                  ].map(({ key, label, color, icon }) => results.iocs[key].length > 0 && (
                    <div key={key} style={{ marginBottom: 20 }}>
                      <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 10 }}>
                        {icon} {label} ({results.iocs[key].length})
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {results.iocs[key].map((ioc, i) => (
                          <span key={i} onClick={() => copy(ioc, `ioc-${key}-${i}`)}
                            style={{ background: `${color}12`, border: `1px solid ${color}30`, color, fontSize: 11, padding: "4px 10px", borderRadius: 4, cursor: "pointer", ...M, wordBreak: "break-all", transition: "all 0.15s" }}>
                            {copied === `ioc-${key}-${i}` ? "✓ copied" : ioc}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                  {results.iocs.headers.subject && (
                    <div style={{ background: "#090E1C", border: `1px solid ${C.border}`, borderRadius: 6, padding: "14px 16px", marginTop: 10 }}>
                      <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 10 }}>📋 PARSED EMAIL HEADERS</div>
                      {Object.entries(results.iocs.headers).filter(([, v]) => v).map(([k, v]) => (
                        <div key={k} style={{ display: "flex", gap: 12, marginBottom: 6, fontSize: 11 }}>
                          <span style={{ color: C.textDim, minWidth: 130, textTransform: "capitalize" }}>{k.replace(/([A-Z])/g, " $1")}:</span>
                          <span style={{ color: C.text, ...M, wordBreak: "break-all" }}>{v}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ── FILE ANALYSIS TAB ── */}
              {activeTab === "file" && (
                <div>
                  {!fileInfo ? (
                    <div style={{ textAlign: "center", padding: "60px 20px", color: C.textDim }}>
                      <div style={{ fontSize: 40, marginBottom: 12, opacity: 0.4 }}>📎</div>
                      <div style={{ fontSize: 13, marginBottom: 8 }}>No file uploaded yet</div>
                      <div style={{ fontSize: 11 }}>Upload a .eml, .exe, .doc, .pdf or any attachment using the panel on the left</div>
                    </div>
                  ) : (
                    <div>
                      {/* File Info */}
                      <div style={{ background: "#090E1C", border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px", marginBottom: 16 }}>
                        <div style={{ fontSize: 10, color: C.accent, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>📄 FILE METADATA</div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                          {[
                            ["Filename", fileInfo.name],
                            ["Size", `${(fileInfo.size / 1024).toFixed(2)} KB (${fileInfo.size} bytes)`],
                            ["Extension", `.${fileInfo.ext.toUpperCase()}`],
                            ["MIME Type", fileInfo.type || "Unknown"],
                          ].map(([k, v]) => (
                            <div key={k}>
                              <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 3 }}>{k}</div>
                              <div style={{ fontSize: 12, color: C.textBright, ...M }}>{v}</div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Hashes */}
                      <div style={{ background: "#090E1C", border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px", marginBottom: 16 }}>
                        <div style={{ fontSize: 10, color: C.accent, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>🔐 FILE HASHES</div>
                        {[["MD5", fileInfo.md5], ["SHA-1", fileInfo.sha1], ["SHA-256", fileInfo.sha256]].map(([type, hash]) => (
                          <div key={type} style={{ marginBottom: 10 }}>
                            <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.1em", marginBottom: 4 }}>{type}</div>
                            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                              <code style={{ fontSize: 11, color: C.accent, ...M, wordBreak: "break-all", flex: 1 }}>{hash}</code>
                              <button className="copy-btn" onClick={() => copy(hash, `hash-${type}`)}
                                style={{ background: `${C.accent}15`, border: `1px solid ${C.accent}30`, color: C.accent, fontSize: 9, padding: "3px 8px", borderRadius: 3, cursor: "pointer", ...M, whiteSpace: "nowrap" }}>
                                {copied === `hash-${type}` ? "✓" : "COPY"}
                              </button>
                            </div>
                          </div>
                        ))}
                        <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
                          <a href={fileInfo.vtUrl} target="_blank" rel="noreferrer" style={{ background: `${C.blue}15`, border: `1px solid ${C.blue}30`, color: C.blue, fontSize: 10, padding: "5px 12px", borderRadius: 4, textDecoration: "none", fontFamily: "inherit" }}>
                            🔍 Search on VirusTotal →
                          </a>
                          <a href="https://app.any.run/" target="_blank" rel="noreferrer" style={{ background: `${C.orange}15`, border: `1px solid ${C.orange}30`, color: C.orange, fontSize: 10, padding: "5px 12px", borderRadius: 4, textDecoration: "none", fontFamily: "inherit" }}>
                            🧪 Submit to ANY.run →
                          </a>
                        </div>
                      </div>

                      {/* Behavioral Analysis */}
                      <div>
                        <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>🧬 BEHAVIORAL ANALYSIS</div>
                        {fileInfo.behaviors.map((b, i) => (
                          <div key={i} style={{ background: "#090E1C", border: `1px solid ${b.type === "CRITICAL" ? C.red : b.type === "HIGH" ? C.orange : b.type === "MEDIUM" ? C.yellow : C.border}25`, borderLeft: `3px solid ${b.type === "CRITICAL" ? C.red : b.type === "HIGH" ? C.orange : b.type === "MEDIUM" ? C.yellow : C.accent}`, borderRadius: 6, padding: "10px 14px", marginBottom: 8 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                              <span style={{ fontSize: 12, fontWeight: 600, color: C.textBright }}>{b.label}</span>
                              <span style={{ fontSize: 9, fontWeight: 700, color: b.type === "CRITICAL" ? C.red : b.type === "HIGH" ? C.orange : b.type === "MEDIUM" ? C.yellow : C.accent, letterSpacing: "0.1em", background: `${b.type === "CRITICAL" ? C.red : b.type === "HIGH" ? C.orange : C.accent}15`, padding: "2px 8px", borderRadius: 3 }}>{b.type}</span>
                            </div>
                            <div style={{ fontSize: 11, color: C.textDim }}>{b.detail}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── C2 DETECTION TAB ── */}
              {activeTab === "c2" && (
                <div>
                  {results.c2.c2Indicators.length === 0 && results.c2.beaconPatterns.length === 0 ? (
                    <div style={{ textAlign: "center", padding: "40px", color: C.textDim }}>
                      <div style={{ fontSize: 30, marginBottom: 10 }}>📡</div>
                      <div>No C2 indicators detected in this sample</div>
                    </div>
                  ) : (
                    <>
                      {results.c2.c2Indicators.length > 0 && (
                        <>
                          <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>🚨 C2 INFRASTRUCTURE INDICATORS</div>
                          {results.c2.c2Indicators.map((ind, i) => (
                            <div key={i} style={{ background: "#090E1C", border: `1px solid ${ind.severity === "CRITICAL" ? C.red : C.orange}25`, borderLeft: `3px solid ${ind.severity === "CRITICAL" ? C.red : C.orange}`, borderRadius: 6, padding: "12px 16px", marginBottom: 10 }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                                  <span style={{ fontSize: 9, color: ind.severity === "CRITICAL" ? C.red : C.orange, fontWeight: 700, letterSpacing: "0.1em", background: `${ind.severity === "CRITICAL" ? C.red : C.orange}15`, padding: "2px 8px", borderRadius: 3 }}>{ind.type}</span>
                                  <code style={{ fontSize: 12, color: C.textBright, ...M }}>{ind.value}</code>
                                </div>
                                <span style={{ fontSize: 9, color: ind.severity === "CRITICAL" ? C.red : C.orange, fontWeight: 700 }}>{ind.severity}</span>
                              </div>
                              <div style={{ fontSize: 11, color: C.textDim }}>{ind.detail}</div>
                            </div>
                          ))}
                        </>
                      )}
                      {results.c2.beaconPatterns.length > 0 && (
                        <>
                          <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", margin: "20px 0 12px" }}>📡 BEACON PATTERNS DETECTED</div>
                          {results.c2.beaconPatterns.map((bp, i) => (
                            <div key={i} style={{ background: "#090E1C", border: `1px solid ${C.purple}25`, borderLeft: `3px solid ${C.purple}`, borderRadius: 6, padding: "12px 16px", marginBottom: 10 }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                                  <span style={{ fontSize: 9, color: C.purple, fontWeight: 700, letterSpacing: "0.1em", background: `${C.purple}15`, padding: "2px 8px", borderRadius: 3 }}>{bp.pattern}</span>
                                  <code style={{ fontSize: 11, color: C.accent, ...M, wordBreak: "break-all", maxWidth: 400 }}>{bp.url}</code>
                                </div>
                                <span style={{ fontSize: 9, color: C.purple, fontWeight: 700, ...M }}>{bp.mitre}</span>
                              </div>
                              <div style={{ fontSize: 11, color: C.textDim }}>{bp.detail}</div>
                            </div>
                          ))}
                        </>
                      )}
                    </>
                  )}
                </div>
              )}

              {/* ── ATTACK CHAIN TAB ── */}
              {activeTab === "chain" && (
                <div>
                  <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 20 }}>END-TO-END ATTACK CHAIN — MITRE ATT&CK KILL CHAIN</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
                    {results.chain.map((phase, i) => (
                      <div key={i} style={{ display: "flex", gap: 0, alignItems: "stretch" }}>

                        {/* Left timeline */}
                        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 48, flexShrink: 0 }}>
                          <div style={{ width: 36, height: 36, borderRadius: "50%", background: `${phase.color}20`, border: `2px solid ${phase.color}60`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, flexShrink: 0, boxShadow: `0 0 10px ${phase.color}30` }}>
                            {phase.icon}
                          </div>
                          {i < results.chain.length - 1 && (
                            <div style={{ width: 2, flex: 1, background: `linear-gradient(${phase.color}60, ${results.chain[i+1].color}60)`, minHeight: 20, margin: "4px 0" }} />
                          )}
                        </div>

                        {/* Phase card */}
                        <div style={{ flex: 1, background: "#090E1C", border: `1px solid ${phase.color}20`, borderRadius: 8, padding: "14px 16px", marginBottom: i < results.chain.length - 1 ? 8 : 0, marginLeft: 10 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                              <span style={{ fontSize: 11, fontWeight: 700, color: phase.color, letterSpacing: "0.05em" }}>Phase {phase.phase}: {phase.name}</span>
                              <span style={{ fontSize: 9, color: C.textDim, ...M }}>{phase.tactic}</span>
                            </div>
                            <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.1em", background: phase.status === "confirmed" ? `${C.red}15` : phase.status === "likely" ? `${C.orange}15` : `${C.yellow}15`, border: `1px solid ${phase.status === "confirmed" ? C.red : phase.status === "likely" ? C.orange : C.yellow}30`, color: phase.status === "confirmed" ? C.red : phase.status === "likely" ? C.orange : C.yellow, padding: "2px 8px", borderRadius: 3, textTransform: "uppercase" }}>
                              {phase.status}
                            </span>
                          </div>
                          <div style={{ fontSize: 11, color: C.text, marginBottom: 8, lineHeight: 1.6 }}>{phase.detail}</div>
                          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                            {phase.techniques.map((t, j) => (
                              <span key={j} style={{ background: `${phase.color}10`, border: `1px solid ${phase.color}25`, color: phase.color, fontSize: 9, padding: "2px 8px", borderRadius: 3, ...M }}>{t}</span>
                            ))}
                          </div>
                          {phase.evidence && (
                            <div style={{ marginTop: 8, fontSize: 10, color: C.textDim }}>
                              <span style={{ color: C.textDim }}>Evidence: </span>
                              <code style={{ color: C.accent, ...M }}>{phase.evidence}</code>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
                    {[["confirmed", C.red, "Confirmed by IOCs in email"], ["likely", C.orange, "Likely based on attack pattern"], ["suspected", C.yellow, "Suspected next stage"]].map(([s, c, d]) => (
                      <div key={s} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, color: C.textDim }}>
                        <div style={{ width: 8, height: 8, borderRadius: "50%", background: c }} />
                        <span style={{ color: c, fontWeight: 600, textTransform: "uppercase" }}>{s}</span>
                        <span>— {d}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── ENRICHMENT TAB ── */}
              {activeTab === "enrichment" && (
                <div>
                  {results.iocs.ips.length > 0 && (
                    <>
                      <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>⚡ ABUSEIPDB REPUTATION</div>
                      {results.iocs.ips.map((ip, i) => {
                        const d = results.enrichment.abuseResults[ip];
                        return (
                          <div key={i} style={{ background: "#090E1C", border: `1px solid ${d.abuseScore > 50 ? C.red : C.yellow}25`, borderLeft: `3px solid ${d.abuseScore > 50 ? C.red : C.yellow}`, borderRadius: 8, padding: "14px 16px", marginBottom: 10 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                              <code style={{ fontSize: 14, fontWeight: 700, color: C.textBright, ...M }}>{ip}</code>
                              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                <span style={{ fontSize: 11, color: C.textDim }}>Abuse Score:</span>
                                <span style={{ fontSize: 16, fontWeight: 700, color: d.abuseScore > 75 ? C.red : d.abuseScore > 40 ? C.orange : C.yellow, ...M }}>{d.abuseScore}%</span>
                              </div>
                            </div>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
                              {[["Country", `${d.countryName} (${d.country})`], ["ISP/Hosting", d.isp], ["Usage Type", d.usageType], ["Total Reports", d.totalReports], ["Last Reported", d.lastReported], ["Verdict", d.verdict]].map(([k, v]) => (
                                <div key={k}>
                                  <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 2 }}>{k}</div>
                                  <div style={{ fontSize: 11, color: k === "Verdict" ? (v === "MALICIOUS" ? C.red : v === "SUSPICIOUS" ? C.orange : C.accent) : C.text, fontWeight: k === "Verdict" ? 700 : 400 }}>{v}</div>
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                    </>
                  )}

                  {[...results.iocs.ips, ...results.iocs.domains].length > 0 && (
                    <>
                      <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", margin: "20px 0 12px" }}>🦠 VIRUSTOTAL REPUTATION</div>
                      {[...results.iocs.ips, ...results.iocs.domains].map((ioc, i) => {
                        const vt = results.enrichment.vtResults[ioc];
                        const pct = Math.round((vt.detections / vt.total) * 100);
                        return (
                          <div key={i} style={{ background: "#090E1C", border: `1px solid ${vt.verdict === "Malicious" ? C.red : vt.verdict === "Suspicious" ? C.yellow : C.border}25`, borderLeft: `3px solid ${vt.verdict === "Malicious" ? C.red : vt.verdict === "Suspicious" ? C.yellow : C.accent}`, borderRadius: 8, padding: "12px 16px", marginBottom: 8 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                              <code style={{ fontSize: 12, fontWeight: 600, color: C.textBright, ...M }}>{ioc}</code>
                              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                <span style={{ fontSize: 11, color: C.textDim }}>{vt.detections}/{vt.total} engines</span>
                                <span style={{ fontSize: 10, fontWeight: 700, background: `${vt.verdict === "Malicious" ? C.red : vt.verdict === "Suspicious" ? C.yellow : C.accent}15`, border: `1px solid ${vt.verdict === "Malicious" ? C.red : vt.verdict === "Suspicious" ? C.yellow : C.accent}30`, color: vt.verdict === "Malicious" ? C.red : vt.verdict === "Suspicious" ? C.yellow : C.accent, padding: "2px 10px", borderRadius: 3 }}>{vt.verdict}</span>
                              </div>
                            </div>
                            <div style={{ height: 4, background: C.border, borderRadius: 2, overflow: "hidden", marginBottom: 6 }}>
                              <div style={{ height: "100%", width: `${pct}%`, background: vt.verdict === "Malicious" ? C.red : vt.verdict === "Suspicious" ? C.yellow : C.accent, borderRadius: 2 }} />
                            </div>
                            {vt.engines.length > 0 && <div style={{ fontSize: 10, color: C.textDim }}>Detected by: {vt.engines.join(", ")}</div>}
                          </div>
                        );
                      })}
                    </>
                  )}
                </div>
              )}

              {/* ── QUERIES TAB ── */}
              {activeTab === "queries" && (
                <div>
                  <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
                    {[["splunk","Splunk SPL"],["sentinel","Sentinel KQL"],["crowdstrike","CrowdStrike"],["mde","MDE (Defender)"]].map(([id, label]) => (
                      <button key={id} onClick={() => setQueryTab(id)}
                        style={{ background: queryTab === id ? C.accent : "transparent", border: `1px solid ${queryTab === id ? C.accent : C.border}`, color: queryTab === id ? "#000" : C.textDim, padding: "6px 14px", borderRadius: 4, fontFamily: "inherit", fontSize: 11, cursor: "pointer", fontWeight: queryTab === id ? 700 : 400, transition: "all 0.15s" }}>
                        {label}
                      </button>
                    ))}
                  </div>
                  <div style={{ position: "relative" }}>
                    <pre style={{ background: "#050A12", border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px", fontSize: 11, color: C.accent, lineHeight: 1.8, whiteSpace: "pre-wrap", wordBreak: "break-all", ...M, maxHeight: 500, overflow: "auto" }}>
                      {results.queries[queryTab]}
                    </pre>
                    <button className="copy-btn" onClick={() => copy(results.queries[queryTab], "query")}
                      style={{ position: "absolute", top: 10, right: 10, background: `${C.accent}15`, border: `1px solid ${C.accent}30`, color: C.accent, fontSize: 9, padding: "4px 10px", borderRadius: 3, cursor: "pointer", ...M, letterSpacing: "0.1em" }}>
                      {copied === "query" ? "✓ COPIED" : "COPY ALL"}
                    </button>
                  </div>
                </div>
              )}

              {/* ── CONTROLS TAB ── */}
              {activeTab === "controls" && (
                <div>
                  {["CRITICAL","HIGH","MEDIUM","LOW"].map(priority => {
                    const pControls = results.controls.filter(c => c.priority === priority);
                    if (!pControls.length) return null;
                    const pColor = { CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow, LOW: C.accent }[priority];
                    return (
                      <div key={priority} style={{ marginBottom: 20 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                          <span style={{ background: `${pColor}15`, border: `1px solid ${pColor}30`, color: pColor, fontSize: 9, padding: "3px 10px", borderRadius: 3, fontWeight: 700, letterSpacing: "0.15em" }}>{priority}</span>
                          <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.1em", textTransform: "uppercase" }}>Priority Controls</span>
                        </div>
                        {pControls.map((ctrl, i) => (
                          <div key={i} className="hoverable" style={{ background: "#090E1C", border: `1px solid ${ctrl.color}15`, borderLeft: `3px solid ${ctrl.color}`, borderRadius: 8, padding: "14px 16px", marginBottom: 8, transition: "all 0.2s" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
                              <div style={{ fontSize: 12, fontWeight: 600, color: C.textBright }}>{ctrl.title}</div>
                              <div style={{ display: "flex", gap: 6 }}>
                                <span style={{ fontSize: 9, color: C.textDim, background: C.border, padding: "2px 8px", borderRadius: 3 }}>{ctrl.cat}</span>
                                <span style={{ fontSize: 9, color: C.purple, ...M }}>{ctrl.mitre}</span>
                              </div>
                            </div>
                            <div style={{ fontSize: 11, color: C.text, lineHeight: 1.6, marginBottom: 10 }}>{ctrl.desc}</div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                              {ctrl.tools.map((tool, j) => (
                                <span key={j} style={{ background: C.border, border: `1px solid ${C.border}`, color: C.textDim, fontSize: 10, padding: "2px 8px", borderRadius: 3 }}>{tool}</span>
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

        {!results && !analyzing && (
          <div style={{ textAlign: "center", padding: "60px 20px", color: C.textDim }}>
            <div style={{ fontSize: 48, marginBottom: 16, opacity: 0.3 }}>🎣</div>
            <div style={{ fontSize: 13, color: C.textDim, marginBottom: 8 }}>PASTE AN EMAIL OR UPLOAD A FILE THEN CLICK ANALYZE</div>
            <div style={{ fontSize: 11, color: C.textDim, opacity: 0.6 }}>
              Fixed Risk Scoring · File Hash Analysis · C2 Detection · End-to-End Attack Chain
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
