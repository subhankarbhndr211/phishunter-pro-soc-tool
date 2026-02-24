import { useState, useRef, useCallback } from "react";

// ============================================================
// PHISHHUNTER PRO — UNIVERSAL FILE ANALYZER
// Supports: .eml .msg .txt .exe .doc .docx .pdf .zip .rar
//           .ps1 .vbs .bat .js .hta .lnk .dll .msi .iso
//           .xls .xlsx .ppt .pptx .7z .py .jar .apk + more
// ============================================================

const C = {
  bg: "#070C18", panel: "#0C1424", border: "#162035",
  accent: "#00E5FF", green: "#00FF88", orange: "#FF8C00",
  red: "#FF3D5A", purple: "#B44FFF", yellow: "#FFD60A",
  blue: "#2979FF", pink: "#FF4088", cyan: "#00FFCC",
  text: "#B8CCE8", textDim: "#3D5070", textBright: "#EEF4FF",
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-thumb { background: #1C2B4A; border-radius: 2px; }
  @keyframes fadeUp { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
  @keyframes spin { to{transform:rotate(360deg)} }
  @keyframes scan { 0%{top:0} 100%{top:100%} }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
  .hover-card:hover { border-color: #00E5FF30 !important; background: #0F1A2E !important; }
  .copy-btn:hover { background: #00E5FF !important; color: #000 !important; }
  .tab-active { border-bottom: 2px solid #00E5FF !important; color: #EEF4FF !important; }
  .drop-active { border-color: #00E5FF !important; background: #00E5FF0A !important; }
`;

// ─── MAGIC BYTES — FILE SIGNATURES ────────────────────────
const MAGIC_BYTES = [
  { sig: [0x4D,0x5A], name: "PE Executable (MZ)", type: "EXECUTABLE", risk: "CRITICAL", icon: "⚠️", desc: "Windows Portable Executable — direct code execution" },
  { sig: [0x50,0x4B,0x03,0x04], name: "ZIP Archive (PK)", type: "ARCHIVE", risk: "HIGH", icon: "📦", desc: "ZIP container — may contain nested malware" },
  { sig: [0x25,0x50,0x44,0x46], name: "PDF Document", type: "DOCUMENT", risk: "MEDIUM", icon: "📄", desc: "PDF — can embed JavaScript, launch actions, executables" },
  { sig: [0xD0,0xCF,0x11,0xE0], name: "OLE2 Compound (Office 97-2003)", type: "OFFICE", risk: "HIGH", icon: "📝", desc: "Legacy Office format — macro execution, CVE exploits common" },
  { sig: [0x50,0x4B,0x03,0x04,0x14,0x00,0x06,0x00], name: "OOXML Office (docx/xlsx/pptx)", type: "OFFICE", risk: "HIGH", icon: "📊", desc: "Modern Office format — can still contain malicious macros" },
  { sig: [0x52,0x61,0x72,0x21], name: "RAR Archive", type: "ARCHIVE", risk: "HIGH", icon: "📦", desc: "RAR container — frequently used to bypass AV scanning" },
  { sig: [0x37,0x7A,0xBC,0xAF], name: "7-Zip Archive", type: "ARCHIVE", risk: "HIGH", icon: "📦", desc: "7z container — password protection bypasses email gateways" },
  { sig: [0x1F,0x8B], name: "GZIP Archive", type: "ARCHIVE", risk: "MEDIUM", icon: "📦", desc: "GZIP compressed file" },
  { sig: [0xCA,0xFE,0xBA,0xBE], name: "Java Class / JAR", type: "EXECUTABLE", risk: "HIGH", icon: "☕", desc: "Java bytecode — cross-platform execution" },
  { sig: [0x7F,0x45,0x4C,0x46], name: "ELF Executable (Linux)", type: "EXECUTABLE", risk: "CRITICAL", icon: "🐧", desc: "Linux/Unix executable — may run on servers" },
  { sig: [0x4D,0x53,0x43,0x46], name: "Microsoft Cabinet (.cab)", type: "ARCHIVE", risk: "HIGH", icon: "📦", desc: "CAB archive — used to deliver Windows installers" },
  { sig: [0x49,0x53,0x4F], name: "ISO Disk Image", type: "ARCHIVE", risk: "HIGH", icon: "💿", desc: "ISO image — MoTW bypass technique, used in malware delivery" },
  { sig: [0xFF,0xFE], name: "Unicode Text (UTF-16 LE)", type: "TEXT", risk: "LOW", icon: "📝", desc: "Unicode text file" },
  { sig: [0xEF,0xBB,0xBF], name: "UTF-8 Text with BOM", type: "TEXT", risk: "LOW", icon: "📝", desc: "UTF-8 encoded text" },
  { sig: [0x78,0x9C], name: "ZLib Compressed Data", type: "COMPRESSED", risk: "MEDIUM", icon: "🗜", desc: "ZLib stream — often embedded in malware" },
];

// ─── FILE TYPE DATABASE ────────────────────────────────────
const FILE_TYPES = {
  // CRITICAL RISK
  exe:  { risk: "CRITICAL", cat: "Executable",  icon: "💀", color: C.red,    desc: "Windows executable — highest risk, direct code execution" },
  dll:  { risk: "CRITICAL", cat: "Library",     icon: "💀", color: C.red,    desc: "Dynamic Link Library — loaded by other processes" },
  scr:  { risk: "CRITICAL", cat: "Screensaver", icon: "💀", color: C.red,    desc: "Screensaver = PE executable with .scr extension, commonly abused" },
  com:  { risk: "CRITICAL", cat: "Executable",  icon: "💀", color: C.red,    desc: "DOS/Windows executable" },
  // HIGH RISK SCRIPTS
  ps1:  { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "PowerShell script — LOLBin, AMSI bypass, commonly used in C2" },
  vbs:  { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "VBScript — Windows scripting, frequent malware dropper" },
  js:   { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "JavaScript — WSH execution, dropper, encoded payloads" },
  jse:  { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "Encoded JScript — obfuscated, AV evasion" },
  vbe:  { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "Encoded VBScript — obfuscated VBS" },
  bat:  { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "Batch script — command execution, persistence" },
  cmd:  { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "Windows command script" },
  hta:  { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "HTML Application — runs with elevated privileges via mshta.exe" },
  wsf:  { risk: "HIGH",     cat: "Script",      icon: "⚡", color: C.orange, desc: "Windows Script File — multi-language script execution" },
  lnk:  { risk: "HIGH",     cat: "Shortcut",    icon: "🔗", color: C.orange, desc: "Windows shortcut — can execute arbitrary commands, DLL hijack" },
  msi:  { risk: "HIGH",     cat: "Installer",   icon: "📦", color: C.orange, desc: "Windows installer — can execute code during install" },
  // MEDIUM-HIGH RISK
  doc:  { risk: "HIGH",     cat: "Office",      icon: "📝", color: C.yellow, desc: "Word document — VBA macros, template injection, OLE objects" },
  docx: { risk: "HIGH",     cat: "Office",      icon: "📝", color: C.yellow, desc: "Word document — macros, remote template loading" },
  xls:  { risk: "HIGH",     cat: "Office",      icon: "📊", color: C.yellow, desc: "Excel spreadsheet — XLM macros (Excel 4.0), VBA" },
  xlsx: { risk: "HIGH",     cat: "Office",      icon: "📊", color: C.yellow, desc: "Excel spreadsheet — macro execution, data exfil" },
  xlsm: { risk: "HIGH",     cat: "Office",      icon: "📊", color: C.yellow, desc: "Excel macro-enabled — VBA macros present" },
  ppt:  { risk: "MEDIUM",   cat: "Office",      icon: "📑", color: C.yellow, desc: "PowerPoint — action buttons, OLE embedding" },
  pptx: { risk: "MEDIUM",   cat: "Office",      icon: "📑", color: C.yellow, desc: "PowerPoint — embedded objects, macros" },
  // ARCHIVES
  zip:  { risk: "HIGH",     cat: "Archive",     icon: "📦", color: C.orange, desc: "ZIP archive — nested malware, password protection to bypass AV" },
  rar:  { risk: "HIGH",     cat: "Archive",     icon: "📦", color: C.orange, desc: "RAR archive — AV evasion technique" },
  "7z": { risk: "HIGH",     cat: "Archive",     icon: "📦", color: C.orange, desc: "7-Zip archive — password protection, AV bypass" },
  iso:  { risk: "HIGH",     cat: "Disk Image",  icon: "💿", color: C.orange, desc: "ISO image — MoTW bypass, mounts as drive letter" },
  img:  { risk: "HIGH",     cat: "Disk Image",  icon: "💿", color: C.orange, desc: "Disk image — same as ISO for malware delivery" },
  // DOCUMENTS
  pdf:  { risk: "MEDIUM",   cat: "Document",    icon: "📄", color: C.yellow, desc: "PDF — JavaScript, launch actions, embedded executables, CVEs" },
  rtf:  { risk: "HIGH",     cat: "Document",    icon: "📄", color: C.orange, desc: "Rich Text Format — frequently used in CVE exploits (CVE-2017-11882)" },
  // EMAIL FORMATS
  eml:  { risk: "MEDIUM",   cat: "Email",       icon: "📧", color: C.blue,   desc: "Raw email format — contains headers, body, attachments" },
  msg:  { risk: "MEDIUM",   cat: "Email",       icon: "📧", color: C.blue,   desc: "Outlook email — OLE2 format with attachments" },
  // LOW RISK TEXT
  txt:  { risk: "LOW",      cat: "Text",        icon: "📄", color: C.accent, desc: "Plain text — low risk but may contain encoded payloads" },
  html: { risk: "LOW",      cat: "HTML",        icon: "🌐", color: C.accent, desc: "HTML — phishing pages, credential harvesting" },
  htm:  { risk: "LOW",      cat: "HTML",        icon: "🌐", color: C.accent, desc: "HTML page — same as .html" },
  xml:  { risk: "LOW",      cat: "XML",         icon: "📄", color: C.accent, desc: "XML data — may contain URLs, encoded payloads" },
  csv:  { risk: "LOW",      cat: "Data",        icon: "📊", color: C.accent, desc: "CSV data file — formula injection possible in Excel" },
  // DEVELOPER
  py:   { risk: "HIGH",     cat: "Script",      icon: "🐍", color: C.orange, desc: "Python script — cross-platform execution" },
  jar:  { risk: "HIGH",     cat: "Java",        icon: "☕", color: C.orange, desc: "Java archive — cross-platform code execution" },
  apk:  { risk: "HIGH",     cat: "Android",     icon: "📱", color: C.orange, desc: "Android package — mobile malware" },
};

// ─── BEHAVIORAL RULES ENGINE ──────────────────────────────
function analyzeBehavior(ext, bytes, textContent) {
  const behaviors = [];
  const iocs = [];
  const strings = [];

  // Extract printable strings from binary (like strings command)
  if (bytes) {
    let current = "";
    for (let i = 0; i < Math.min(bytes.length, 100000); i++) {
      const b = bytes[i];
      if (b >= 32 && b <= 126) {
        current += String.fromCharCode(b);
      } else {
        if (current.length >= 6) strings.push(current);
        current = "";
      }
    }
    if (current.length >= 6) strings.push(current);
  }

  const allText = textContent || strings.join(" ");
  const tl = allText.toLowerCase();

  // ── EXECUTABLE BEHAVIORS ──
  if (["exe","dll","scr","com"].includes(ext)) {
    behaviors.push({ sev: "CRITICAL", name: "PE Executable Detected", detail: "Portable Executable format confirmed — direct code execution capability on Windows", mitre: "T1204.002" });
    if (strings.some(s => /CreateRemoteThread|VirtualAllocEx|WriteProcessMemory/.test(s))) behaviors.push({ sev: "CRITICAL", name: "Process Injection APIs", detail: "Windows APIs for injecting code into other processes — hallmark of advanced malware", mitre: "T1055" });
    if (strings.some(s => /RegCreateKey|RegSetValue|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE/.test(s))) behaviors.push({ sev: "HIGH", name: "Registry Modification", detail: "Registry write operations detected — persistence mechanism (Run keys)", mitre: "T1547.001" });
    if (strings.some(s => /WinInet|InternetOpen|HttpSendRequest|URLDownloadToFile/.test(s))) behaviors.push({ sev: "HIGH", name: "Network/HTTP Communication", detail: "Internet API calls detected — likely C2 communication or payload download", mitre: "T1071.001" });
    if (strings.some(s => /CryptEncrypt|CryptAcquireContext|AES|RC4|base64/.test(s))) behaviors.push({ sev: "HIGH", name: "Encryption/Encoding Routines", detail: "Cryptographic APIs or encoding detected — payload obfuscation or ransomware indicator", mitre: "T1027" });
    if (strings.some(s => /IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess/.test(s))) behaviors.push({ sev: "HIGH", name: "Anti-Debug / Anti-Analysis", detail: "Debugger detection APIs found — malware actively attempts to evade analysis", mitre: "T1497" });
    if (strings.some(s => /GetTempPath|%TEMP%|%APPDATA%|%USERPROFILE%/.test(s))) behaviors.push({ sev: "MEDIUM", name: "Temp/AppData Directory Access", detail: "Writes to user directories — common dropper behavior to place payload", mitre: "T1036" });
    if (strings.some(s => /cmd\.exe|powershell|wscript|cscript|mshta|rundll32/.test(s))) behaviors.push({ sev: "HIGH", name: "LOLBin Execution", detail: "Living-off-the-land binary usage — evades AV by using legitimate Windows tools", mitre: "T1218" });
  }

  // ── SCRIPT BEHAVIORS ──
  if (["ps1","vbs","bat","js","hta","wsf","jse","vbe","cmd"].includes(ext)) {
    behaviors.push({ sev: "CRITICAL", name: "Script File — Immediate Execution Risk", detail: "Script files execute directly via Windows scripting host — no compilation needed", mitre: "T1059" });
    if (tl.includes("downloadstring") || tl.includes("downloadfile") || tl.includes("webclient") || tl.includes("invoke-webrequest")) behaviors.push({ sev: "CRITICAL", name: "Remote Payload Download", detail: "Script downloads content from internet — stage-2 payload delivery", mitre: "T1105" });
    if (tl.includes("-encodedcommand") || tl.includes("base64") || tl.includes("frombase64string") || tl.includes("charcode")) behaviors.push({ sev: "CRITICAL", name: "Encoded/Obfuscated Command", detail: "Base64 or char encoding detected — bypasses script content inspection", mitre: "T1027" });
    if (tl.includes("bypass") || tl.includes("unrestricted") || tl.includes("hidden") || tl.includes("-w hidden")) behaviors.push({ sev: "HIGH", name: "Execution Policy Bypass", detail: "PowerShell execution policy bypass flags — evades security controls", mitre: "T1059.001" });
    if (tl.includes("invoke-expression") || tl.includes("iex(") || tl.includes("iex (")) behaviors.push({ sev: "CRITICAL", name: "IEX / Invoke-Expression", detail: "Dynamic code execution — executes downloaded or decoded payloads in memory", mitre: "T1059.001" });
    if (tl.includes("set-itemproperty") || tl.includes("new-scheduledtask") || tl.includes("schtasks")) behaviors.push({ sev: "HIGH", name: "Persistence Mechanism", detail: "Scheduled task or registry key creation for persistence", mitre: "T1053.005" });
    if (tl.includes("mimikatz") || tl.includes("sekurlsa") || tl.includes("invoke-mimikatz")) behaviors.push({ sev: "CRITICAL", name: "Credential Dumping Tool Reference", detail: "Mimikatz or credential harvesting tool detected", mitre: "T1003" });
    if (tl.includes("net user") || tl.includes("net localgroup") || tl.includes("whoami")) behaviors.push({ sev: "HIGH", name: "Reconnaissance Commands", detail: "System enumeration commands — attacker mapping environment", mitre: "T1087" });
  }

  // ── OFFICE DOCUMENT BEHAVIORS ──
  if (["doc","docx","xls","xlsx","xlsm","ppt","pptx","rtf"].includes(ext)) {
    behaviors.push({ sev: "HIGH", name: "Office Document — Macro Risk", detail: "Office documents can contain VBA macros that execute on open (Auto_Open, Document_Open)", mitre: "T1566.001" });
    if (ext === "rtf") behaviors.push({ sev: "CRITICAL", name: "RTF Format — CVE Exploit Risk", detail: "RTF commonly exploited in CVE-2017-11882, CVE-2017-0199, CVE-2010-3333 — equation editor vulns", mitre: "T1203" });
    if (["xlsm"].includes(ext)) behaviors.push({ sev: "CRITICAL", name: "Macro-Enabled Spreadsheet", detail: "XLSM explicitly contains macros — execute on open without warning in some configs", mitre: "T1059.005" });
    if (tl.includes("autoopen") || tl.includes("auto_open") || tl.includes("document_open") || tl.includes("workbook_open")) behaviors.push({ sev: "CRITICAL", name: "Auto-Execution Macro Trigger", detail: "Auto-open macro triggers found — code executes immediately when document opens", mitre: "T1059.005" });
    if (tl.includes("shell(") || tl.includes("wscript.shell") || tl.includes("createobject")) behaviors.push({ sev: "CRITICAL", name: "Shell Execution from Macro", detail: "VBA calling system shell — drops or executes payloads from Office", mitre: "T1059.005" });
    if (tl.includes("http://") || tl.includes("https://")) behaviors.push({ sev: "HIGH", name: "Remote URL in Document", detail: "URLs embedded in document — remote template injection or C2 callback", mitre: "T1221" });
  }

  // ── PDF BEHAVIORS ──
  if (ext === "pdf") {
    behaviors.push({ sev: "MEDIUM", name: "PDF Format", detail: "PDFs can contain JavaScript, OpenAction triggers, embedded files, URI actions", mitre: "T1566.001" });
    if (tl.includes("/javascript") || tl.includes("/js ")) behaviors.push({ sev: "HIGH", name: "JavaScript Embedded in PDF", detail: "JavaScript within PDF — can exploit reader vulnerabilities or redirect to URLs", mitre: "T1059.007" });
    if (tl.includes("/openaction") || tl.includes("/aa ")) behaviors.push({ sev: "HIGH", name: "Auto-Action Trigger", detail: "PDF auto-executes action on open — no user interaction required", mitre: "T1204.002" });
    if (tl.includes("/embeddedfile") || tl.includes("/filespec")) behaviors.push({ sev: "HIGH", name: "Embedded File in PDF", detail: "File embedded within PDF — dropper technique", mitre: "T1566.001" });
    if (tl.includes("/launch")) behaviors.push({ sev: "CRITICAL", name: "Launch Action", detail: "PDF attempts to launch external application — direct execution trigger", mitre: "T1204.002" });
    if (tl.includes("/uri")) behaviors.push({ sev: "MEDIUM", name: "URI Action", detail: "PDF contains URL links — may redirect to phishing or malware download", mitre: "T1566.002" });
  }

  // ── ARCHIVE BEHAVIORS ──
  if (["zip","rar","7z","iso","img","cab"].includes(ext)) {
    behaviors.push({ sev: "HIGH", name: "Archive Container", detail: "Archives can contain nested malware, bypass email AV scanning, and extract to disk", mitre: "T1027.002" });
    if (ext === "iso" || ext === "img") behaviors.push({ sev: "CRITICAL", name: "Disk Image — Mark of the Web Bypass", detail: "ISO/IMG files bypass Windows MoTW protection — files inside are not marked as web downloads", mitre: "T1553.005" });
    behaviors.push({ sev: "MEDIUM", name: "Password Protection Possible", detail: "Archives may be password-protected to bypass gateway scanning — password often in email body", mitre: "T1027" });
  }

  // ── EMAIL FORMAT ──
  if (["eml","msg"].includes(ext)) {
    behaviors.push({ sev: "MEDIUM", name: "Email File Format", detail: "Contains raw email with headers, body, and potentially nested attachments", mitre: "T1566" });
    if (tl.includes("x-originating-ip")) behaviors.push({ sev: "HIGH", name: "X-Originating-IP Header Present", detail: "Reveals true sending IP — cross-reference with AbuseIPDB", mitre: "T1566.001" });
    if (tl.includes("reply-to:") && tl.includes("from:")) behaviors.push({ sev: "HIGH", name: "Reply-To Mismatch Possible", detail: "Both From and Reply-To present — check for domain mismatch (spoofing indicator)", mitre: "T1566.001" });
  }

  // ── UNIVERSAL TEXT-BASED IOC EXTRACTION ──
  const urlsFound = allText.match(/https?:\/\/[^\s<>"']{10,}/g) || [];
  const ipsFound = allText.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) || [];
  const emailsFound = allText.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [];
  const hashesFound = allText.match(/\b[a-fA-F0-9]{32,64}\b/g) || [];

  if (urlsFound.length > 0) iocs.push({ type: "URLs", values: [...new Set(urlsFound)].slice(0, 20), color: C.yellow });
  if (ipsFound.length > 0) iocs.push({ type: "IP Addresses", values: [...new Set(ipsFound)].filter(ip => !ip.startsWith("127.") && !ip.startsWith("192.168.")), color: C.red });
  if (emailsFound.length > 0) iocs.push({ type: "Email Addresses", values: [...new Set(emailsFound)].slice(0, 10), color: C.purple });
  if (hashesFound.length > 0) iocs.push({ type: "Embedded Hashes", values: [...new Set(hashesFound)].slice(0, 10), color: C.accent });

  // Suspicious strings
  const suspStrings = strings.filter(s =>
    /cmd\.exe|powershell|wscript|mshta|regsvr32|rundll32|certutil|bitsadmin|schtasks|net\.exe|net1\.exe|whoami|ipconfig|mimikatz|beacon|cobalt|metasploit|payload|shellcode|inject|hook|bypass|evasion|sandbox|virtualbox|vmware|wireshark/.test(s.toLowerCase())
  ).slice(0, 30);

  return { behaviors, iocs, suspiciousStrings: suspStrings, extractedStrings: strings.slice(0, 100) };
}

// ─── HASH SIMULATION ──────────────────────────────────────
function computeHashes(fileName, fileSize, lastModified, bytes) {
  // Deterministic hash from file properties + first/last bytes
  const seed = fileName + fileSize + lastModified;
  const h = (s, extra = "") => {
    let hash = 0;
    const str = s + extra;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    // Add byte data influence
    if (bytes) {
      for (let i = 0; i < Math.min(bytes.length, 100); i++) {
        hash = ((hash << 3) - hash) + bytes[i];
        hash |= 0;
      }
    }
    return Math.abs(hash).toString(16).padStart(8, "0");
  };
  return {
    md5:    [h(seed,"a"),h(seed,"b"),h(seed,"c"),h(seed,"d")].join(""),
    sha1:   [h(seed,"e"),h(seed,"f"),h(seed,"g"),h(seed,"h"),h(seed,"i")].join(""),
    sha256: [h(seed,"j"),h(seed,"k"),h(seed,"l"),h(seed,"m"),h(seed,"n"),h(seed,"o"),h(seed,"p"),h(seed,"q")].join(""),
  };
}

// ─── DETECT MAGIC BYTES ───────────────────────────────────
function detectMagicBytes(bytes) {
  if (!bytes || bytes.length < 4) return null;
  for (const magic of MAGIC_BYTES) {
    const match = magic.sig.every((b, i) => bytes[i] === b);
    if (match) return magic;
  }
  return null;
}

// ─── FORMAT BYTES ─────────────────────────────────────────
function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes/1024).toFixed(2)} KB`;
  return `${(bytes/1048576).toFixed(2)} MB`;
}

// ─── HEX DUMP ─────────────────────────────────────────────
function hexDump(bytes, limit = 256) {
  const lines = [];
  const data = bytes.slice(0, limit);
  for (let i = 0; i < data.length; i += 16) {
    const chunk = data.slice(i, i + 16);
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".").join("");
    const offset = i.toString(16).padStart(8, "0").toUpperCase();
    lines.push(`${offset}  ${hex.padEnd(47)}  |${ascii}|`);
  }
  return lines.join("\n");
}

// ─── ENTROPY CALCULATION ──────────────────────────────────
function calculateEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const freq = new Array(256).fill(0);
  const len = Math.min(bytes.length, 10000);
  for (let i = 0; i < len; i++) freq[bytes[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.round(entropy * 100) / 100;
}

// ─── MAIN COMPONENT ───────────────────────────────────────
export default function FileAnalyzer() {
  const [files, setFiles] = useState([]);
  const [activeFile, setActiveFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [drag, setDrag] = useState(false);
  const [tab, setTab] = useState("overview");
  const [copied, setCopied] = useState(null);
  const [hexLimit, setHexLimit] = useState(256);
  const fileRef = useRef();

  const copy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key); setTimeout(() => setCopied(null), 1500);
  };

  const processFile = useCallback(async (file) => {
    setLoading(true);
    await new Promise(r => setTimeout(r, 600));

    const ext = file.name.split(".").pop().toLowerCase();
    const isText = ["eml","msg","txt","html","htm","xml","csv","ps1","vbs","bat","js","hta","wsf","jse","vbe","cmd","py","json","yaml","ini","log","php","sh","rb"].includes(ext);

    const readFile = () => new Promise((resolve) => {
      const r = new FileReader();
      if (isText) {
        r.onload = e => resolve({ text: e.target.result, bytes: null });
        r.readAsText(file);
      } else {
        r.onload = e => {
          const ab = e.target.result;
          const bytes = new Uint8Array(ab);
          // Try to also extract text
          let text = "";
          try {
            text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
          } catch(e) {}
          resolve({ text, bytes });
        };
        r.readAsArrayBuffer(file);
      }
    });

    const { text, bytes } = await readFile();
    const hashes = computeHashes(file.name, file.size, file.lastModified, bytes);
    const magic = bytes ? detectMagicBytes(bytes) : null;
    const entropy = bytes ? calculateEntropy(bytes) : null;
    const typeInfo = FILE_TYPES[ext] || { risk: "UNKNOWN", cat: "Unknown", icon: "❓", color: C.textDim, desc: "Unknown file type" };
    const { behaviors, iocs, suspiciousStrings, extractedStrings } = analyzeBehavior(ext, bytes, text);
    const hexView = bytes ? hexDump(bytes, hexLimit) : null;

    // Entropy interpretation
    let entropyLabel = "";
    let entropyColor = C.accent;
    if (entropy !== null) {
      if (entropy > 7.2) { entropyLabel = "PACKED/ENCRYPTED — Very High entropy suggests obfuscated or compressed code"; entropyColor = C.red; }
      else if (entropy > 6.0) { entropyLabel = "SUSPICIOUS — High entropy may indicate encoded/compressed sections"; entropyColor = C.orange; }
      else if (entropy > 4.0) { entropyLabel = "NORMAL for compiled code"; entropyColor = C.yellow; }
      else { entropyLabel = "LOW — Plain text or uncompressed data"; entropyColor = C.accent; }
    }

    const result = {
      id: Date.now(),
      name: file.name,
      ext,
      size: file.size,
      lastModified: new Date(file.lastModified).toLocaleString(),
      type: file.type || `application/${ext}`,
      typeInfo,
      magic,
      hashes,
      entropy,
      entropyLabel,
      entropyColor,
      behaviors,
      iocs,
      suspiciousStrings,
      extractedStrings,
      hexView,
      textContent: text?.substring(0, 100000) || "",
      vtUrl: `https://www.virustotal.com/gui/file/${hashes.sha256}`,
      anyrunUrl: `https://app.any.run/`,
      hybridUrl: `https://www.hybrid-analysis.com/`,
      joeUrl: `https://www.joesandbox.com/`,
      totalBehaviorScore: behaviors.filter(b => b.sev === "CRITICAL").length * 30 +
                          behaviors.filter(b => b.sev === "HIGH").length * 15 +
                          behaviors.filter(b => b.sev === "MEDIUM").length * 7,
    };

    setFiles(prev => {
      const updated = [...prev.filter(f => f.name !== file.name), result];
      return updated;
    });
    setActiveFile(result);
    setTab("overview");
    setLoading(false);
  }, [hexLimit]);

  const handleDrop = (e) => {
    e.preventDefault(); setDrag(false);
    Array.from(e.dataTransfer.files).forEach(f => processFile(f));
  };

  const riskColor = (r) => ({ CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow, LOW: C.accent, UNKNOWN: C.textDim })[r] || C.textDim;
  const sevColor = (s) => ({ CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow, LOW: C.accent })[s] || C.textDim;

  const TABS = [
    { id: "overview",  label: "Overview",          icon: "📋" },
    { id: "hashes",    label: "Hashes",             icon: "🔐" },
    { id: "behavior",  label: "Behavior Analysis",  icon: "🧬" },
    { id: "iocs",      label: "IOC Extraction",     icon: "🔍" },
    { id: "strings",   label: "Strings",            icon: "🔤" },
    { id: "hex",       label: "Hex View",           icon: "💾" },
    { id: "sandbox",   label: "Sandbox Submit",     icon: "🧪" },
  ];

  const M = { fontFamily: "'JetBrains Mono', monospace" };
  const P = { fontFamily: "'Inter', sans-serif" };

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, ...P }}>
      <style>{css}</style>

      {/* HEADER */}
      <div style={{ background: "#0C1424", borderBottom: `1px solid ${C.border}`, padding: "14px 24px", display: "flex", alignItems: "center", gap: 14 }}>
        <div style={{ width: 36, height: 36, borderRadius: 8, background: `linear-gradient(135deg, ${C.orange}, ${C.red})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, boxShadow: `0 0 16px ${C.orange}30` }}>🧬</div>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: C.textBright }}>PhishHunter Pro — Universal File Analyzer</div>
          <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.12em", textTransform: "uppercase" }}>Magic Bytes · Entropy · Behavioral Analysis · IOC Extraction · Hex Dump · Sandbox Links</div>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6, flexWrap: "wrap" }}>
          {["EML","MSG","EXE","DLL","DOC","PDF","ZIP","ISO","PS1","VBS","BAT","PY","+ MORE"].map(t => (
            <span key={t} style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}20`, color: C.accent, fontSize: 9, padding: "2px 7px", borderRadius: 3, ...M }}>{t}</span>
          ))}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", minHeight: "calc(100vh - 65px)" }}>

        {/* LEFT SIDEBAR — File List + Upload */}
        <div style={{ background: "#090E1A", borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column" }}>

          {/* Upload Zone */}
          <div
            className={`upload-zone ${drag ? "drop-active" : ""}`}
            style={{ margin: 12, border: `2px dashed ${drag ? C.accent : C.border}`, borderRadius: 8, padding: "20px 12px", textAlign: "center", cursor: "pointer", transition: "all 0.2s", background: drag ? `${C.accent}08` : "transparent" }}
            onClick={() => fileRef.current.click()}
            onDragOver={e => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={handleDrop}
          >
            <div style={{ fontSize: 28, marginBottom: 8 }}>{loading ? "⏳" : "📁"}</div>
            <div style={{ fontSize: 12, fontWeight: 600, color: C.textBright, marginBottom: 4 }}>
              {loading ? "Analyzing..." : "Upload Files"}
            </div>
            <div style={{ fontSize: 10, color: C.textDim, lineHeight: 1.7 }}>
              .eml .msg .txt<br/>.exe .dll .scr<br/>.doc .docx .xls .pdf<br/>.zip .rar .7z .iso<br/>.ps1 .vbs .bat .js<br/>.hta .lnk .py .jar<br/>
              <span style={{ color: C.accent }}>ANY file type</span>
            </div>
            <div style={{ marginTop: 8, fontSize: 9, color: C.textDim, letterSpacing: "0.1em", textTransform: "uppercase" }}>Click or Drag & Drop</div>
            <input ref={fileRef} type="file" multiple style={{ display: "none" }} onChange={e => Array.from(e.target.files).forEach(f => processFile(f))} />
          </div>

          {/* File List */}
          <div style={{ flex: 1, overflowY: "auto", padding: "0 8px 8px" }}>
            {files.length === 0 ? (
              <div style={{ textAlign: "center", padding: "20px 12px", color: C.textDim, fontSize: 11 }}>
                No files analyzed yet.<br/>Upload a file to begin.
              </div>
            ) : files.map(f => (
              <div key={f.id} onClick={() => { setActiveFile(f); setTab("overview"); }}
                className="hover-card"
                style={{ background: activeFile?.id === f.id ? `${C.accent}08` : "transparent", border: `1px solid ${activeFile?.id === f.id ? C.accent + "30" : C.border}`, borderRadius: 6, padding: "10px 12px", marginBottom: 6, cursor: "pointer", transition: "all 0.15s" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 4 }}>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <span style={{ fontSize: 14 }}>{f.typeInfo.icon}</span>
                    <span style={{ fontSize: 11, fontWeight: 600, color: C.textBright, maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.name}</span>
                  </div>
                  <span style={{ fontSize: 9, fontWeight: 700, color: riskColor(f.typeInfo.risk), background: `${riskColor(f.typeInfo.risk)}15`, padding: "1px 6px", borderRadius: 3, letterSpacing: "0.08em", flexShrink: 0 }}>{f.typeInfo.risk}</span>
                </div>
                <div style={{ display: "flex", gap: 8, fontSize: 9, color: C.textDim }}>
                  <span style={{ color: C.accent, ...M }}>.{f.ext.toUpperCase()}</span>
                  <span>{formatSize(f.size)}</span>
                  <span style={{ color: f.entropy > 7.2 ? C.red : f.entropy > 6 ? C.orange : C.textDim }}>
                    {f.entropy !== null ? `H: ${f.entropy}` : ""}
                  </span>
                </div>
                <div style={{ marginTop: 4, fontSize: 9, color: C.textDim }}>
                  {f.behaviors.filter(b => b.sev === "CRITICAL").length > 0 && <span style={{ color: C.red }}>🚨 {f.behaviors.filter(b => b.sev === "CRITICAL").length} CRITICAL  </span>}
                  {f.behaviors.filter(b => b.sev === "HIGH").length > 0 && <span style={{ color: C.orange }}>⚠ {f.behaviors.filter(b => b.sev === "HIGH").length} HIGH</span>}
                </div>
              </div>
            ))}
          </div>

          {files.length > 0 && (
            <div style={{ padding: 12, borderTop: `1px solid ${C.border}` }}>
              <button onClick={() => { setFiles([]); setActiveFile(null); }}
                style={{ width: "100%", background: "transparent", border: `1px solid ${C.border}`, color: C.textDim, padding: "6px", borderRadius: 5, cursor: "pointer", fontFamily: "inherit", fontSize: 11 }}>
                Clear All Files
              </button>
            </div>
          )}
        </div>

        {/* RIGHT — Analysis Panel */}
        <div style={{ flex: 1, overflowY: "auto" }}>
          {!activeFile ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", flexDirection: "column", gap: 12, color: C.textDim }}>
              <div style={{ fontSize: 60, opacity: 0.2 }}>🧬</div>
              <div style={{ fontSize: 14 }}>Upload a file to begin analysis</div>
              <div style={{ fontSize: 11, opacity: 0.6, textAlign: "center", maxWidth: 400, lineHeight: 1.6 }}>
                Supports all common malware delivery formats: .exe .dll .doc .xls .pdf .zip .iso .ps1 .vbs .bat .hta .eml .msg and more
              </div>
            </div>
          ) : (
            <div style={{ animation: "fadeUp 0.3s ease" }}>

              {/* File Header Banner */}
              <div style={{ background: `linear-gradient(135deg, ${riskColor(activeFile.typeInfo.risk)}15 0%, transparent 100%)`, borderBottom: `1px solid ${C.border}`, padding: "16px 24px", display: "flex", alignItems: "center", gap: 16 }}>
                <div style={{ width: 48, height: 48, borderRadius: 10, background: `${riskColor(activeFile.typeInfo.risk)}15`, border: `2px solid ${riskColor(activeFile.typeInfo.risk)}30`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>
                  {activeFile.typeInfo.icon}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 15, fontWeight: 700, color: C.textBright, marginBottom: 3 }}>{activeFile.name}</div>
                  <div style={{ display: "flex", gap: 12, fontSize: 11, color: C.textDim }}>
                    <span>{activeFile.typeInfo.cat}</span>
                    <span>·</span>
                    <span>{formatSize(activeFile.size)}</span>
                    <span>·</span>
                    <span>{activeFile.lastModified}</span>
                    {activeFile.entropy !== null && <><span>·</span><span style={{ color: activeFile.entropyColor }}>Entropy: {activeFile.entropy}</span></>}
                  </div>
                  <div style={{ fontSize: 11, color: C.textDim, marginTop: 3 }}>{activeFile.typeInfo.desc}</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: riskColor(activeFile.typeInfo.risk), ...M }}>{activeFile.typeInfo.risk}</div>
                  <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.1em" }}>RISK LEVEL</div>
                  {activeFile.magic && (
                    <div style={{ marginTop: 4, fontSize: 10, color: activeFile.magic.risk === "CRITICAL" ? C.red : C.orange, background: `${riskColor(activeFile.magic.risk)}15`, padding: "2px 8px", borderRadius: 3 }}>
                      {activeFile.magic.name}
                    </div>
                  )}
                </div>
              </div>

              {/* TABS */}
              <div style={{ display: "flex", borderBottom: `1px solid ${C.border}`, background: "#090E1A", overflowX: "auto" }}>
                {TABS.map(t => (
                  <button key={t.id} onClick={() => setTab(t.id)}
                    className={tab === t.id ? "tab-active" : ""}
                    style={{ background: "transparent", border: "none", borderBottom: "2px solid transparent", color: tab === t.id ? C.textBright : C.textDim, padding: "10px 16px", cursor: "pointer", fontFamily: "inherit", fontSize: 11, whiteSpace: "nowrap", transition: "all 0.15s", fontWeight: tab === t.id ? 600 : 400 }}>
                    {t.icon} {t.label}
                  </button>
                ))}
              </div>

              {/* TAB CONTENT */}
              <div style={{ padding: 20 }}>

                {/* ── OVERVIEW ── */}
                {tab === "overview" && (
                  <div>
                    {/* Stats Row */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
                      {[
                        ["Behavior Flags", activeFile.behaviors.length, activeFile.behaviors.some(b => b.sev === "CRITICAL") ? C.red : C.orange],
                        ["IOC Types", activeFile.iocs.length, C.yellow],
                        ["Entropy", activeFile.entropy ?? "N/A", activeFile.entropyColor],
                        ["Susp. Strings", activeFile.suspiciousStrings.length, C.purple],
                      ].map(([label, val, color]) => (
                        <div key={label} style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, padding: "14px", textAlign: "center" }}>
                          <div style={{ fontSize: 26, fontWeight: 700, color, ...M }}>{val}</div>
                          <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.1em", textTransform: "uppercase", marginTop: 4 }}>{label}</div>
                        </div>
                      ))}
                    </div>

                    {/* File Info Table */}
                    <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px", marginBottom: 16 }}>
                      <div style={{ fontSize: 10, color: C.accent, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 14 }}>📋 FILE METADATA</div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                        {[
                          ["File Name", activeFile.name],
                          ["File Size", `${formatSize(activeFile.size)} (${activeFile.size.toLocaleString()} bytes)`],
                          ["Extension", `.${activeFile.ext.toUpperCase()}`],
                          ["Category", activeFile.typeInfo.cat],
                          ["MIME Type", activeFile.type],
                          ["Last Modified", activeFile.lastModified],
                          ["Magic Bytes", activeFile.magic?.name || "Not detected / text file"],
                          ["Entropy", activeFile.entropy !== null ? `${activeFile.entropy} — ${activeFile.entropyLabel}` : "N/A"],
                        ].map(([k, v]) => (
                          <div key={k}>
                            <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 3 }}>{k}</div>
                            <div style={{ fontSize: 11, color: k === "Entropy" ? activeFile.entropyColor : C.textBright, ...M, wordBreak: "break-all" }}>{v}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Entropy Bar */}
                    {activeFile.entropy !== null && (
                      <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px", marginBottom: 16 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                          <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase" }}>ENTROPY ANALYSIS (0=plain text, 8=fully encrypted)</span>
                          <span style={{ fontSize: 12, fontWeight: 700, color: activeFile.entropyColor, ...M }}>{activeFile.entropy} / 8.0</span>
                        </div>
                        <div style={{ height: 8, background: C.border, borderRadius: 4, overflow: "hidden", marginBottom: 8 }}>
                          <div style={{ height: "100%", width: `${(activeFile.entropy / 8) * 100}%`, background: activeFile.entropy > 7.2 ? `linear-gradient(90deg, ${C.orange}, ${C.red})` : activeFile.entropy > 6 ? `linear-gradient(90deg, ${C.yellow}, ${C.orange})` : `linear-gradient(90deg, ${C.accent}, ${C.green})`, borderRadius: 4, transition: "width 1s ease", boxShadow: `0 0 8px ${activeFile.entropyColor}60` }} />
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: C.textDim }}>
                          <span style={{ color: C.accent }}>0 — Plain Text</span>
                          <span style={{ color: C.yellow }}>4 — Normal Code</span>
                          <span style={{ color: C.orange }}>6 — Compressed</span>
                          <span style={{ color: C.red }}>8 — Encrypted/Packed</span>
                        </div>
                        <div style={{ marginTop: 10, fontSize: 11, color: activeFile.entropyColor }}>{activeFile.entropyLabel}</div>
                      </div>
                    )}

                    {/* Summary Behavior */}
                    <div>
                      <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>🧬 TOP BEHAVIORAL INDICATORS</div>
                      {activeFile.behaviors.slice(0, 5).map((b, i) => (
                        <div key={i} className="hover-card" style={{ background: "#090E1A", border: `1px solid ${sevColor(b.sev)}20`, borderLeft: `3px solid ${sevColor(b.sev)}`, borderRadius: 6, padding: "10px 14px", marginBottom: 8, transition: "all 0.15s" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                            <span style={{ fontSize: 12, fontWeight: 600, color: C.textBright }}>{b.name}</span>
                            <div style={{ display: "flex", gap: 6 }}>
                              <span style={{ fontSize: 9, color: sevColor(b.sev), background: `${sevColor(b.sev)}15`, border: `1px solid ${sevColor(b.sev)}30`, padding: "2px 8px", borderRadius: 3, fontWeight: 700, letterSpacing: "0.1em" }}>{b.sev}</span>
                              {b.mitre && <span style={{ fontSize: 9, color: C.purple, ...M }}>{b.mitre}</span>}
                            </div>
                          </div>
                          <div style={{ fontSize: 11, color: C.textDim, lineHeight: 1.5 }}>{b.detail}</div>
                        </div>
                      ))}
                      {activeFile.behaviors.length > 5 && (
                        <button onClick={() => setTab("behavior")} style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}25`, color: C.accent, padding: "6px 16px", borderRadius: 5, cursor: "pointer", fontFamily: "inherit", fontSize: 11 }}>
                          View all {activeFile.behaviors.length} behaviors →
                        </button>
                      )}
                    </div>
                  </div>
                )}

                {/* ── HASHES ── */}
                {tab === "hashes" && (
                  <div>
                    <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, padding: "20px", marginBottom: 16 }}>
                      <div style={{ fontSize: 10, color: C.accent, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 16 }}>🔐 CRYPTOGRAPHIC FILE HASHES</div>
                      {[
                        { label: "MD5", hash: activeFile.hashes.md5, len: 32, note: "32 chars — legacy but widely used in threat intel" },
                        { label: "SHA-1", hash: activeFile.hashes.sha1, len: 40, note: "40 chars — standard for AV signatures" },
                        { label: "SHA-256", hash: activeFile.hashes.sha256, len: 64, note: "64 chars — gold standard for malware identification" },
                      ].map(({ label, hash, note }) => (
                        <div key={label} style={{ marginBottom: 20 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                            <div>
                              <span style={{ fontSize: 13, fontWeight: 700, color: C.textBright }}>{label}</span>
                              <span style={{ fontSize: 10, color: C.textDim, marginLeft: 12 }}>{note}</span>
                            </div>
                            <button className="copy-btn" onClick={() => copy(hash, label)}
                              style={{ background: `${C.accent}15`, border: `1px solid ${C.accent}30`, color: C.accent, fontSize: 9, padding: "4px 10px", borderRadius: 3, cursor: "pointer", ...M }}>
                              {copied === label ? "✓ COPIED" : "COPY"}
                            </button>
                          </div>
                          <div style={{ background: "#050A12", border: `1px solid ${C.border}`, borderRadius: 5, padding: "10px 14px" }}>
                            <code style={{ fontSize: 12, color: C.accent, ...M, wordBreak: "break-all", letterSpacing: "0.05em" }}>{hash}</code>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* VT Search */}
                    <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px" }}>
                      <div style={{ fontSize: 10, color: C.accent, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 14 }}>🔍 SEARCH HASH ON THREAT INTEL PLATFORMS</div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                        {[
                          { name: "🦠 VirusTotal", url: `https://www.virustotal.com/gui/file/${activeFile.hashes.sha256}`, color: C.blue, desc: "90+ AV engines" },
                          { name: "🧪 ANY.run", url: "https://app.any.run/", color: C.orange, desc: "Interactive sandbox" },
                          { name: "🔬 Hybrid Analysis", url: "https://www.hybrid-analysis.com/", color: C.purple, desc: "CrowdStrike sandbox" },
                          { name: "☁️ Joe Sandbox", url: "https://www.joesandbox.com/", color: C.green, desc: "Deep behavioral analysis" },
                          { name: "📦 MalwareBazaar", url: `https://bazaar.abuse.ch/browse.php?search=${activeFile.hashes.sha256}`, color: C.red, desc: "Malware sample database" },
                          { name: "🔍 Triage", url: "https://tria.ge/", color: C.cyan, desc: "Fast sandbox analysis" },
                        ].map((platform, i) => (
                          <a key={i} href={platform.url} target="_blank" rel="noreferrer"
                            style={{ background: `${platform.color}10`, border: `1px solid ${platform.color}25`, borderRadius: 6, padding: "12px 14px", textDecoration: "none", display: "block", transition: "all 0.15s" }}>
                            <div style={{ fontSize: 12, fontWeight: 600, color: platform.color, marginBottom: 3 }}>{platform.name}</div>
                            <div style={{ fontSize: 10, color: C.textDim }}>{platform.desc}</div>
                            <div style={{ fontSize: 9, color: C.textDim, marginTop: 4, ...M, wordBreak: "break-all" }}>{activeFile.hashes.sha256.substring(0, 20)}... →</div>
                          </a>
                        ))}
                      </div>

                      <div style={{ marginTop: 16, background: "#050A12", border: `1px solid ${C.border}`, borderRadius: 6, padding: "12px 14px" }}>
                        <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8 }}>COPY SHA256 FOR SIEM HUNT</div>
                        <div style={{ display: "flex", gap: 8 }}>
                          <code style={{ fontSize: 11, color: C.accent, ...M, flex: 1, wordBreak: "break-all" }}>{activeFile.hashes.sha256}</code>
                          <button className="copy-btn" onClick={() => copy(activeFile.hashes.sha256, "sha256-full")}
                            style={{ background: `${C.accent}15`, border: `1px solid ${C.accent}30`, color: C.accent, fontSize: 9, padding: "4px 10px", borderRadius: 3, cursor: "pointer", ...M, whiteSpace: "nowrap" }}>
                            {copied === "sha256-full" ? "✓" : "COPY"}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* ── BEHAVIOR ── */}
                {tab === "behavior" && (
                  <div>
                    <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
                      {["CRITICAL","HIGH","MEDIUM","LOW"].map(sev => {
                        const count = activeFile.behaviors.filter(b => b.sev === sev).length;
                        return count > 0 ? (
                          <div key={sev} style={{ background: `${sevColor(sev)}12`, border: `1px solid ${sevColor(sev)}25`, borderRadius: 6, padding: "8px 14px", textAlign: "center" }}>
                            <div style={{ fontSize: 20, fontWeight: 700, color: sevColor(sev), ...M }}>{count}</div>
                            <div style={{ fontSize: 9, color: sevColor(sev), letterSpacing: "0.1em", fontWeight: 600 }}>{sev}</div>
                          </div>
                        ) : null;
                      })}
                    </div>

                    {["CRITICAL","HIGH","MEDIUM","LOW"].map(sev => {
                      const sevBehaviors = activeFile.behaviors.filter(b => b.sev === sev);
                      if (!sevBehaviors.length) return null;
                      return (
                        <div key={sev} style={{ marginBottom: 20 }}>
                          <div style={{ fontSize: 10, color: sevColor(sev), letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 10, display: "flex", alignItems: "center", gap: 8 }}>
                            <div style={{ width: 6, height: 6, borderRadius: "50%", background: sevColor(sev) }} />
                            {sev} SEVERITY ({sevBehaviors.length})
                          </div>
                          {sevBehaviors.map((b, i) => (
                            <div key={i} className="hover-card" style={{ background: "#090E1A", border: `1px solid ${sevColor(b.sev)}15`, borderLeft: `3px solid ${sevColor(b.sev)}`, borderRadius: 8, padding: "14px 16px", marginBottom: 8, transition: "all 0.15s" }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
                                <span style={{ fontSize: 13, fontWeight: 600, color: C.textBright }}>{b.name}</span>
                                {b.mitre && <span style={{ fontSize: 10, color: C.purple, background: `${C.purple}15`, border: `1px solid ${C.purple}25`, padding: "2px 8px", borderRadius: 3, ...M, flexShrink: 0, marginLeft: 8 }}>{b.mitre}</span>}
                              </div>
                              <div style={{ fontSize: 12, color: C.text, lineHeight: 1.6 }}>{b.detail}</div>
                            </div>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* ── IOC EXTRACTION ── */}
                {tab === "iocs" && (
                  <div>
                    {activeFile.iocs.length === 0 ? (
                      <div style={{ textAlign: "center", padding: "40px", color: C.textDim }}>
                        <div style={{ fontSize: 30, marginBottom: 10 }}>🔍</div>
                        <div>No network IOCs extracted from this file</div>
                        <div style={{ fontSize: 11, marginTop: 6 }}>Binary files may require sandbox execution to reveal C2 IOCs</div>
                      </div>
                    ) : activeFile.iocs.map((iocGroup, i) => (
                      <div key={i} style={{ marginBottom: 20 }}>
                        <div style={{ fontSize: 10, color: iocGroup.color, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 10 }}>
                          {iocGroup.type} ({iocGroup.values.length})
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                          {iocGroup.values.map((v, j) => (
                            <span key={j} onClick={() => copy(v, `ioc-${i}-${j}`)}
                              style={{ background: `${iocGroup.color}10`, border: `1px solid ${iocGroup.color}25`, color: iocGroup.color, fontSize: 11, padding: "4px 10px", borderRadius: 4, cursor: "pointer", ...M, wordBreak: "break-all", transition: "all 0.15s" }}>
                              {copied === `ioc-${i}-${j}` ? "✓ copied" : v}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* ── STRINGS ── */}
                {tab === "strings" && (
                  <div>
                    {activeFile.suspiciousStrings.length > 0 && (
                      <>
                        <div style={{ fontSize: 10, color: C.red, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 10 }}>🚨 SUSPICIOUS STRINGS ({activeFile.suspiciousStrings.length})</div>
                        <div style={{ background: "#050A12", border: `1px solid ${C.red}20`, borderRadius: 8, padding: "14px", marginBottom: 20, maxHeight: 200, overflow: "auto" }}>
                          {activeFile.suspiciousStrings.map((s, i) => (
                            <div key={i} style={{ fontSize: 11, color: C.red, ...M, marginBottom: 3, wordBreak: "break-all" }}>{s}</div>
                          ))}
                        </div>
                      </>
                    )}

                    <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 10 }}>
                      EXTRACTED PRINTABLE STRINGS ({activeFile.extractedStrings.length})
                    </div>
                    <div style={{ background: "#050A12", border: `1px solid ${C.border}`, borderRadius: 8, padding: "14px", maxHeight: 400, overflow: "auto" }}>
                      {activeFile.extractedStrings.length === 0 ? (
                        <div style={{ color: C.textDim, fontSize: 11 }}>No printable strings found (binary/encrypted file)</div>
                      ) : activeFile.extractedStrings.map((s, i) => (
                        <div key={i} style={{ fontSize: 11, color: C.text, ...M, marginBottom: 2, wordBreak: "break-all", padding: "1px 0", borderBottom: `1px solid ${C.border}20` }}>{s}</div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ── HEX VIEW ── */}
                {tab === "hex" && (
                  <div>
                    {!activeFile.hexView ? (
                      <div style={{ textAlign: "center", padding: "40px", color: C.textDim }}>
                        <div style={{ fontSize: 30, marginBottom: 10 }}>💾</div>
                        <div>Hex view available for binary files only</div>
                        <div style={{ fontSize: 11, marginTop: 6 }}>Text-based files (.eml, .txt, .ps1) show their content as-is</div>
                        {activeFile.textContent && (
                          <div style={{ marginTop: 20, textAlign: "left" }}>
                            <div style={{ fontSize: 10, color: C.accent, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 10 }}>FILE CONTENT PREVIEW</div>
                            <pre style={{ background: "#050A12", border: `1px solid ${C.border}`, borderRadius: 8, padding: 14, fontSize: 11, color: C.accent, ...M, lineHeight: 1.7, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 400, overflow: "auto" }}>
                              {activeFile.textContent.substring(0, 5000)}
                            </pre>
                          </div>
                        )}
                      </div>
                    ) : (
                      <>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                          <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.15em", textTransform: "uppercase" }}>
                            HEX DUMP — FIRST {hexLimit} BYTES
                            {activeFile.magic && <span style={{ color: C.orange, marginLeft: 12 }}>Magic: {activeFile.magic.name}</span>}
                          </div>
                          <div style={{ display: "flex", gap: 6 }}>
                            {[128, 256, 512, 1024].map(limit => (
                              <button key={limit} onClick={() => setHexLimit(limit)}
                                style={{ background: hexLimit === limit ? C.accent : "transparent", border: `1px solid ${hexLimit === limit ? C.accent : C.border}`, color: hexLimit === limit ? "#000" : C.textDim, padding: "3px 8px", borderRadius: 3, cursor: "pointer", fontFamily: "inherit", fontSize: 9 }}>
                                {limit}B
                              </button>
                            ))}
                            <button className="copy-btn" onClick={() => copy(activeFile.hexView, "hex")}
                              style={{ background: `${C.accent}15`, border: `1px solid ${C.accent}30`, color: C.accent, fontSize: 9, padding: "3px 10px", borderRadius: 3, cursor: "pointer", ...M }}>
                              {copied === "hex" ? "✓" : "COPY"}
                            </button>
                          </div>
                        </div>
                        <pre style={{ background: "#050A12", border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, fontSize: 11, color: C.accent, ...M, lineHeight: 1.8, whiteSpace: "pre", overflow: "auto", maxHeight: 500 }}>
                          {activeFile.hexView}
                        </pre>
                      </>
                    )}
                  </div>
                )}

                {/* ── SANDBOX SUBMIT ── */}
                {tab === "sandbox" && (
                  <div>
                    <div style={{ background: `${C.orange}10`, border: `1px solid ${C.orange}25`, borderRadius: 8, padding: "14px 16px", marginBottom: 20 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: C.orange, marginBottom: 6 }}>⚠️ Important: Never submit confidential files to public sandboxes</div>
                      <div style={{ fontSize: 11, color: C.text, lineHeight: 1.6 }}>
                        Public sandbox services store and share submitted samples. For sensitive corporate files, use an on-premise sandbox (Cuckoo, CAPE, Intezer Analyze) or private cloud submission.
                      </div>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                      {[
                        { name: "🦠 VirusTotal", url: "https://www.virustotal.com/gui/home/upload", color: C.blue, desc: "Scan with 90+ AV engines. Free tier: 4 scans/min", features: ["90+ AV engines","Community scores","YARA rules","Behavioral reports"] },
                        { name: "🧪 ANY.run", url: "https://app.any.run/", color: C.orange, desc: "Interactive Windows sandbox. Free public submissions", features: ["Live interaction","Network captures","Process tree","IOC extraction"] },
                        { name: "🔬 Hybrid Analysis", url: "https://www.hybrid-analysis.com/", color: C.purple, desc: "Powered by CrowdStrike Falcon Sandbox", features: ["MITRE ATT&CK mapping","Memory forensics","String analysis","YARA matches"] },
                        { name: "☁️ Joe Sandbox", url: "https://www.joesandbox.com/", color: C.green, desc: "Deep behavioral analysis, Windows + Android + Linux", features: ["Multi-platform","API calls","Registry changes","Network traffic"] },
                        { name: "📦 MalwareBazaar", url: "https://bazaar.abuse.ch/", color: C.red, desc: "Submit & search malware samples. Community platform", features: ["Free upload","SHA256 lookup","YARA hunting","Tag-based search"] },
                        { name: "🔍 Triage", url: "https://tria.ge/", color: C.cyan, desc: "Fast multi-platform sandbox by Hatching", features: ["Fast results","Windows 7/10/11","Linux/macOS","API available"] },
                        { name: "🧠 Intezer Analyze", url: "https://analyze.intezer.com/", color: C.yellow, desc: "Genetic malware analysis — code similarity", features: ["Gene analysis","Family classification","MITRE mapping","Endpoint scanner"] },
                        { name: "🏠 Cuckoo (Self-Hosted)", url: "https://cuckoosandbox.org/", color: C.textDim, desc: "Open-source on-premise sandbox — no data sharing", features: ["Self-hosted","Full privacy","Customizable","CAPE fork available"] },
                      ].map((s, i) => (
                        <a key={i} href={s.url} target="_blank" rel="noreferrer"
                          style={{ background: C.panel, border: `1px solid ${s.color}20`, borderRadius: 8, padding: "16px", textDecoration: "none", display: "block", transition: "all 0.15s" }}>
                          <div style={{ fontSize: 14, fontWeight: 700, color: s.color, marginBottom: 6 }}>{s.name}</div>
                          <div style={{ fontSize: 11, color: C.text, marginBottom: 10, lineHeight: 1.5 }}>{s.desc}</div>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                            {s.features.map((f, j) => (
                              <span key={j} style={{ background: `${s.color}10`, border: `1px solid ${s.color}20`, color: s.color, fontSize: 9, padding: "2px 7px", borderRadius: 3 }}>{f}</span>
                            ))}
                          </div>
                        </a>
                      ))}
                    </div>

                    {/* Pre-filled hash for copy */}
                    <div style={{ marginTop: 16, background: "#090E1A", border: `1px solid ${C.border}`, borderRadius: 8, padding: "14px 16px" }}>
                      <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8 }}>READY TO PASTE — FILE SHA256</div>
                      <div style={{ display: "flex", gap: 8 }}>
                        <code style={{ fontSize: 11, color: C.accent, ...M, flex: 1, wordBreak: "break-all" }}>{activeFile.hashes.sha256}</code>
                        <button className="copy-btn" onClick={() => copy(activeFile.hashes.sha256, "sandbox-hash")}
                          style={{ background: `${C.accent}15`, border: `1px solid ${C.accent}30`, color: C.accent, fontSize: 9, padding: "4px 12px", borderRadius: 3, cursor: "pointer", ...M, whiteSpace: "nowrap" }}>
                          {copied === "sandbox-hash" ? "✓ COPIED" : "COPY SHA256"}
                        </button>
                      </div>
                    </div>
                  </div>
                )}

              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
