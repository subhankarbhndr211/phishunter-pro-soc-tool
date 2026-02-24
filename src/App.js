import { useState } from "react";
import PhishingAnalyzer from './components/PhishingAnalyzer';
import FileAnalyzer from './components/FileAnalyzer';

export default function App() {
  const [activeTool, setActiveTool] = useState("phishing");

  const tools = [
    {
      id: "phishing",
      label: "PhishHunter Pro v2",
      icon: "🎣",
      desc: "Email IOC Analyzer · C2 Detection · Attack Chain",
      color: "#00E5FF",
    },
    {
      id: "fileanalyzer",
      label: "File Analyzer",
      icon: "🧬",
      desc: "Universal File Analysis · Hex Dump · Entropy · Behavioral",
      color: "#FF8C00",
    },
  ];

  return (
    <div style={{ minHeight: "100vh", background: "#070C18", fontFamily: "'Inter', sans-serif" }}>

      {/* TOP NAV BAR */}
      <div style={{
        background: "#0C1424",
        borderBottom: "1px solid #162035",
        padding: "0 24px",
        display: "flex",
        alignItems: "center",
        gap: 0,
        position: "sticky",
        top: 0,
        zIndex: 1000,
      }}>

        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "12px 0", marginRight: 32 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: "linear-gradient(135deg, #00E5FF, #B44FFF)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 16, boxShadow: "0 0 12px #00E5FF30"
          }}>🛡</div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#EEF4FF", lineHeight: 1 }}>SOC Toolkit</div>
            <div style={{ fontSize: 9, color: "#3D5070", letterSpacing: "0.12em", textTransform: "uppercase" }}>by Subhankar Bhandari</div>
          </div>
        </div>

        {/* Tool Tabs */}
        {tools.map(tool => (
          <button
            key={tool.id}
            onClick={() => setActiveTool(tool.id)}
            style={{
              background: activeTool === tool.id ? `${tool.color}12` : "transparent",
              border: "none",
              borderBottom: activeTool === tool.id ? `2px solid ${tool.color}` : "2px solid transparent",
              color: activeTool === tool.id ? tool.color : "#3D5070",
              padding: "16px 20px",
              cursor: "pointer",
              fontFamily: "inherit",
              fontSize: 12,
              fontWeight: activeTool === tool.id ? 700 : 400,
              display: "flex",
              alignItems: "center",
              gap: 8,
              transition: "all 0.2s",
              whiteSpace: "nowrap",
            }}
          >
            <span style={{ fontSize: 16 }}>{tool.icon}</span>
            <div style={{ textAlign: "left" }}>
              <div>{tool.label}</div>
              <div style={{ fontSize: 9, color: activeTool === tool.id ? `${tool.color}80` : "#3D5070", fontWeight: 400, letterSpacing: "0.05em" }}>{tool.desc}</div>
            </div>
          </button>
        ))}

        {/* Right badges */}
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          {["TryHackMe Top 4%", "MS Learn Level 9", "ISC2 CC"].map(b => (
            <span key={b} style={{
              background: "#162035", border: "1px solid #1C2B4A",
              color: "#3D5070", fontSize: 9, padding: "3px 8px",
              borderRadius: 3, letterSpacing: "0.08em",
              fontFamily: "'JetBrains Mono', monospace"
            }}>{b}</span>
          ))}
        </div>
      </div>

      {/* TOOL CONTENT */}
      <div>
        {activeTool === "phishing" && <PhishingAnalyzer />}
        {activeTool === "fileanalyzer" && <FileAnalyzer />}
      </div>
    </div>
  );
}
