/**
 * Winnie-SOC: 47-Pattern Kill-Chain & MITRE ATT&CK Classification Engine
 * Analyzes raw incoming honeypot events (logins and executed commands)
 * and maps them to cybersecurity taxonomies, MITRE ATT&CK matrix, and botnet profiles.
 */

// 47 Attack Pattern Taxonomy Definitions
const PATTERNS_TAXONOMY = {
  // Category 1: Credential Brute Force & Authentication (P01 - P10)
  "P01": { id: "P01", category: "Credential Brute Force", name: "Default Root Login Attempt", severity: "HIGH", mitre: "T1078.001", tactic: "TA0001" },
  "P02": { id: "P02", category: "Credential Brute Force", name: "Admin Account Dictionary Attack", severity: "MEDIUM", mitre: "T1110.001", tactic: "TA0006" },
  "P03": { id: "P03", category: "Credential Brute Force", name: "Common IoT Hardcoded Credentials (admin/admin)", severity: "HIGH", mitre: "T1078.001", tactic: "TA0001" },
  "P04": { id: "P04", category: "Credential Brute Force", name: "Mirai Known Credential Match (root/xc3511)", severity: "CRITICAL", mitre: "T1110.001", tactic: "TA0006" },
  "P05": { id: "P05", category: "Credential Brute Force", name: "Gafgyt/Qbot Known Credential Match (root/vizxv)", severity: "CRITICAL", mitre: "T1110.001", tactic: "TA0006" },
  "P06": { id: "P06", category: "Credential Brute Force", name: "Empty / Null Password Probe", severity: "MEDIUM", mitre: "T1110.001", tactic: "TA0006" },
  "P07": { id: "P07", category: "Credential Brute Force", name: "High-Frequency Credential Spraying", severity: "HIGH", mitre: "T1110.003", tactic: "TA0006" },
  "P08": { id: "P08", category: "Credential Brute Force", name: "Telecom / Router Vendor Default Probe (support/support)", severity: "MEDIUM", mitre: "T1078.001", tactic: "TA0001" },
  "P09": { id: "P09", category: "Credential Brute Force", name: "Camera / DVR Appliance Default Probe (guest/guest)", severity: "MEDIUM", mitre: "T1078.001", tactic: "TA0001" },
  "P10": { id: "P10", category: "Credential Brute Force", name: "Anomalous Username Syntax Fuzzing", severity: "LOW", mitre: "T1110.001", tactic: "TA0006" },

  // Category 2: Reconnaissance & Environment Fingerprinting (P11 - P20)
  "P11": { id: "P11", category: "Reconnaissance", name: "Kernel & Architecture Fingerprinting (uname -a)", severity: "LOW", mitre: "T1082", tactic: "TA0007" },
  "P12": { id: "P12", category: "Reconnaissance", name: "Current Working Directory Discovery (pwd)", severity: "LOW", mitre: "T1083", tactic: "TA0007" },
  "P13": { id: "P13", category: "Reconnaissance", name: "Current User Privilege Inspection (whoami)", severity: "LOW", mitre: "T1033", tactic: "TA0007" },
  "P14": { id: "P14", category: "Reconnaissance", name: "Detailed Identity & Group Enumeration (id)", severity: "MEDIUM", mitre: "T1033", tactic: "TA0007" },
  "P15": { id: "P15", category: "Reconnaissance", name: "Root Filesystem Exploration (ls /)", severity: "LOW", mitre: "T1083", tactic: "TA0007" },
  "P16": { id: "P16", category: "Reconnaissance", name: "Root Home Directory Audit (ls /root)", severity: "MEDIUM", mitre: "T1083", tactic: "TA0007" },
  "P17": { id: "P17", category: "Reconnaissance", name: "Configuration Directory Audit (ls /etc)", severity: "MEDIUM", mitre: "T1083", tactic: "TA0007" },
  "P18": { id: "P18", category: "Reconnaissance", name: "Temporary Directory Staging Recon (ls /tmp)", severity: "MEDIUM", mitre: "T1083", tactic: "TA0007" },
  "P19": { id: "P19", category: "Reconnaissance", name: "Interactive Shell Capability Probe (help)", severity: "LOW", mitre: "T1059.004", tactic: "TA0002" },
  "P20": { id: "P20", category: "Reconnaissance", name: "Process & Service Inspection Probe (ps / top)", severity: "MEDIUM", mitre: "T1057", tactic: "TA0007" },

  // Category 3: Vulnerability Exploitation & Credential Harvesting (P21 - P30)
  "P21": { id: "P21", category: "Credential Harvesting", name: "Password File Exfiltration (/etc/passwd)", severity: "HIGH", mitre: "T1003.008", tactic: "TA0006" },
  "P22": { id: "P22", category: "Credential Harvesting", name: "Shadow File Hash Theft (/etc/shadow)", severity: "CRITICAL", mitre: "T1003.008", tactic: "TA0006" },
  "P23": { id: "P23", category: "Credential Harvesting", name: "SSH Private Key Hunt (.ssh/id_rsa)", severity: "CRITICAL", mitre: "T1552.004", tactic: "TA0006" },
  "P24": { id: "P24", category: "Credential Harvesting", name: "Command History Snooping (.bash_history)", severity: "HIGH", mitre: "T1552.003", tactic: "TA0009" },
  "P25": { id: "P25", category: "Exploitation", name: "BusyBox Shell Escape Probe", severity: "HIGH", mitre: "T1059.004", tactic: "TA0002" },
  "P26": { id: "P26", category: "Exploitation", name: "Router CGI Script Injection (/cgi-bin)", severity: "HIGH", mitre: "T1190", tactic: "TA0001" },
  "P27": { id: "P27", category: "Exploitation", name: "Network Interfaces Inspection (/etc/network)", severity: "MEDIUM", mitre: "T1016", tactic: "TA0007" },
  "P28": { id: "P28", category: "Exploitation", name: "Init Script & Daemon Enumeration (/etc/init.d)", severity: "MEDIUM", mitre: "T1082", tactic: "TA0007" },
  "P29": { id: "P29", category: "Exploitation", name: "System Log Snooping (/var/log)", severity: "MEDIUM", mitre: "T1005", tactic: "TA0009" },
  "P30": { id: "P30", category: "Exploitation", name: "Service Backup Archive Probing (/var/backups)", severity: "HIGH", mitre: "T1005", tactic: "TA0009" },

  // Category 4: Post-Exploitation, Staging & Malware Droppers (P31 - P40)
  "P31": { id: "P31", category: "Malware Staging", name: "Remote Payload Download via WGET", severity: "CRITICAL", mitre: "T1105", tactic: "TA0011" },
  "P32": { id: "P32", category: "Malware Staging", name: "Remote Dropper Fetch via CURL", severity: "CRITICAL", mitre: "T1105", tactic: "TA0011" },
  "P33": { id: "P33", category: "Malware Staging", name: "Malicious Shell Script Staging (.sh download)", severity: "CRITICAL", mitre: "T1105", tactic: "TA0011" },
  "P34": { id: "P34", category: "Malware Staging", name: "Binary Dropper Staging (bin/elf download)", severity: "CRITICAL", mitre: "T1105", tactic: "TA0011" },
  "P35": { id: "P35", category: "Persistence", name: "Backdoor File Creation (touch / echo)", severity: "MEDIUM", mitre: "T1059.004", tactic: "TA0002" },
  "P36": { id: "P36", category: "Persistence", name: "Hidden Staging Directory Creation (mkdir)", severity: "MEDIUM", mitre: "T1083", tactic: "TA0007" },
  "P37": { id: "P37", category: "Defense Evasion", name: "Indicator Removal / Artifact Deletion (rm)", severity: "HIGH", mitre: "T1070.004", tactic: "TA0005" },
  "P38": { id: "P38", category: "Defense Evasion", name: "Log Wiping Attempt (rm -rf /var/log)", severity: "CRITICAL", mitre: "T1070.002", tactic: "TA0005" },
  "P39": { id: "P39", category: "Execution", name: "Payload Execution via Direct Shell Piping (| sh)", severity: "CRITICAL", mitre: "T1059.004", tactic: "TA0002" },
  "P40": { id: "P40", category: "Execution", name: "Cron Scheduled Persistence Probe (/etc/cron)", severity: "HIGH", mitre: "T1053.003", tactic: "TA0003" },

  // Category 5: Botnet Signatures & Behavioral Anomalies (P41 - P47)
  "P41": { id: "P41", category: "Botnet Signature", name: "Mirai Botnet Automated Post-Auth Burst", severity: "CRITICAL", mitre: "T1587.001", tactic: "TA0002" },
  "P42": { id: "P42", category: "Botnet Signature", name: "Hajime P2P Worm Discovery Footprint", severity: "HIGH", mitre: "T1587.001", tactic: "TA0007" },
  "P43": { id: "P43", category: "Botnet Signature", name: "Mozi Botnet DHT Discovery Pattern", severity: "HIGH", mitre: "T1587.001", tactic: "TA0011" },
  "P44": { id: "P44", category: "Botnet Signature", name: "Gafgyt / Bashlite Architecture Recon Wave", severity: "CRITICAL", mitre: "T1587.001", tactic: "TA0007" },
  "P45": { id: "P45", category: "Behavioral Anomaly", name: "Hawkes Temporal Burst Rate Anomaly", severity: "HIGH", mitre: "T1046", tactic: "TA0043" },
  "P46": { id: "P46", category: "Behavioral Anomaly", name: "Out-of-Order Kill-Chain Leap (Fast Exploit)", severity: "MEDIUM", mitre: "T1190", tactic: "TA0001" },
  "P47": { id: "P47", category: "Behavioral Anomaly", name: "Multi-Session Distributed Reconnaissance", severity: "HIGH", mitre: "T1046", tactic: "TA0043" }
};

// MITRE ATT&CK Matrix Reference Tactics
const MITRE_TACTICS = {
  "TA0043": { id: "TA0043", name: "Reconnaissance" },
  "TA0001": { id: "TA0001", name: "Initial Access" },
  "TA0002": { id: "TA0002", name: "Execution" },
  "TA0003": { id: "TA0003", name: "Persistence" },
  "TA0005": { id: "TA0005", name: "Defense Evasion" },
  "TA0006": { id: "TA0006", name: "Credential Access" },
  "TA0007": { id: "TA0007", name: "Discovery" },
  "TA0009": { id: "TA0009", name: "Collection" },
  "TA0011": { id: "TA0011", name: "Command and Control" }
};

class AttackClassifier {
  constructor() {
    this.sessionHistory = new Map(); // sessionId -> array of events
    this.ipHistory = new Map();      // ip -> array of sessionIds
  }

  /**
   * Main classification method
   * @param {Object} rawEvent { ip, session, command, timestamp }
   * @returns {Object} enriched event
   */
  classify(rawEvent) {
    const timestamp = rawEvent.timestamp || new Date().toISOString();
    const command = (rawEvent.command || "").trim();
    const sessionId = rawEvent.session;
    const ip = rawEvent.ip;

    const matchedPatterns = [];
    let killChainStage = "1. Reconnaissance";
    let threatLevel = "LOW";
    let botnetAttribution = "Unknown Actor";
    let mitreTechniques = [];
    let isLogin = false;
    let authDetails = null;

    // Track sessions by IP for distributed multi-session recon (P47)
    if (!this.ipHistory.has(ip)) {
      this.ipHistory.set(ip, new Set());
    }
    const ipSessions = this.ipHistory.get(ip);
    ipSessions.add(sessionId);
    if (ipSessions.size > 1) {
      matchedPatterns.push(PATTERNS_TAXONOMY["P47"]);
    }

    // Track session command history for behavioral/sequence analysis
    if (!this.sessionHistory.has(sessionId)) {
      this.sessionHistory.set(sessionId, []);
    }
    const sessionEvents = this.sessionHistory.get(sessionId);

    // 1. Authentication / Login Detection (P01 - P10)
    if (command.startsWith("LOGIN:")) {
      isLogin = true;
      const credPart = command.replace("LOGIN:", "").trim();
      const parts = credPart.split("/").map(s => s.trim());
      const username = parts[0] || "unknown";
      const password = parts[1] || "";
      authDetails = { username, password };

      killChainStage = "2. Credential Access";
      threatLevel = "MEDIUM";

      // P01: Default Root Login
      if (username.toLowerCase() === "root") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P01"]);
        mitreTechniques.push({ id: "T1078.001", name: "Default Accounts: Root", tactic: "TA0001" });
      }
      // P02: Admin Dictionary
      if (username.toLowerCase() === "admin") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P02"]);
        mitreTechniques.push({ id: "T1110.001", name: "Password Guessing: Admin", tactic: "TA0006" });
      }
      // P03: IoT Hardcoded (admin/admin)
      if (username === "admin" && password === "admin") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P03"]);
        threatLevel = "HIGH";
        botnetAttribution = "Generic IoT Scanner";
        mitreTechniques.push({ id: "T1078.001", name: "Default Accounts", tactic: "TA0001" });
      }
      // P04: Mirai Known Credential (root/xc3511)
      if (password === "xc3511" || (username === "root" && password === "xc3511")) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P04"]);
        threatLevel = "CRITICAL";
        botnetAttribution = "Mirai Botnet";
        mitreTechniques.push({ id: "T1110.001", name: "Password Spraying: Mirai", tactic: "TA0006" });
      }
      // P05: Gafgyt/Qbot Known Credential (root/vizxv)
      if (password === "vizxv" || (username === "root" && password === "vizxv")) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P05"]);
        threatLevel = "CRITICAL";
        botnetAttribution = "Gafgyt / BASHLITE";
        mitreTechniques.push({ id: "T1110.001", name: "Password Spraying: Gafgyt", tactic: "TA0006" });
      }
      // P06: Empty / Null Password
      if (!password || password.length === 0) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P06"]);
        mitreTechniques.push({ id: "T1110.001", name: "Null Password", tactic: "TA0006" });
      }
      // P08: Telecom / Router default (support/support)
      if (username === "support" || password === "support") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P08"]);
        mitreTechniques.push({ id: "T1078.001", name: "Vendor Default Account", tactic: "TA0001" });
      }
      // P09: Camera / DVR default (guest/guest)
      if (username === "guest" || password === "guest") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P09"]);
        mitreTechniques.push({ id: "T1078.001", name: "Appliance Default Account", tactic: "TA0001" });
      }
      // P10: Anomalous Username Fuzzing (SQLi / path traversal / long string / injection)
      if (username.includes("'") || username.includes('"') || username.includes(";") || username.includes("%") || username.length > 25) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P10"]);
        threatLevel = "HIGH";
        mitreTechniques.push({ id: "T1110.001", name: "Authentication Fuzzing", tactic: "TA0006" });
      }

      // P07: High frequency spraying
      const prevLogins = sessionEvents.filter(e => e.isLogin).length;
      if (prevLogins > 2) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P07"]);
        threatLevel = "HIGH";
        mitreTechniques.push({ id: "T1110.003", name: "Password Spraying", tactic: "TA0006" });
      }
    } 
    // 2. Command Execution Analysis
    else {
      const lower = command.toLowerCase();
      const tokens = lower.split(/\s+/);
      const baseCmd = tokens[0] || "";

      // Reconnaissance (P11 - P20)
      if (baseCmd === "uname") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P11"]);
        mitreTechniques.push({ id: "T1082", name: "System Information Discovery", tactic: "TA0007" });
        killChainStage = "3. Host Discovery";
        threatLevel = "LOW";
      }
      if (baseCmd === "pwd") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P12"]);
        mitreTechniques.push({ id: "T1083", name: "File and Directory Discovery", tactic: "TA0007" });
        killChainStage = "3. Host Discovery";
      }
      if (baseCmd === "whoami") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P13"]);
        mitreTechniques.push({ id: "T1033", name: "System Owner/User Discovery", tactic: "TA0007" });
        killChainStage = "3. Host Discovery";
      }
      if (baseCmd === "id") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P14"]);
        mitreTechniques.push({ id: "T1033", name: "System Owner/User Discovery", tactic: "TA0007" });
        killChainStage = "3. Host Discovery";
        threatLevel = "MEDIUM";
      }
      if (baseCmd === "ls") {
        mitreTechniques.push({ id: "T1083", name: "File and Directory Discovery", tactic: "TA0007" });
        killChainStage = "3. Host Discovery";
        if (command.includes("/root")) matchedPatterns.push(PATTERNS_TAXONOMY["P16"]);
        else if (command.includes("/etc")) matchedPatterns.push(PATTERNS_TAXONOMY["P17"]);
        else if (command.includes("/tmp")) matchedPatterns.push(PATTERNS_TAXONOMY["P18"]);
        else matchedPatterns.push(PATTERNS_TAXONOMY["P15"]);
      }
      if (baseCmd === "help") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P19"]);
        mitreTechniques.push({ id: "T1059.004", name: "Unix Shell", tactic: "TA0002" });
      }
      if (baseCmd === "ps" || baseCmd === "top") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P20"]);
        mitreTechniques.push({ id: "T1057", name: "Process Discovery", tactic: "TA0007" });
        killChainStage = "3. Host Discovery";
        threatLevel = "MEDIUM";
      }

      // Credential Harvesting & Sensitive Files (P21 - P30)
      if (baseCmd === "cat") {
        killChainStage = "4. Credential Harvesting";
        if (command.includes("/etc/passwd")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P21"]);
          mitreTechniques.push({ id: "T1003.008", name: "OS Credential Dumping: /etc/passwd", tactic: "TA0006" });
          threatLevel = "HIGH";
        } else if (command.includes("/etc/shadow")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P22"]);
          mitreTechniques.push({ id: "T1003.008", name: "OS Credential Dumping: /etc/shadow", tactic: "TA0006" });
          threatLevel = "CRITICAL";
        } else if (command.includes(".ssh") || command.includes("id_rsa")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P23"]);
          mitreTechniques.push({ id: "T1552.004", name: "Private Keys", tactic: "TA0006" });
          threatLevel = "CRITICAL";
        } else if (command.includes(".bash_history")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P24"]);
          mitreTechniques.push({ id: "T1552.003", name: "Bash History", tactic: "TA0009" });
          threatLevel = "HIGH";
        } else if (command.includes("/etc/network")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P27"]);
          mitreTechniques.push({ id: "T1016", name: "Network Configuration Discovery", tactic: "TA0007" });
          threatLevel = "MEDIUM";
        } else if (command.includes("/var/log")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P29"]);
          mitreTechniques.push({ id: "T1005", name: "System Log Snooping", tactic: "TA0009" });
          threatLevel = "MEDIUM";
        } else if (command.includes("/var/backups")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P30"]);
          mitreTechniques.push({ id: "T1005", name: "Backup Probing", tactic: "TA0009" });
          threatLevel = "HIGH";
        } else {
          mitreTechniques.push({ id: "T1005", name: "Data from Local System", tactic: "TA0009" });
          threatLevel = "MEDIUM";
        }
      }

      // Shell & Router Exploitation (P25, P26, P27, P28)
      if (lower.includes("busybox") || baseCmd === "sh" || baseCmd === "/bin/sh") {
        matchedPatterns.push(PATTERNS_TAXONOMY["P25"]);
        mitreTechniques.push({ id: "T1059.004", name: "Unix Shell: BusyBox", tactic: "TA0002" });
        threatLevel = "HIGH";
      }
      if (lower.includes("cgi-bin") || lower.includes(".cgi")) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P26"]);
        mitreTechniques.push({ id: "T1190", name: "Exploit Public-Facing App: CGI", tactic: "TA0001" });
        threatLevel = "CRITICAL";
      }
      if (baseCmd === "ifconfig" || lower.includes("ip addr") || lower.includes("ip a")) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P27"]);
        mitreTechniques.push({ id: "T1016", name: "System Network Configuration", tactic: "TA0007" });
        killChainStage = "3. Host Discovery";
      }
      if (lower.includes("/etc/init.d") || lower.includes("systemctl") || lower.includes("service")) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P28"]);
        mitreTechniques.push({ id: "T1082", name: "System Services Discovery", tactic: "TA0007" });
      }

      // Malware Staging & Droppers (P31 - P34)
      if (baseCmd === "wget" || baseCmd === "curl") {
        killChainStage = "5. Payload Staging";
        threatLevel = "CRITICAL";
        mitreTechniques.push({ id: "T1105", name: "Ingress Tool Transfer (wget/curl)", tactic: "TA0011" });

        if (baseCmd === "wget") matchedPatterns.push(PATTERNS_TAXONOMY["P31"]);
        if (baseCmd === "curl") matchedPatterns.push(PATTERNS_TAXONOMY["P32"]);

        if (lower.includes(".sh")) matchedPatterns.push(PATTERNS_TAXONOMY["P33"]);
        if (lower.includes(".bin") || lower.includes("mips") || lower.includes("arm") || lower.includes("x86") || lower.includes("elf")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P34"]);
        }

        if (lower.includes("mirai") || lower.includes("arm7") || lower.includes("mips")) {
          botnetAttribution = "Mirai Botnet";
        } else if (lower.includes("mozi")) {
          botnetAttribution = "Mozi Botnet";
          matchedPatterns.push(PATTERNS_TAXONOMY["P43"]);
        } else {
          botnetAttribution = "IoT Dropper Bot";
        }
      }

      // Execution via pipe (P39)
      if (command.includes("| sh") || command.includes("| bash") || command.includes("| busybox")) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P39"]);
        mitreTechniques.push({ id: "T1059.004", name: "Direct Shell Execution Pipe", tactic: "TA0002" });
        threatLevel = "CRITICAL";
      }

      // Cron persistence (P40)
      if (lower.includes("cron") || lower.includes("crontab")) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P40"]);
        mitreTechniques.push({ id: "T1053.003", name: "Cron Scheduled Tasks", tactic: "TA0003" });
        threatLevel = "HIGH";
      }

      // Persistence & Evasion (P35 - P38)
      if (baseCmd === "echo" || baseCmd === "touch") {
        killChainStage = "6. Persistence & Evasion";
        matchedPatterns.push(PATTERNS_TAXONOMY["P35"]);
        mitreTechniques.push({ id: "T1059.004", name: "Unix Shell", tactic: "TA0002" });
        threatLevel = "MEDIUM";
      }
      if (baseCmd === "mkdir") {
        killChainStage = "6. Persistence & Evasion";
        matchedPatterns.push(PATTERNS_TAXONOMY["P36"]);
        threatLevel = "MEDIUM";
      }
      if (baseCmd === "rm") {
        killChainStage = "6. Persistence & Evasion";
        matchedPatterns.push(PATTERNS_TAXONOMY["P37"]);
        mitreTechniques.push({ id: "T1070.004", name: "File Deletion", tactic: "TA0005" });
        threatLevel = "HIGH";
        if (lower.includes("/var/log") || lower.includes("history") || lower.includes("syslog")) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P38"]);
          mitreTechniques.push({ id: "T1070.002", name: "Clear Linux Logs", tactic: "TA0005" });
          threatLevel = "CRITICAL";
        }
      }
      if (baseCmd === "exit") {
        killChainStage = "Session Closed";
        threatLevel = "LOW";
      }

      // Botnet Signature Matching (P41, P42, P43, P44)
      const recentCmds = sessionEvents.map(e => e.command.toLowerCase());
      
      // P41: Mirai sequence: uname -> id -> cat /etc/passwd -> wget
      if (recentCmds.includes("uname -a") && recentCmds.includes("id") && (baseCmd === "wget" || baseCmd === "curl")) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P41"]);
        botnetAttribution = "Mirai Botnet";
        threatLevel = "CRITICAL";
      }

      // P42: Hajime sequence: whoami -> ps -> /tmp
      if (recentCmds.includes("whoami") && (baseCmd === "ps" || lower.includes("/tmp"))) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P42"]);
        botnetAttribution = "Hajime P2P Worm";
        threatLevel = "HIGH";
      }

      // P44: Gafgyt / Bashlite signature
      if (recentCmds.some(c => c.includes("vizxv")) || (recentCmds.includes("uname -a") && lower.includes("busybox"))) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P44"]);
        botnetAttribution = "Gafgyt / BASHLITE";
        threatLevel = "CRITICAL";
      }

      // P46: Out-of-order kill-chain leap (Immediate exploit/download without recon)
      if ((baseCmd === "wget" || baseCmd === "curl" || command.includes("/etc/shadow")) && sessionEvents.length < 2) {
        matchedPatterns.push(PATTERNS_TAXONOMY["P46"]);
        threatLevel = "CRITICAL";
      }

      // P45: Hawkes Temporal Burst Rate Anomaly (>3 commands in <2 seconds)
      if (sessionEvents.length >= 3) {
        const lastFew = sessionEvents.slice(-3);
        const timeDiff = new Date(timestamp) - new Date(lastFew[0].timestamp);
        if (timeDiff > 0 && timeDiff < 2500) {
          matchedPatterns.push(PATTERNS_TAXONOMY["P45"]);
          if (botnetAttribution === "Unknown Actor") botnetAttribution = "Automated Bot Script";
        }
      }
    }

    // Default fallback
    if (matchedPatterns.length === 0) {
      matchedPatterns.push({
        id: "P00",
        category: "Generic Shell Interaction",
        name: `Command: ${command.substring(0, 30)}`,
        severity: threatLevel,
        mitre: "T1059.004",
        tactic: "TA0002"
      });
      mitreTechniques.push({ id: "T1059.004", name: "Command Execution", tactic: "TA0002" });
    }

    const enrichedEvent = {
      id: "EVT-" + Date.now() + "-" + Math.floor(Math.random() * 1000),
      timestamp,
      ip,
      session: sessionId,
      command,
      isLogin,
      authDetails,
      killChainStage,
      threatLevel,
      botnetAttribution,
      matchedPatterns,
      mitreTechniques
    };

    // Store in session history
    sessionEvents.push(enrichedEvent);
    if (sessionEvents.length > 50) sessionEvents.shift();

    return enrichedEvent;
  }
}

module.exports = {
  AttackClassifier,
  PATTERNS_TAXONOMY,
  MITRE_TACTICS
};
