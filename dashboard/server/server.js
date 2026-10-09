/**
 * Winnie-SOC: Main Application Server
 * Serves Cyber SOC Web Dashboard, runs WebSocket streamer,
 * manages 47-pattern classification, and operates TCP ingestion on port 5000.
 */
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const net = require('net');
const WebSocket = require('ws');

const TcpIngestionServer = require('./tcp_server');
const { AttackClassifier, PATTERNS_TAXONOMY, MITRE_TACTICS } = require('./classifier');
const { AttackSimulator, ATTACK_PROFILES } = require('./simulator');

const HTTP_PORT = process.env.PORT || 3000;
const TCP_PORT = process.env.TCP_PORT || 5000;

const DATA_DIR = path.join(__dirname, '..', 'data');
const EVENTS_FILE = path.join(DATA_DIR, 'events.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ---------------------------------------------------------------------
// Application State & Persistence
// ---------------------------------------------------------------------
let events = [];
let sessions = new Map(); // sessionId -> sessionObject
let patternHits = {};
let mitreHits = {};       // tactic -> count
let techniqueHits = {};   // specific technique ID -> count
let velocityTickerEvents = 0;

// Initialize pattern and MITRE counters
Object.keys(PATTERNS_TAXONOMY).forEach(k => { patternHits[k] = 0; });
Object.keys(MITRE_TACTICS).forEach(k => { mitreHits[k] = 0; });

// Load persisted state if exists
try {
  if (fs.existsSync(EVENTS_FILE)) {
    const rawEvents = JSON.parse(fs.readFileSync(EVENTS_FILE, 'utf8'));
    events = Array.isArray(rawEvents) ? rawEvents.slice(-500) : [];
  }
  if (fs.existsSync(SESSIONS_FILE)) {
    const rawSessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
    if (Array.isArray(rawSessions)) {
      rawSessions.forEach(s => sessions.set(s.id, s));
    }
  }
} catch (e) {
  console.warn('[Storage] Notice: Starting with fresh event cache:', e.message);
}

// Recalculate hit counters from loaded events
events.forEach(e => {
  if (e.matchedPatterns) {
    e.matchedPatterns.forEach(p => {
      patternHits[p.id] = (patternHits[p.id] || 0) + 1;
    });
  }
  if (e.mitreTechniques) {
    e.mitreTechniques.forEach(t => {
      if (t.tactic) mitreHits[t.tactic] = (mitreHits[t.tactic] || 0) + 1;
      techniqueHits[t.id] = (techniqueHits[t.id] || 0) + 1;
    });
  }
});

// Throttled persistence saver
let saveTimeout = null;
function persistData() {
  if (saveTimeout) return;
  saveTimeout = setTimeout(() => {
    try {
      fs.writeFileSync(EVENTS_FILE, JSON.stringify(events.slice(-500), null, 2));
      fs.writeFileSync(SESSIONS_FILE, JSON.stringify(Array.from(sessions.values()), null, 2));
    } catch (err) {
      console.error('[Storage Error]', err.message);
    }
    saveTimeout = null;
  }, 2000);
}

// ---------------------------------------------------------------------
// Known Threat Intelligence IP Profiler
// ---------------------------------------------------------------------
function enrichIpIntelligence(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
    return { origin: 'Local Host (Loopback)', asn: 'Internal Test Client', type: 'LOCAL_DEV', threatScore: 10 };
  }
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.')) {
    return { origin: 'Internal LAN / Wi-Fi', asn: 'Local Network Subnet', type: 'LAN_HOST', threatScore: 25 };
  }
  if (ip === '185.220.101.5') {
    return { origin: 'Frankfurt, Germany', asn: 'AS208323 (Tor Exit Relay)', type: 'TOR_EXIT', threatScore: 95 };
  }
  if (ip === '45.154.255.89') {
    return { origin: 'Amsterdam, Netherlands', asn: 'AS9009 (M247 Ltd / Bulletproof)', type: 'BOTNET_C2', threatScore: 92 };
  }
  if (ip === '91.240.118.172') {
    return { origin: 'Moscow, Russia', asn: 'AS44050 (Webzilla Scanner)', type: 'RECON_BOT', threatScore: 85 };
  }
  if (ip === '194.26.29.112') {
    return { origin: 'Sofia, Bulgaria', asn: 'AS48693 (NetProtect Dropper)', type: 'MALWARE_DROPPER', threatScore: 98 };
  }
  if (ip === '103.149.28.14') {
    return { origin: 'Shenzhen, China', asn: 'AS138997 (Mozi P2P Node)', type: 'IOT_WORM', threatScore: 90 };
  }
  return { origin: 'External WAN', asn: 'Public ISP / Unclassified', type: 'EXTERNAL', threatScore: 60 };
}

// ---------------------------------------------------------------------
// Core Ingestion & Processing Pipeline
// ---------------------------------------------------------------------
const classifier = new AttackClassifier();
let wsClients = new Set();

function broadcast(msg) {
  const payload = JSON.stringify(msg);
  wsClients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

function processIncomingEvent(rawEvent) {
  const enriched = classifier.classify(rawEvent);
  events.push(enriched);
  velocityTickerEvents++;
  if (events.length > 1000) events.shift();

  // Update session record
  const sId = enriched.session;
  let session = sessions.get(sId);
  if (!session) {
    session = {
      id: sId,
      ip: enriched.ip,
      ipIntel: enrichIpIntelligence(enriched.ip),
      startTime: enriched.timestamp,
      lastActivity: enriched.timestamp,
      commandCount: 0,
      commands: [],
      maxThreat: 'LOW',
      killChainStage: enriched.killChainStage,
      botnetFamily: enriched.botnetAttribution,
      authAttempts: []
    };
    sessions.set(sId, session);
  }

  session.lastActivity = enriched.timestamp;
  session.commandCount++;
  session.commands.push({
    timestamp: enriched.timestamp,
    command: enriched.command,
    stage: enriched.killChainStage,
    threat: enriched.threatLevel
  });

  // Escalate session attributes if higher severity seen
  const severities = { 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4 };
  if ((severities[enriched.threatLevel] || 1) > (severities[session.maxThreat] || 1)) {
    session.maxThreat = enriched.threatLevel;
  }
  session.killChainStage = enriched.killChainStage;
  if (enriched.botnetAttribution !== 'Unknown Actor') {
    session.botnetFamily = enriched.botnetAttribution;
  }
  if (enriched.isLogin && enriched.authDetails) {
    session.authAttempts.push(enriched.authDetails);
  }

  // Update Taxonomy & MITRE Hits
  enriched.matchedPatterns.forEach(p => {
    patternHits[p.id] = (patternHits[p.id] || 0) + 1;
  });
  enriched.mitreTechniques.forEach(t => {
    if (t.tactic) {
      mitreHits[t.tactic] = (mitreHits[t.tactic] || 0) + 1;
    }
    techniqueHits[t.id] = (techniqueHits[t.id] || 0) + 1;
  });

  persistData();

  // Real-time broadcast
  broadcast({
    type: 'EVENT',
    event: enriched,
    sessionSummary: session,
    stats: computeQuickStats()
  });
}

// ---------------------------------------------------------------------
// Analytics & Metrics Aggregator
// ---------------------------------------------------------------------
function computeQuickStats() {
  const now = Date.now();
  let activeCount = 0;
  sessions.forEach(s => {
    const elapsed = now - new Date(s.lastActivity).getTime();
    if (elapsed < 5 * 60 * 1000) activeCount++;
  });

  // Top usernames & passwords
  const userMap = {};
  const passMap = {};
  const cmdMap = {};
  const ipMap = {};
  const dropperUrls = [];
  const sensitiveFiles = [];
  const botnetCounts = {};
  const killChainCounts = {
    "1. Reconnaissance": 0,
    "2. Credential Access": 0,
    "3. Host Discovery": 0,
    "4. Credential Harvesting": 0,
    "5. Payload Staging": 0,
    "6. Persistence & Evasion": 0
  };

  events.forEach(e => {
    // Kill chain
    if (killChainCounts[e.killChainStage] !== undefined) {
      killChainCounts[e.killChainStage]++;
    }

    // IP counts
    ipMap[e.ip] = (ipMap[e.ip] || 0) + 1;

    // Command counts
    if (!e.isLogin && e.command) {
      const base = e.command.split(' ')[0];
      cmdMap[base] = (cmdMap[base] || 0) + 1;
    }

    // Credentials
    if (e.isLogin && e.authDetails) {
      userMap[e.authDetails.username] = (userMap[e.authDetails.username] || 0) + 1;
      if (e.authDetails.password) {
        passMap[e.authDetails.password] = (passMap[e.authDetails.password] || 0) + 1;
      }
    }

    // Dropper URLs (wget / curl)
    if (e.command.startsWith('wget ') || e.command.startsWith('curl ') || e.command.includes('http://') || e.command.includes('https://')) {
      const parts = e.command.split(/\s+/);
      const urlPart = parts.find(p => p.startsWith('http://') || p.startsWith('https://')) || parts[1] || '';
      if (urlPart && !dropperUrls.some(d => d.url === urlPart)) {
        dropperUrls.push({
          url: urlPart,
          timestamp: e.timestamp,
          ip: e.ip,
          session: e.session
        });
      }
    }

    // Sensitive files
    if (e.command.includes('/etc/passwd') || e.command.includes('/etc/shadow') || e.command.includes('.ssh') || e.command.includes('.bash_history')) {
      sensitiveFiles.push({
        target: e.command,
        ip: e.ip,
        session: e.session,
        timestamp: e.timestamp
      });
    }

    // Botnet distribution - dynamic aggregation
    const fam = e.botnetAttribution || 'Generic Scanner';
    botnetCounts[fam] = (botnetCounts[fam] || 0) + 1;
  });

  // Calculate dynamic ESP32 free heap estimate based on active tasks & sessions
  const baseHeap = 218; // Typical ESP32 free heap after Arduino + LibSSH init
  const estimatedFreeHeap = Math.max(95, Math.round(baseHeap - (activeCount * 18.5) - ((events.length % 20) * 0.4)));

  // Format Top IPs with intelligence
  const enrichedTopIps = Object.entries(ipMap)
    .sort((a,b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ip, count]) => {
      const intel = enrichIpIntelligence(ip);
      return {
        ip,
        count,
        origin: intel.origin,
        asn: intel.asn,
        type: intel.type,
        threatScore: Math.min(100, intel.threatScore + count * 2)
      };
    });

  return {
    totalSessions: sessions.size,
    totalCommands: events.length,
    activeSessions: activeCount,
    maxThreatLevel: events.some(e => e.threatLevel === 'CRITICAL') ? 'CRITICAL' : 
                    events.some(e => e.threatLevel === 'HIGH') ? 'HIGH' : 
                    events.length > 0 ? 'MEDIUM' : 'LOW',
    killChainCounts,
    botnetCounts,
    topUsers: Object.entries(userMap).sort((a,b)=>b[1]-a[1]).slice(0, 6),
    topPasswords: Object.entries(passMap).sort((a,b)=>b[1]-a[1]).slice(0, 6),
    topCommands: Object.entries(cmdMap).sort((a,b)=>b[1]-a[1]).slice(0, 8),
    topIps: enrichedTopIps,
    dropperUrls: dropperUrls.slice(-10),
    sensitiveFiles: sensitiveFiles.slice(-10),
    hardwareHealth: {
      device: "ESP32 DevKit v1 (Xtensa Dual-Core 240MHz)",
      freeHeapKb: estimatedFreeHeap,
      heapStatus: estimatedFreeHeap > 150 ? 'Safe' : estimatedFreeHeap > 110 ? 'Nominal' : 'Warning Low',
      flashSize: "4 MB SPI Flash",
      totalSram: "520 KB SRAM",
      packetsIngested: (tcpServer ? tcpServer.totalPacketsReceived : 0) || events.length,
      lastPacketReceived: tcpServer ? tcpServer.lastPacketTime : null,
      ingestPort: TCP_PORT
    },
    tcpStatus: tcpServer ? tcpServer.getStatus() : { status: 'INITIALIZING', port: TCP_PORT }
  };
}

// ---------------------------------------------------------------------
// Express Web Server & REST API
// ---------------------------------------------------------------------
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// REST Endpoints
app.get('/api/stats', (req, res) => {
  res.json({
    summary: computeQuickStats(),
    patternHits,
    mitreHits,
    techniqueHits,
    taxonomy: PATTERNS_TAXONOMY,
    mitreTactics: MITRE_TACTICS
  });
});

app.get('/api/events', (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  res.json(events.slice(-limit).reverse());
});

app.get('/api/sessions', (req, res) => {
  res.json(Array.from(sessions.values()).reverse());
});

app.get('/api/sessions/:id', (req, res) => {
  // Session IDs may be numeric (simulator) or string (ESP32 device)
  const rawId = req.params.id;
  const s = sessions.get(parseInt(rawId)) || sessions.get(rawId);
  if (s) res.json(s);
  else res.status(404).json({ error: 'Session not found' });
});

app.get('/api/simulator/profiles', (req, res) => {
  res.json(simulator.getProfiles());
});

// Trigger simulated attack wave over real TCP socket
app.post('/api/simulate', async (req, res) => {
  const { profile } = req.body;
  // Always use real TCP socket to port 5000 so the TCP stack is 100% active
  simulator.runProfile(profile || 'mirai_botnet', true, TCP_PORT);
  res.json({ status: 'started', profile, transport: `TCP 127.0.0.1:${TCP_PORT}` });
});

// Live Command Injector: send custom command over real TCP socket to port 5000
app.post('/api/inject', (req, res) => {
  const { command, ip, session } = req.body;
  if (!command) {
    return res.status(400).json({ error: 'Command is required' });
  }

  const clientIp = ip || '192.168.1.105';
  const sessionId = parseInt(session) || (sessions.size > 0 ? Array.from(sessions.keys()).pop() : 1);

  // Send over genuine TCP socket to port 5000 exactly like the ESP32
  const tcpClient = net.createConnection({ port: TCP_PORT, host: '127.0.0.1' }, () => {
    tcpClient.write(JSON.stringify({
      ip: clientIp,
      session: sessionId,
      command: command.trim()
    }));
    tcpClient.end();
    res.json({ status: 'transmitted_over_tcp', port: TCP_PORT, ip: clientIp, command: command.trim() });
  });

  tcpClient.on('error', (err) => {
    console.error('[Inject Error]', err.message);
    res.status(500).json({ error: 'Failed to connect to TCP server: ' + err.message });
  });
});

app.post('/api/clear', (req, res) => {
  events = [];
  sessions.clear();
  Object.keys(patternHits).forEach(k => patternHits[k] = 0);
  Object.keys(mitreHits).forEach(k => mitreHits[k] = 0);
  Object.keys(techniqueHits).forEach(k => techniqueHits[k] = 0);
  persistData();
  broadcast({ type: 'RESET', stats: computeQuickStats() });
  res.json({ status: 'cleared' });
});

app.get('/api/export', (req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename=winnie_soc_audit_log.json');
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify({
    exportedAt: new Date().toISOString(),
    totalSessions: sessions.size,
    totalEvents: events.length,
    sessions: Array.from(sessions.values()),
    events: events
  }, null, 2));
});

// WebSocket connection handling
wss.on('connection', (ws) => {
  wsClients.add(ws);
  // Send initial snapshot
  ws.send(JSON.stringify({
    type: 'INIT',
    stats: computeQuickStats(),
    recentEvents: events.slice(-50).reverse(),
    patternHits,
    mitreHits,
    techniqueHits,
    taxonomy: PATTERNS_TAXONOMY,
    mitreTactics: MITRE_TACTICS
  }));

  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

// Periodic heartbeat broadcast every 2 seconds (with actual event velocity rate)
setInterval(() => {
  const currentVelocity = velocityTickerEvents;
  velocityTickerEvents = 0;
  broadcast({
    type: 'VELOCITY_TICK',
    velocity: currentVelocity,
    stats: computeQuickStats()
  });
}, 2000);

// ---------------------------------------------------------------------
// Initialize Background Services
// ---------------------------------------------------------------------
const tcpServer = new TcpIngestionServer(TCP_PORT, (event) => {
  processIncomingEvent(event);
}, (status) => {
  broadcast({ type: 'NODE_STATUS', status });
});

const simulator = new AttackSimulator((event) => {
  processIncomingEvent(event);
}, TCP_PORT);

// Start TCP and HTTP servers
tcpServer.start();

server.listen(HTTP_PORT, () => {
  console.log(`\n==========================================================`);
  console.log(`🛡️  WINNIE-SOC LIVE CYBER SECURITY DASHBOARD IS ONLINE!`);
  console.log(`🌐  Open UI in Browser:  http://localhost:${HTTP_PORT}`);
  console.log(`🔌  ESP32 Telemetry Port: TCP 0.0.0.0:${TCP_PORT}`);
  console.log(`==========================================================\n`);
});
