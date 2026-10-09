/**
 * Winnie-SOC: Frontend Real-Time Application & Visualization Engine
 * Handles WebSocket telemetry, dynamic panel updates, MITRE ATT&CK matrix rendering,
 * Kill-chain tracking, keystroke replay modal, and real TCP socket attack triggers.
 */

// Global State
let ws = null;
let appState = {
  stats: null,
  recentEvents: [],
  taxonomy: {},
  mitreTactics: {},
  patternHits: {},
  mitreHits: {},
  techniqueHits: {},
  soundEnabled: false,
  velocityData: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  currentVelocity: 0
};

// Web Audio API Synthesizer (Zero external sound files)
let audioCtx = null;
function playCyberBeep(isCritical = false) {
  if (!appState.soundEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    if (isCritical) {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(440, audioCtx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(880, audioCtx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.12, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.15);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.15);
    } else {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(600, audioCtx.currentTime);
      gain.gain.setValueAtTime(0.05, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.08);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.08);
    }
  } catch (e) {
    console.warn('Audio play error:', e);
  }
}

// ---------------------------------------------------------------------
// WebSocket Initialization & Reconnection
// ---------------------------------------------------------------------
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  const wsStatusDot = document.getElementById('wsStatusDot');
  const wsStatusText = document.getElementById('wsStatusText');

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    wsStatusDot.className = 'status-dot dot-connected';
    wsStatusText.textContent = 'CONNECTED';
    console.log('[Winnie-SOC] Real-time telemetry socket connected.');
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleSocketMessage(msg);
    } catch (err) {
      console.error('[Socket Parse Error]', err);
    }
  };

  ws.onclose = () => {
    wsStatusDot.className = 'status-dot dot-idle';
    wsStatusText.textContent = 'RECONNECTING...';
    setTimeout(initWebSocket, 3000);
  };

  ws.onerror = () => {
    ws.close();
  };
}

function handleSocketMessage(msg) {
  if (msg.type === 'INIT') {
    appState.stats = msg.stats;
    appState.recentEvents = msg.recentEvents || [];
    appState.taxonomy = msg.taxonomy || {};
    appState.mitreTactics = msg.mitreTactics || {};
    appState.patternHits = msg.patternHits || {};
    appState.mitreHits = msg.mitreHits || {};
    appState.techniqueHits = msg.techniqueHits || {};

    renderAllPanels();
    renderTaxonomyExplorer();
    renderMitreMatrix();
    loadSessionsTable();

    // Populate terminal with recent events
    const terminal = document.getElementById('terminalOutput');
    terminal.innerHTML = '';
    if (appState.recentEvents.length > 0) {
      appState.recentEvents.forEach(e => appendTerminalLine(e));
    } else {
      terminal.innerHTML = `
        <div class="terminal-line system-msg">
          <span class="term-time">[${new Date().toLocaleTimeString()}]</span> [SYSTEM] Winnie-SOC Ingestion Gateway listening on TCP 0.0.0.0:5000...
        </div>
        <div class="terminal-line system-msg">
          <span class="term-time">[${new Date().toLocaleTimeString()}]</span> [READY] Awaiting live telemetry from ESP32 Honeypot (or inject command below)...
        </div>`;
    }
  } else if (msg.type === 'EVENT') {
    const e = msg.event;
    appState.recentEvents.unshift(e);
    if (appState.recentEvents.length > 250) appState.recentEvents.pop();

    if (msg.stats) appState.stats = msg.stats;

    // Update hits
    e.matchedPatterns.forEach(p => {
      appState.patternHits[p.id] = (appState.patternHits[p.id] || 0) + 1;
    });
    e.mitreTechniques.forEach(t => {
      if (t.tactic) {
        appState.mitreHits[t.tactic] = (appState.mitreHits[t.tactic] || 0) + 1;
      }
      appState.techniqueHits[t.id] = (appState.techniqueHits[t.id] || 0) + 1;
    });

    // Sound alert
    playCyberBeep(e.threatLevel === 'CRITICAL');

    // UI Updates
    appendTerminalLine(e);
    renderAllPanels();
    renderMitreMatrix();
    loadSessionsTable();
  } else if (msg.type === 'VELOCITY_TICK') {
    appState.currentVelocity = msg.velocity || 0;
    appState.velocityData.push(appState.currentVelocity);
    if (appState.velocityData.length > 20) appState.velocityData.shift();
    drawVelocityCanvas();
    if (msg.stats) {
      appState.stats = msg.stats;
      renderAllPanels();
    }
  } else if (msg.type === 'NODE_STATUS') {
    updateNodeStatus(msg.status);
  } else if (msg.type === 'RESET') {
    appState.stats = msg.stats;
    appState.recentEvents = [];
    appState.patternHits = {};
    appState.mitreHits = {};
    appState.techniqueHits = {};
    document.getElementById('terminalOutput').innerHTML = `
      <div class="terminal-line system-msg">
        <span class="term-time">[${new Date().toLocaleTimeString()}]</span> [SYSTEM] Log store cleared. Ready for new incoming events...
      </div>`;
    renderAllPanels();
    renderMitreMatrix();
    renderTaxonomyExplorer();
    loadSessionsTable();
  }
}

// ---------------------------------------------------------------------
// Terminal Renderer (Panel 5)
// ---------------------------------------------------------------------
function appendTerminalLine(e) {
  const terminal = document.getElementById('terminalOutput');
  const autoscroll = document.getElementById('chkAutoscroll').checked;

  const line = document.createElement('div');
  line.className = 'terminal-line';

  const timeStr = new Date(e.timestamp).toLocaleTimeString();
  const timeSpan = `<span class="term-time">[${timeStr}]</span>`;
  const ipBadge = `<span class="badge-version">${e.ip}</span>`;
  const sessBadge = `<span class="badge-version text-amber">#${e.session}</span>`;

  let content = '';
  if (e.isLogin) {
    const creds = e.authDetails ? `${e.authDetails.username} : ${e.authDetails.password}` : e.command;
    content = `${timeSpan} ${ipBadge} ${sessBadge} <span class="text-amber">🔑 AUTH:</span> <span class="term-threat-high">${escapeHtml(creds)}</span>`;
  } else {
    let threatClass = 'term-cmd';
    if (e.threatLevel === 'CRITICAL') threatClass = 'term-threat-crit';
    else if (e.threatLevel === 'HIGH') threatClass = 'term-threat-high';

    content = `${timeSpan} ${ipBadge} ${sessBadge} <span class="term-prompt">root@ubuntu:~#</span> <span class="${threatClass}">${escapeHtml(e.command)}</span>`;
  }

  line.innerHTML = content;
  terminal.appendChild(line);

  // Maintain line count
  if (terminal.children.length > 250) {
    terminal.removeChild(terminal.children[0]);
  }

  if (autoscroll) {
    terminal.scrollTop = terminal.scrollHeight;
  }
}

// ---------------------------------------------------------------------
// Panel Renderers
// ---------------------------------------------------------------------
function renderAllPanels() {
  if (!appState.stats) return;
  const s = appState.stats;

  // KPI Panels 1-4
  document.getElementById('statTotalSessions').textContent = s.totalSessions || 0;
  document.getElementById('statTotalCommands').textContent = s.totalCommands || 0;
  document.getElementById('statActiveSessions').textContent = s.activeSessions || 0;

  const threatElem = document.getElementById('statThreatIndex');
  const threatDesc = document.getElementById('statThreatDesc');
  const level = s.maxThreatLevel || 'LOW';
  threatElem.textContent = level;
  threatElem.className = `kpi-value threat-badge threat-${level.toLowerCase()}`;
  if (level === 'CRITICAL') threatDesc.textContent = 'Active botnet intrusion detected!';
  else if (level === 'HIGH') threatDesc.textContent = 'Malicious commands intercepted';
  else if (level === 'MEDIUM') threatDesc.textContent = 'Authentication probes ongoing';
  else threatDesc.textContent = 'Normal baseline traffic';

  // Hardware Health Panel 17 (Dynamic Telemetry)
  if (s.hardwareHealth) {
    const hw = s.hardwareHealth;
    document.getElementById('hwDevice').textContent = hw.device;
    const heapElem = document.getElementById('hwHeapVal');
    heapElem.textContent = `${hw.freeHeapKb} KB (${hw.heapStatus})`;
    heapElem.className = hw.freeHeapKb > 150 ? 'hw-val text-emerald' : hw.freeHeapKb > 110 ? 'hw-val text-amber' : 'hw-val text-crimson';
    document.getElementById('hwPacketsVal').textContent = hw.packetsIngested || s.totalCommands || 0;
  }

  if (s.tcpStatus) {
    updateNodeStatus(s.tcpStatus);
  }

  // Panel 6: Cyber Kill-Chain Funnel
  renderKillChain(s.killChainCounts, s.totalCommands);

  // Panel 15: Botnet Family Attribution
  renderBotnetBars(s.botnetCounts, s.totalCommands);

  // Panels 8 & 9: Credentials
  renderStatList('topUsersList', s.topUsers, '#00f0ff');
  renderStatList('topPasswordsList', s.topPasswords, '#a855f7');

  // Panel 10: Top Commands
  renderStatList('topCommandsList', s.topCommands, '#00ff9d');

  // Panel 11: Attacker IP Profiler
  renderTopIpsTable(s.topIps);

  // Panel 13: Intercepted Dropper URLs
  renderDropperUrls(s.dropperUrls);

  // Panel 14: Sensitive Files
  renderSensitiveFiles(s.sensitiveFiles);
}

function updateNodeStatus(status) {
  const pillText = document.getElementById('espStatusText');
  const pillDot = document.getElementById('espStatusDot');

  if (status.status && status.status.includes('ONLINE')) {
    pillText.textContent = `ESP32 SENSOR: ONLINE (${status.lastClientIp || 'Node'})`;
    pillDot.className = 'status-dot dot-connected';
  } else if (status.lastPacketTime) {
    pillText.textContent = `ESP32 SENSOR: STANDBY (${status.totalPackets || 0} pkts)`;
    pillDot.className = 'status-dot dot-idle';
  } else {
    pillText.textContent = 'WAITING FOR PACKETS';
    pillDot.className = 'status-dot dot-idle';
  }
}

// Panel 6: Cyber Kill-Chain Funnel
function renderKillChain(counts, total) {
  const container = document.getElementById('killchainList');
  if (!counts) return;

  const stages = [
    { key: "1. Reconnaissance", name: "1. Network Recon & Probing", icon: "🔍", color: "#00f0ff" },
    { key: "2. Credential Access", name: "2. Brute Force Authentication", icon: "🔑", color: "#a855f7" },
    { key: "3. Host Discovery", name: "3. System & Host Fingerprinting", icon: "💻", color: "#00ff9d" },
    { key: "4. Credential Harvesting", name: "4. Sensitive File Theft (/etc/passwd)", icon: "📂", color: "#ffb800" },
    { key: "5. Payload Staging", name: "5. Malware Dropper Fetch (wget/curl)", icon: "⚡", color: "#ff0055" },
    { key: "6. Persistence & Evasion", name: "6. Evasion & Log Erasure", icon: "🛡️", color: "#ef4444" }
  ];

  container.innerHTML = stages.map(st => {
    const count = counts[st.key] || 0;
    const pct = total > 0 ? Math.round((count / total) * 100) : 0;
    const isActive = count > 0;

    return `
      <div class="kc-item ${isActive ? 'active-stage' : ''}">
        <div class="kc-header">
          <span class="kc-name"><span>${st.icon}</span> ${st.name}</span>
          <span class="kc-badge" style="color: ${st.color}">${count} hits (${pct}%)</span>
        </div>
        <div class="kc-bar-bg">
          <div class="kc-bar-fill" style="width: ${pct}%; background: ${st.color}"></div>
        </div>
      </div>
    `;
  }).join('');
}

// Panel 7: MITRE ATT&CK Matrix Grid (Real Technique Hits)
function renderMitreMatrix() {
  const grid = document.getElementById('mitreGrid');
  const tactics = [
    { id: "TA0043", name: "Reconnaissance", techs: [{ id: "T1082", name: "System Info" }, { id: "T1083", name: "File Discovery" }, { id: "T1046", name: "Network Scan" }] },
    { id: "TA0001", name: "Initial Access", techs: [{ id: "T1078.001", name: "Default Accounts" }, { id: "T1190", name: "Exploit Web App" }] },
    { id: "TA0002", name: "Execution", techs: [{ id: "T1059.004", name: "Unix Shell" }, { id: "T1587.001", name: "Botnet Malware" }] },
    { id: "TA0003", name: "Persistence", techs: [{ id: "T1053.003", name: "Cron Task" }] },
    { id: "TA0005", name: "Defense Evasion", techs: [{ id: "T1070.004", name: "File Deletion" }, { id: "T1070.002", name: "Clear Logs" }] },
    { id: "TA0006", name: "Credential Access", techs: [{ id: "T1110.001", name: "Password Guessing" }, { id: "T1110.003", name: "Password Spraying" }, { id: "T1003.008", name: "OS Cred Dumping" }, { id: "T1552.004", name: "Private Keys" }] },
    { id: "TA0007", name: "Discovery", techs: [{ id: "T1033", name: "User Discovery" }, { id: "T1016", name: "Network Config" }, { id: "T1057", name: "Process Discovery" }] },
    { id: "TA0009", name: "Collection", techs: [{ id: "T1005", name: "Data from System" }, { id: "T1552.003", name: "Bash History" }] },
    { id: "TA0011", name: "Command & Control", techs: [{ id: "T1105", name: "Ingress Transfer" }] }
  ];

  grid.innerHTML = tactics.map(tac => {
    const tacticHits = appState.mitreHits[tac.id] || 0;
    return `
      <div class="mitre-column">
        <div class="mitre-tactic-name">${tac.name} (${tacticHits})</div>
        <div class="mitre-tech-list">
          ${tac.techs.map(t => {
            const techHitCount = appState.techniqueHits[t.id] || 0;
            const isHit = techHitCount > 0;
            return `
              <div class="mitre-tech-item ${isHit ? 'active' : ''}">
                <span>${t.name}</span>
                <span class="mitre-count">${isHit ? techHitCount + 'x' : t.id}</span>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }).join('');
}

// Panel 15: Botnet Family Attribution (Dynamic distribution)
function renderBotnetBars(counts, total) {
  const container = document.getElementById('botnetBars');
  if (!counts) return;

  const entries = Object.entries(counts);
  if (entries.length === 0) {
    container.innerHTML = '<div class="empty-state">No botnet signatures detected yet.</div>';
    return;
  }

  const colors = {
    "Mirai Botnet": "#ff0055",
    "Gafgyt / BASHLITE": "#ff7700",
    "Hajime P2P Worm": "#a855f7",
    "Mozi Botnet": "#e11d48",
    "Generic IoT Scanner": "#00f0ff",
    "Automated Bot Script": "#ffb800",
    "Custom Attack": "#64748b"
  };

  container.innerHTML = entries.map(([name, count]) => {
    const pct = total > 0 ? Math.round((count / total) * 100) : 0;
    const color = colors[name] || "#00ff9d";
    return `
      <div class="botnet-bar-row">
        <div class="botnet-bar-info">
          <span>${name}</span>
          <span style="color: ${color}">${count} (${pct}%)</span>
        </div>
        <div class="botnet-bar-track">
          <div class="botnet-bar-progress" style="width: ${pct}%; background: ${color}"></div>
        </div>
      </div>
    `;
  }).join('');
}

// Horizontal Stat Bars Utility
function renderStatList(containerId, dataArray, color) {
  const el = document.getElementById(containerId);
  if (!dataArray || dataArray.length === 0) {
    el.innerHTML = '<div class="empty-state">No data captured yet.</div>';
    return;
  }

  const maxVal = Math.max(...dataArray.map(item => item[1])) || 1;
  el.innerHTML = dataArray.map(item => {
    const [label, count] = item;
    const pct = Math.round((count / maxVal) * 100);
    return `
      <div class="stat-bar-item">
        <div class="stat-bar-header">
          <span class="text-cyan">${escapeHtml(label || '<none>')}</span>
          <span class="text-muted">${count}</span>
        </div>
        <div class="stat-bar-bg">
          <div class="stat-bar-fill" style="width: ${pct}%; background: ${color}"></div>
        </div>
      </div>
    `;
  }).join('');
}

// Top IPs Table (Panel 11 with Rich Threat Intel)
function renderTopIpsTable(ips) {
  const tbody = document.getElementById('topIpsBody');
  if (!ips || ips.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No attacker IPs logged.</td></tr>';
    return;
  }

  tbody.innerHTML = ips.map(item => {
    const scoreClass = item.threatScore >= 80 ? 'score-high' : item.threatScore >= 40 ? 'score-med' : 'score-low';
    return `
      <tr>
        <td class="text-cyan font-bold">${escapeHtml(item.ip)}</td>
        <td style="font-size: 0.72rem; color: #cbd5e1">${escapeHtml(item.origin)}<br><span class="text-muted" style="font-size:0.65rem">${escapeHtml(item.asn)}</span></td>
        <td>${item.count}</td>
        <td><span class="threat-score-pill ${scoreClass}">${item.threatScore}/100</span></td>
      </tr>
    `;
  }).join('');
}

// Dropper URLs (Panel 13)
function renderDropperUrls(urls) {
  const el = document.getElementById('dropperUrlsList');
  if (!urls || urls.length === 0) {
    el.innerHTML = '<div class="empty-state">No malware drop URLs intercepted yet.</div>';
    return;
  }

  el.innerHTML = urls.map(d => `
    <div class="incident-item danger">
      <div style="font-weight: 600; color: #ff0055">${escapeHtml(d.url)}</div>
      <div class="text-muted" style="font-size: 0.68rem">
        Session #${d.session} • Source: ${escapeHtml(d.ip)} • ${new Date(d.timestamp).toLocaleTimeString()}
      </div>
    </div>
  `).join('');
}

// Sensitive Files (Panel 14)
function renderSensitiveFiles(files) {
  const el = document.getElementById('sensitiveFilesList');
  if (!files || files.length === 0) {
    el.innerHTML = '<div class="empty-state">No sensitive system files accessed yet.</div>';
    return;
  }

  el.innerHTML = files.map(f => `
    <div class="incident-item warn">
      <div style="font-weight: 600; color: #ffb800">${escapeHtml(f.target)}</div>
      <div class="text-muted" style="font-size: 0.68rem">
        Session #${f.session} • Source: ${escapeHtml(f.ip)} • ${new Date(f.timestamp).toLocaleTimeString()}
      </div>
    </div>
  `).join('');
}

// Sessions Explorer & Keystroke Replay (Panels 16 & 18)
async function loadSessionsTable() {
  try {
    const res = await fetch('/api/sessions');
    const sessions = await res.json();
    const tbody = document.getElementById('sessionsTableBody');

    if (!sessions || sessions.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No recorded sessions yet.</td></tr>';
      return;
    }

    tbody.innerHTML = sessions.slice(0, 15).map(s => `
      <tr>
        <td class="text-cyan font-bold">#${s.id}</td>
        <td>${escapeHtml(s.ip)}</td>
        <td>${s.commandCount}</td>
        <td><span class="badge-version">${escapeHtml(s.killChainStage)}</span></td>
        <td>
          <button class="small-btn text-emerald" onclick="openReplayModal(${s.id})">
            ▶ Replay
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.warn('Failed to load sessions:', err);
  }
}

// Modal Replay Inspector (Panel 18)
window.openReplayModal = async function(sessionId) {
  try {
    const res = await fetch(`/api/sessions/${sessionId}`);
    const s = await res.json();
    if (!s) return;

    document.getElementById('modalSessionTitle').textContent = `SESSION #${s.id} KEYSTROKE REPLAY`;
    document.getElementById('modalSessionSubtitle').textContent = `Source IP: ${s.ip} • Family: ${s.botnetFamily || 'Unclassified'} • Commands: ${s.commandCount}`;

    const replayBody = document.getElementById('replayTerminal');
    replayBody.innerHTML = '';

    // Render header
    replayBody.innerHTML += `<div class="system-msg">[REPLAY] SSH Connection opened from ${s.ip} at ${new Date(s.startTime).toLocaleString()}</div>`;

    if (s.authAttempts && s.authAttempts.length > 0) {
      s.authAttempts.forEach(auth => {
        replayBody.innerHTML += `<div class="terminal-line"><span class="text-amber">🔑 AUTH:</span> user='${escapeHtml(auth.username)}' pass='${escapeHtml(auth.password)}' -> SUCCESS</div>`;
      });
    }

    replayBody.innerHTML += `<div class="system-msg">[SHELL SPAWNED] root@ubuntu:~#</div>`;

    // Render commands
    s.commands.forEach((c, idx) => {
      setTimeout(() => {
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = `<span class="term-time">[#${idx + 1}]</span> <span class="term-prompt">root@ubuntu:~#</span> <span class="term-cmd font-bold">${escapeHtml(c.command)}</span>`;
        replayBody.appendChild(line);
        replayBody.scrollTop = replayBody.scrollHeight;
      }, idx * 100);
    });

    document.getElementById('replayModal').classList.add('active');
  } catch (err) {
    console.error('Replay error:', err);
  }
};

// 47-Pattern Threat Taxonomy Explorer (Panel 19)
function renderTaxonomyExplorer() {
  const grid = document.getElementById('taxonomyGrid');
  const tax = appState.taxonomy;
  const hits = appState.patternHits || {};
  const search = (document.getElementById('taxonomySearch').value || '').toLowerCase();

  const keys = Object.keys(tax);
  if (keys.length === 0) return;

  grid.innerHTML = keys
    .filter(k => {
      const p = tax[k];
      return !search || p.name.toLowerCase().includes(search) || p.id.toLowerCase().includes(search) || p.category.toLowerCase().includes(search);
    })
    .map(k => {
      const p = tax[k];
      const count = hits[p.id] || 0;
      const isHit = count > 0;
      const sevColor = p.severity === 'CRITICAL' ? 'var(--crimson)' :
                       p.severity === 'HIGH' ? '#ff7700' :
                       p.severity === 'MEDIUM' ? 'var(--amber)' : 'var(--cyan)';

      return `
        <div class="tax-card ${isHit ? 'hit' : ''}">
          <div class="tax-header">
            <span class="tax-id">${p.id}</span>
            <span style="color: ${sevColor}; font-weight: 700">${p.severity}</span>
          </div>
          <div class="tax-name">${p.name}</div>
          <div class="tax-cat">${p.category} • ${p.mitre || ''}</div>
          ${isHit ? `<div class="badge-version text-emerald" style="margin-top:4px">Triggered ${count}x</div>` : ''}
        </div>
      `;
    }).join('');
}

// Ingestion Velocity Canvas Graph (Panel 12)
function drawVelocityCanvas() {
  const canvas = document.getElementById('velocityCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  document.getElementById('velocityRateText').textContent = `${(appState.currentVelocity / 2).toFixed(1)} eps`;

  ctx.clearRect(0, 0, w, h);

  const data = appState.velocityData;
  const max = Math.max(...data, 4);
  const step = w / (data.length - 1);

  // Draw gradient area
  ctx.beginPath();
  ctx.moveTo(0, h);
  data.forEach((val, i) => {
    const x = i * step;
    const y = h - (val / max) * (h - 10);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.lineTo(w, h);
  ctx.closePath();

  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(0, 240, 255, 0.4)');
  grad.addColorStop(1, 'rgba(0, 240, 255, 0.0)');
  ctx.fillStyle = grad;
  ctx.fill();

  // Draw stroke line
  ctx.beginPath();
  data.forEach((val, i) => {
    const x = i * step;
    const y = h - (val / max) * (h - 10);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#00f0ff';
  ctx.lineWidth = 2;
  ctx.stroke();
}

// Utility: HTML Escaper
function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#039;');
}

// ---------------------------------------------------------------------
// Event Listeners & Interactive Controls
// ---------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initWebSocket();

  // Live TCP Command Injector Handler
  const injectCmdInput = document.getElementById('injectCmd');
  const injectIpInput = document.getElementById('injectIp');
  const btnInjectTcp = document.getElementById('btnInjectTcp');

  const executeInjection = async (cmd) => {
    const commandText = cmd || injectCmdInput.value.trim();
    if (!commandText) return;

    btnInjectTcp.disabled = true;
    btnInjectTcp.textContent = 'Transmitting...';

    try {
      await fetch('/api/inject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: commandText,
          ip: injectIpInput.value.trim() || '192.168.1.105'
        })
      });
      injectCmdInput.value = '';
    } catch (err) {
      console.error('Injection error:', err);
    } finally {
      setTimeout(() => {
        btnInjectTcp.disabled = false;
        btnInjectTcp.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> Inject via TCP:5000`;
      }, 300);
    }
  };

  btnInjectTcp.addEventListener('click', () => executeInjection());
  injectCmdInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') executeInjection();
  });

  // Quick Payload Presets
  document.querySelectorAll('.preset-tag').forEach(tag => {
    tag.addEventListener('click', () => {
      const cmd = tag.getAttribute('data-cmd');
      injectCmdInput.value = cmd;
      executeInjection(cmd);
    });
  });

  // Simulator Trigger Button
  document.getElementById('btnLaunchSim').addEventListener('click', async () => {
    const profile = document.getElementById('simProfileSelect').value;
    const btn = document.getElementById('btnLaunchSim');
    btn.disabled = true;
    btn.innerHTML = '⚡ Transmitting TCP Wave...';

    try {
      await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile })
      });
    } catch (err) {
      console.error('Simulator trigger failed:', err);
    }

    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg> Simulate Wave`;
    }, 4500);
  });

  // Sound Toggle
  document.getElementById('btnSoundToggle').addEventListener('click', () => {
    appState.soundEnabled = !appState.soundEnabled;
    document.getElementById('soundIcon').textContent = appState.soundEnabled ? '🔊' : '🔇';
    if (appState.soundEnabled) playCyberBeep(false);
  });

  // Clear Logs
  document.getElementById('btnClearLogs').addEventListener('click', async () => {
    if (confirm('Are you sure you want to clear all telemetry and session logs?')) {
      await fetch('/api/clear', { method: 'POST' });
    }
  });

  // Clear Terminal Button
  document.getElementById('btnClearTerminal').addEventListener('click', () => {
    document.getElementById('terminalOutput').innerHTML = '';
  });

  // Taxonomy Search Input
  document.getElementById('taxonomySearch').addEventListener('input', () => {
    renderTaxonomyExplorer();
  });

  // Modal Close Handlers
  const closeModal = () => document.getElementById('replayModal').classList.remove('active');
  document.getElementById('modalCloseBtn').addEventListener('click', closeModal);
  document.getElementById('modalCloseFooterBtn').addEventListener('click', closeModal);
  document.getElementById('modalBackdrop').addEventListener('click', closeModal);
});
