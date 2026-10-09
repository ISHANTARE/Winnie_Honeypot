/**
 * Winnie-SOC: High-Reliability TCP Ingestion Server
 * Listens on port 5000 (0.0.0.0) to capture raw telemetry directly from ESP32 WiFiClient
 */
const net = require('net');

class TcpIngestionServer {
  constructor(port = 5000, onEventCallback, onStatusCallback) {
    this.port = port;
    this.host = '0.0.0.0';
    this.onEvent = onEventCallback || (() => {});
    this.onStatus = onStatusCallback || (() => {});
    this.server = null;
    this.lastPacketTime = null;
    this.totalPacketsReceived = 0;
    this.lastConnectedClientIp = null;
  }

  start() {
    this.server = net.createServer((socket) => {
      let buffer = '';
      const remoteAddress = socket.remoteAddress || 'unknown';
      this.lastConnectedClientIp = remoteAddress;
      this.lastPacketTime = new Date().toISOString();

      socket.on('data', (chunk) => {
        buffer += chunk.toString();
      });

      socket.on('end', () => {
        const raw = buffer.trim();
        if (!raw) return;

        try {
          const parsed = JSON.parse(raw);
          this.totalPacketsReceived++;
          this.lastPacketTime = new Date().toISOString();

          // Ensure standard fields
          const event = {
            ip: parsed.ip || remoteAddress,
            session: typeof parsed.session === 'number' ? parsed.session : parseInt(parsed.session) || 1,
            command: parsed.command || '',
            timestamp: new Date().toISOString(),
            source: 'esp32_hardware'
          };

          this.onEvent(event);
          this.onStatus({
            espStatus: 'CONNECTED',
            lastPacketTime: this.lastPacketTime,
            totalPackets: this.totalPacketsReceived,
            lastClientIp: this.lastConnectedClientIp
          });
        } catch (err) {
          console.error('[TCP Ingestion] Failed to parse JSON from ESP32:', err.message);
          console.error('[TCP Ingestion] Raw payload:', raw);
        }
      });

      socket.on('error', (err) => {
        console.warn(`[TCP Ingestion] Socket error: ${err.message}`);
      });
    });

    this.server.listen(this.port, this.host, () => {
      console.log(`[🚀 Winnie-SOC] TCP Ingestion Server listening on 0.0.0.0:${this.port}`);
      console.log(`[📡 Ready] Set your ESP32 logging target to <YOUR_PC_IP>:${this.port}`);
    });

    this.server.on('error', (err) => {
      console.error(`[TCP Server Error]`, err);
    });
  }

  getStatus() {
    const isRecent = this.lastPacketTime && (Date.now() - new Date(this.lastPacketTime).getTime() < 30000);
    return {
      status: isRecent ? 'ONLINE (ACTIVE)' : (this.lastPacketTime ? 'IDLE' : 'WAITING_FOR_DEVICE'),
      port: this.port,
      lastPacketTime: this.lastPacketTime,
      totalPackets: this.totalPacketsReceived,
      lastClientIp: this.lastConnectedClientIp
    };
  }
}

module.exports = TcpIngestionServer;
