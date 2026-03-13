// ============================================================================
// Real-time WebSocket Event Stream
// Zero-dependency WebSocket server for live metrics/events
// ============================================================================

import * as http from 'http';
import * as crypto from 'crypto';
import { Logger } from '../utils/logger';
import type { AntiDDoSShield, BlockEvent } from '../core/shield';

const log = new Logger('WSStream');

export interface WSStreamConfig {
  enabled: boolean;
  metricsIntervalMs: number;  // How often to push metrics (default: 1000ms)
  maxClients: number;         // Max concurrent WS clients
  path: string;               // WebSocket upgrade path
}

export const DEFAULT_WS_CONFIG: WSStreamConfig = {
  enabled: true,
  metricsIntervalMs: 1000,
  maxClients: 50,
  path: '/shield-ws',
};

interface WSClient {
  socket: import('net').Socket;
  subscriptions: Set<string>;
  lastPing: number;
}

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export class WSStream {
  private readonly config: WSStreamConfig;
  private clients: Map<string, WSClient> = new Map();
  private metricsTimer: ReturnType<typeof setInterval> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private shield: AntiDDoSShield | null = null;
  private lastEventIndex = 0;

  private stats = {
    totalConnections: 0,
    messagesSent: 0,
    activeClients: 0,
  };

  constructor(config: WSStreamConfig) {
    this.config = config;
  }

  /**
   * Attach to HTTP server for WebSocket upgrade
   */
  attach(server: http.Server, shield: AntiDDoSShield): void {
    if (!this.config.enabled) return;
    this.shield = shield;

    server.on('upgrade', (req, rawSocket, head) => {
      const socket = rawSocket as import('net').Socket;
      const url = req.url ?? '';
      if (!url.startsWith(this.config.path)) return;

      const key = req.headers['sec-websocket-key'];
      if (!key) { socket.destroy(); return; }

      if (this.clients.size >= this.config.maxClients) {
        socket.write('HTTP/1.1 503 Too Many Connections\r\n\r\n');
        socket.destroy();
        return;
      }

      // Complete WebSocket handshake
      const accept = crypto.createHash('sha1')
        .update(key + WS_GUID).digest('base64');

      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
      );

      const clientId = crypto.randomBytes(8).toString('hex');
      const client: WSClient = {
        socket,
        subscriptions: new Set(['metrics', 'events']), // default subscriptions
        lastPing: Date.now(),
      };
      this.clients.set(clientId, client);
      this.stats.totalConnections++;
      this.stats.activeClients = this.clients.size;

      log.debug(`WS client connected: ${clientId}`);

      // Handle incoming frames
      socket.on('data', (data: Buffer) => {
        try { this.handleFrame(clientId, data); } catch { /* ignore malformed */ }
      });

      socket.on('close', () => {
        this.clients.delete(clientId);
        this.stats.activeClients = this.clients.size;
      });

      socket.on('error', () => {
        this.clients.delete(clientId);
        this.stats.activeClients = this.clients.size;
      });

      // Send welcome message
      this.sendToClient(client, JSON.stringify({
        type: 'welcome',
        subscriptions: Array.from(client.subscriptions),
        server: 'Shield Guard WSStream',
      }));
    });

    // Start metrics broadcast
    this.metricsTimer = setInterval(() => this.broadcastMetrics(), this.config.metricsIntervalMs);
    this.metricsTimer.unref();

    // Ping/pong keepalive
    this.pingTimer = setInterval(() => this.pingClients(), 30000);
    this.pingTimer.unref();

    log.info(`WebSocket stream ready at ${this.config.path}`);
  }

  /**
   * Broadcast a block event to all subscribed clients
   */
  broadcastEvent(event: BlockEvent): void {
    const msg = JSON.stringify({ type: 'event', data: event });
    for (const client of this.clients.values()) {
      if (client.subscriptions.has('events')) {
        this.sendToClient(client, msg);
      }
    }
  }

  /**
   * Broadcast an anomaly alert
   */
  broadcastAnomaly(data: Record<string, unknown>): void {
    const msg = JSON.stringify({ type: 'anomaly', data });
    for (const client of this.clients.values()) {
      if (client.subscriptions.has('anomaly')) {
        this.sendToClient(client, msg);
      }
    }
  }

  private broadcastMetrics(): void {
    if (!this.shield || this.clients.size === 0) return;

    const metrics = this.shield.getMetrics();
    const msg = JSON.stringify({ type: 'metrics', data: metrics, ts: Date.now() });

    for (const client of this.clients.values()) {
      if (client.subscriptions.has('metrics')) {
        this.sendToClient(client, msg);
      }
    }

    // Also push new events since last broadcast
    const events = this.shield.getRecentEvents(10);
    if (events.length > 0 && events[0].ts > this.lastEventIndex) {
      this.lastEventIndex = events[0].ts;
      for (const event of events) {
        this.broadcastEvent(event);
      }
    }
  }

  private handleFrame(clientId: string, data: Buffer): void {
    if (data.length < 2) return;

    const opcode = data[0] & 0x0F;
    const masked = (data[1] & 0x80) !== 0;
    let payloadLength = data[1] & 0x7F;
    let offset = 2;

    if (payloadLength === 126) {
      payloadLength = data.readUInt16BE(2);
      offset = 4;
    } else if (payloadLength === 127) {
      // Skip very large frames
      return;
    }

    if (masked) {
      const mask = data.slice(offset, offset + 4);
      offset += 4;
      const payload = data.slice(offset, offset + payloadLength);
      for (let i = 0; i < payload.length; i++) {
        payload[i] ^= mask[i % 4];
      }

      if (opcode === 0x01) { // Text frame
        try {
          const msg = JSON.parse(payload.toString('utf8'));
          this.handleMessage(clientId, msg);
        } catch { /* ignore */ }
      } else if (opcode === 0x08) { // Close
        const client = this.clients.get(clientId);
        if (client) {
          client.socket.destroy();
          this.clients.delete(clientId);
          this.stats.activeClients = this.clients.size;
        }
      } else if (opcode === 0x0A) { // Pong
        const client = this.clients.get(clientId);
        if (client) client.lastPing = Date.now();
      }
    }
  }

  private handleMessage(clientId: string, msg: { action?: string; topics?: string[] }): void {
    const client = this.clients.get(clientId);
    if (!client) return;

    if (msg.action === 'subscribe' && Array.isArray(msg.topics)) {
      for (const topic of msg.topics) {
        if (['metrics', 'events', 'anomaly'].includes(topic)) {
          client.subscriptions.add(topic);
        }
      }
    } else if (msg.action === 'unsubscribe' && Array.isArray(msg.topics)) {
      for (const topic of msg.topics) {
        client.subscriptions.delete(topic);
      }
    }
  }

  private sendToClient(client: WSClient, data: string): void {
    try {
      const payload = Buffer.from(data, 'utf8');
      const frame = this.buildFrame(payload);
      client.socket.write(frame);
      this.stats.messagesSent++;
    } catch { /* client may have disconnected */ }
  }

  private buildFrame(payload: Buffer): Buffer {
    const len = payload.length;
    let header: Buffer;

    if (len < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x81; // FIN + text opcode
      header[1] = len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x81;
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x81;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }

    return Buffer.concat([header, payload]);
  }

  private pingClients(): void {
    const now = Date.now();
    for (const [id, client] of this.clients) {
      if (now - client.lastPing > 60000) {
        client.socket.destroy();
        this.clients.delete(id);
        continue;
      }
      // Send ping frame
      try {
        const ping = Buffer.alloc(2);
        ping[0] = 0x89; // FIN + ping opcode
        ping[1] = 0;
        client.socket.write(ping);
      } catch {
        this.clients.delete(id);
      }
    }
    this.stats.activeClients = this.clients.size;
  }

  getStats() {
    return { ...this.stats };
  }

  destroy(): void {
    if (this.metricsTimer) clearInterval(this.metricsTimer);
    if (this.pingTimer) clearInterval(this.pingTimer);
    for (const client of this.clients.values()) {
      client.socket.destroy();
    }
    this.clients.clear();
  }
}
