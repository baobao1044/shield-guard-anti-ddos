# Shield Guard

[![CI](https://github.com/baobao1044/shield-guard-anti-ddos/actions/workflows/ci.yml/badge.svg)](https://github.com/baobao1044/shield-guard-anti-ddos/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A high-performance Node.js reverse proxy with intelligent anti-DDoS, anti-abuse, and security controls. Shield Guard sits in front of your origin, inspects traffic through layered defenses, and forwards clean requests via `http-proxy`.

## Features

### Core Protection
- **Layered defense** — L3 (IP reputation), L4 (connection), L7 (application) filters
- **WAF** — blocks SQLi, XSS, path traversal, command injection (33 regex patterns)
- **Rate limiting** — global, per-IP (token bucket), and per-endpoint
- **Bot detection** — user-agent analysis, request fingerprinting, timing analysis
- **Under Attack Mode** — SHA-256 proof-of-work browser challenge (like Cloudflare UAM)

### Advanced Security *(NEW)*
- **🧠 Anomaly Detection Engine** — EMA-based traffic baseline learning with z-score alerting. Auto-detects zero-day attack patterns without signatures
- **🔏 JA3 TLS Fingerprinting** — identifies bot frameworks by TLS handshake characteristics. Detects User-Agent spoofing
- **🍯 Honeypot + Tarpit** — traps attackers with fake paths (`/admin`, `/.env`, `/wp-login.php`...) and slow-drip responses to waste their resources
- **🌍 GeoIP Intelligence** — country-level IP geolocation with block/challenge/allow per country (zero-dependency, embedded lookup table)
- **🔗 Request Correlation Engine** — detects coordinated botnet attacks by hashing request behavior signatures across multiple IPs
- **⚡ Real-time WebSocket Stream** — live metrics and event push at `/shield-ws` (zero-dependency WebSocket server)

### Infrastructure
- **HTTP/2** with rapid reset detection
- **Slowloris protection** at socket level
- **TLS guard** for handshake abuse
- **Dashboard** with JSON APIs and health endpoint
- **Terminal live monitor** (`dstat`)
- **Single-file deployment** via esbuild (one `shield.js` bundle)

## What this is not

- Not a kernel firewall or packet-filter appliance
- Not a replacement for upstream network-layer DDoS mitigation from your CDN, edge, or host
- Not able to inspect raw TCP/IP packet fields unless those signals are exposed through Node server APIs

## Requirements

- Node.js 18+
- npm

## Quick start

```bash
npm install
npm run build
node shield.js --target http://localhost:3000 --port 8080
```

Then open:

- Dashboard: `http://localhost:8080/shield-dashboard`
- Health check: `http://localhost:8080/shield-health`
- Demo page: `http://localhost:8080/shield-demo`
- WebSocket: `ws://localhost:8080/shield-ws`

## Development

Run from TypeScript source:

```bash
npm run dev -- --target http://localhost:3000 --port 8080
```

Build a bundled production file:

```bash
npm run build
```

Run validation locally:

```bash
npm test
```

## Configuration

Shield Guard reads `shield.config.json` if present. CLI flags override file config. Configuration is validated at startup; invalid values fail fast with a clear error.

Create a config from the example:

```bash
cp shield.config.json.example shield.config.json
```

### Full example

```json
{
  "target": "http://localhost:3000",
  "port": 8080,
  "dashboardPassword": "changeme123",
  "shield": {
    "global": {
      "adaptiveMode": true,
      "emergencyThreshold": 100000,
      "whitelistIPs": []
    },
    "l7": {
      "enabled": true,
      "rateLimiting": {
        "global": { "windowMs": 1000, "maxRequests": 50000 },
        "perIP": { "maxRequests": 200, "windowMs": 1000, "burstSize": 500 },
        "perEndpoint": { "windowMs": 1000, "maxRequests": 1000 }
      },
      "waf": {
        "enabled": true,
        "sqlInjection": true,
        "xss": true,
        "pathTraversal": true,
        "commandInjection": true
      },
      "botDetection": {
        "enabled": true,
        "challengeThreshold": 50,
        "fingerprintAnalysis": true
      },
      "headerValidation": {
        "enabled": true,
        "requiredHeaders": ["host"],
        "maxHeaders": 100,
        "maxHeaderSize": 16384
      }
    }
  },
  "uam": {
    "enabled": false,
    "difficulty": 4,
    "cookieTTLSeconds": 3600,
    "autoActivateThreshold": 5000,
    "exemptPaths": ["/shield-health", "/shield-api/"]
  },
  "anomaly": {
    "enabled": true,
    "learningPeriodMs": 1800000,
    "zScoreThreshold": 3.0,
    "criticalZScoreThreshold": 5.0
  },
  "tarpit": {
    "enabled": true,
    "honeypotPaths": ["/admin", "/wp-admin", "/wp-login.php", "/.env", "/.git/config", "/phpMyAdmin"],
    "tarpitEnabled": true,
    "tarpitBytesPerSecond": 1,
    "tarpitMaxDurationMs": 60000,
    "autoBlacklistOnHoneypot": true
  },
  "correlation": {
    "enabled": true,
    "minIPsForCorrelation": 5,
    "autoBlockThreshold": 20,
    "botScoreBoost": 30
  },
  "ja3": {
    "enabled": true,
    "mismatchScoreBoost": 40,
    "blockUnknownFingerprints": false
  },
  "geoip": {
    "enabled": false,
    "blockedCountries": [],
    "allowedCountries": [],
    "challengeCountries": []
  },
  "wsStream": {
    "enabled": true,
    "metricsIntervalMs": 1000,
    "maxClients": 50,
    "path": "/shield-ws"
  }
}
```

### Config reference

| Section | Description |
|---------|-------------|
| `target` | Upstream origin URL to proxy to |
| `port` | HTTP listen port |
| `httpsPort` | Optional HTTPS listen port |
| `tls` | TLS cert/key paths or `selfSigned: true` |
| `dashboardPassword` | Basic auth for dashboard and API routes |
| `shield.global` | Adaptive mode, emergency threshold, IP whitelist |
| `shield.l3` | IP reputation and source heuristics |
| `shield.l4` | Connection/session heuristics and slow request controls |
| `shield.l7` | Rate limiting, WAF, bot detection, header validation |
| `uam` | Proof-of-work challenge settings and auto-activation |
| `anomaly` | Traffic baseline learning and z-score anomaly detection |
| `tarpit` | Honeypot paths and slow-drip tarpit settings |
| `correlation` | Coordinated attack detection thresholds |
| `ja3` | TLS fingerprinting and UA mismatch scoring |
| `geoip` | Country-level blocking, challenge, allow lists |
| `wsStream` | WebSocket real-time streaming settings |
| `http2` | HTTP/2 enablement and rapid reset limits |
| `slowloris` | Socket/header timeout protection |
| `tlsGuard` | TLS handshake anomaly controls |

## CLI

```bash
node shield.js [options]
node shield.js --config shield.config.json
```

Flags:

- `--target <url>` target origin server
- `--port <n>` HTTP port
- `--https-port <n>` HTTPS port
- `--cert <path>` TLS certificate file
- `--key <path>` TLS private key file
- `--self-signed` generate a self-signed certificate
- `--password <pass>` dashboard password
- `--config <path>` config file path
- `--dstat` start live terminal monitor after proxy starts
- `--dstat-only <url>` run only the live monitor against an existing instance
- `--dstat-refresh <seconds>` dstat refresh interval
- `--help` show usage

## Internal routes

| Route | Description |
|-------|-------------|
| `/shield-health` | Health JSON |
| `/shield-dashboard` | Dashboard UI |
| `/shield-api/metrics` | Metrics JSON |
| `/shield-api/stats` | Layer stats (L3, L4, L7, anomaly, correlation, GeoIP) |
| `/shield-api/events` | Recent blocked events |
| `/shield-api/uam/on` | Enable UAM |
| `/shield-api/uam/off` | Disable UAM |
| `/shield-demo` | Built-in playground/demo page |
| `/shield-ws` | WebSocket real-time stream |

## Under Attack Mode

UAM works like a lightweight browser challenge:

- Suspicious traffic can be escalated from normal filtering to challenge mode
- Clients solve a SHA-256 proof-of-work in the browser
- Successful clients receive a clearance cookie
- Exempt paths such as health and dashboard APIs can bypass challenge flow

It can be activated manually through the API or automatically once request rate crosses the configured threshold.

## Anomaly Detection

The anomaly engine learns your normal traffic patterns during a configurable learning period (default: 30 minutes), then detects deviations using z-scores across multiple metrics:

- **RPS** — requests per second spikes or drops
- **Unique IPs** — sudden surge or concentration of source IPs
- **Payload size** — abnormal request body sizes
- **Error rate** — spike in blocked requests
- **Endpoint entropy** — many requests hitting the same path (Shannon entropy drop)

When composite anomaly score exceeds thresholds, the engine suggests escalation: tighten rate limits → activate UAM → emergency mode.

## Honeypot + Tarpit

The tarpit system operates before the shield engine processes requests:

1. **Honeypot**: Configurable fake paths that real users would never visit (`/admin`, `/.env`, `/wp-login.php`, etc.). Any client hitting these gets auto-blacklisted and intel is logged
2. **Tarpit**: Instead of an instant 403, blocked requests receive a slow-drip response at ~1 byte/second, wasting the attacker's connection resources

## Request Correlation

The correlation engine detects coordinated botnet attacks:

1. Each request is hashed into a **behavior signature** (method + normalized path + header keys + UA family)
2. When the same signature appears from ≥N distinct IPs within a time window → coordinated attack detected
3. All IPs sharing the signature get a bot score boost and can be auto-blacklisted

## JA3 TLS Fingerprinting

When HTTPS is enabled, Shield Guard extracts TLS fingerprints from secure connections:

- Classifies clients by their negotiated TLS parameters
- Detects mismatches between TLS fingerprint and claimed User-Agent (e.g., Python script claiming to be Chrome)
- Mismatched clients receive a bot score boost in L7 detection

## GeoIP Intelligence

Country-level filtering using an embedded zero-dependency IP lookup table:

- `blockedCountries`: block all traffic from specified countries
- `allowedCountries`: allow ONLY traffic from specified countries (overrides blocked)
- `challengeCountries`: route traffic from specified countries through UAM challenge

## WebSocket Stream

Connect to `/shield-ws` for real-time streaming:

```javascript
const ws = new WebSocket('ws://localhost:8080/shield-ws');
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  // msg.type: 'welcome' | 'metrics' | 'event' | 'anomaly'
  console.log(msg);
};

// Subscribe to specific topics
ws.send(JSON.stringify({ action: 'subscribe', topics: ['metrics', 'events', 'anomaly'] }));
```

## HTTP/2 protection

When `http2.enabled` is turned on, Shield Guard starts an HTTP/2 server with:

- Per-session stream limits
- Rapid reset detection for abusive `RST_STREAM` behavior
- Per-IP blocking for repeated reset abuse
- HTTP/1.1 fallback via `allowHTTP1`

## Live monitor

```bash
node shield.js --target http://localhost:3000 --port 8080 --dstat
```

Or monitor an already running instance:

```bash
node shield.js --dstat-only http://localhost:8080
```

## Testing

The primary validation path is cross-platform and uses Node's built-in test runner:

```bash
npm test
```

That command will:

- Build the project
- Run strict TypeScript typechecking
- Run portable Node validation checks for config and startup contracts

An optional deeper smoke flow is also available:

```bash
npm run test:smoke
```

A local attack-lab workflow is also available:

```bash
npm run test:attack
```

A legacy Bash smoke script with optional benchmarking:

```bash
bash test.sh
bash test.sh --benchmark
```

## GitHub Actions

This repo ships with three workflows:

- `CI`: runs `typecheck`, `build`, `test`, and `test:smoke` on Ubuntu and Windows
- `Attack Lab`: manual workflow that runs the attack harness, captures `dstat`, and uploads metrics/events/log artifacts
- `Release`: builds `shield.js`, packages a release bundle, and publishes assets on version tags

## Project layout

```text
src/
  core/        core types, defaults, shield engine
  dashboard/   dashboard UI and API handlers
  demo/        built-in demo page
  layers/      L3/L4/L7 filters, UAM, TLS, Slowloris,
               anomaly engine, JA3, tarpit, GeoIP, correlation
  proxy/       HTTP and HTTP/2 proxy servers
  stats/       terminal live monitor, WebSocket stream
  utils/       logger and data structures
```

## License

MIT
