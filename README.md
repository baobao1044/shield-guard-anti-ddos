# Shield Guard

[![CI](https://github.com/baobao1044/shield-guard-anti-ddos/actions/workflows/ci.yml/badge.svg)](https://github.com/baobao1044/shield-guard-anti-ddos/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A high-performance Node.js reverse proxy with **AI-powered** anti-DDoS, anti-abuse, and zero-trust security controls. Shield Guard sits in front of your origin, inspects traffic through 14 layered defenses, and forwards clean requests via `http-proxy`.

## Architecture

```
Client ─→ [mTLS Gateway] ─→ [Biometric SDK Inject]
       ─→ [Circuit Breaker] ─→ [Traffic Shaper]
       ─→ [Honeypot/Tarpit] ─→ [Threat Intel]
       ─→ [GeoIP] ─→ [L3] ─→ [Correlation]
       ─→ [L7 WAF] ─→ [ML WAF] ─→ [Plugins]
       ─→ [Anomaly Engine] ─→ Origin Server
```

## Feature Overview

### Core Protection
- **Layered defense** — L3 (IP reputation), L4 (connection), L7 (application) filters
- **WAF** — blocks SQLi, XSS, path traversal, command injection (33 regex patterns)
- **Rate limiting** — global, per-IP (token bucket), per-endpoint
- **Bot detection** — user-agent analysis, request fingerprinting, timing analysis
- **Under Attack Mode** — SHA-256 proof-of-work browser challenge

### AI & ML Security
- **🧬 ML WAF** — 3-layer perceptron neural network (22→16→8→1) classifies requests as malicious/benign. Pre-trained weights detect zero-day attacks that regex misses. Self-learning via ensemble with regex WAF
- **🧠 Anomaly Detection** — EMA-based traffic baseline learning with z-score alerting. Auto-detects attack patterns without signatures
- **🔗 Request Correlation** — behavior signature hashing detects coordinated botnet attacks across multiple IPs

### Active Defense
- **🍯 Honeypot + Tarpit** — 16 fake paths trap scanners. Slow-drip responses waste attacker resources at 1 byte/sec
- **🎭 Biometric SDK** — injected JS collects mouse movement, keystroke dynamics, scroll patterns, canvas/WebGL fingerprints. Scores "real human" 0-100. Headless browsers can't fake behavioral biometrics
- **⚡ Circuit Breaker** — CLOSED→OPEN→HALF_OPEN state machine protects backend from cascade failure. Auto-recovery with configurable thresholds
- **📊 Traffic Shaper** — classifies clients (premium/normal/suspicious/bot), per-class token bucket rate limiting

### Intelligence
- **🌐 Threat Intel Feed** — pulls from Emerging Threats, Spamhaus DROP, Feodo Tracker. CIDR + exact IP. Auto-refresh hourly
- **🔏 JA3 TLS Fingerprinting** — identifies bots by TLS handshake. Detects User-Agent spoofing
- **🌍 GeoIP Intelligence** — country-level block/challenge/allow with zero-dependency embedded lookup table
- **🔍 Request Forensics** — ring buffer of 10K blocked requests, HAR export, filtered queries, auto-redact sensitive headers

### Enterprise & Extensibility
- **🔌 Plugin System** — hot-reload `.js` plugins from `plugins/` directory. Sandboxed VM execution. Lifecycle hooks: `onInit`, `onRequest`, `onBlock`, `onDestroy`
- **🔐 mTLS Zero-Trust** — mutual TLS client cert verification, JWT validation (RS256/ES256), API key management with per-key rate limits and path-based permissions
- **⚡ WebSocket Stream** — real-time metrics and event push at `/shield-ws`

### Infrastructure
- **HTTP/2** with rapid reset detection
- **Slowloris protection** at socket level  
- **TLS guard** for handshake abuse
- **Dashboard** with JSON APIs and health endpoint
- **Terminal live monitor** (`dstat`)
- **Single-file deployment** via esbuild (one `shield.js` bundle, ~473KB)

## What this is not

- Not a kernel firewall or packet-filter appliance
- Not a replacement for upstream network-layer DDoS mitigation from your CDN, edge, or host

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

```bash
npm run dev -- --target http://localhost:3000 --port 8080   # TypeScript source
npm run build                                               # Production bundle
npm test                                                    # Validation suite
```

## Configuration

Shield Guard reads `shield.config.json` if present. CLI flags override file config.

```bash
cp shield.config.json.example shield.config.json
```

### Config reference

| Section | Description |
|---------|-------------|
| `target` | Upstream origin URL |
| `port` / `httpsPort` | HTTP / HTTPS listen ports |
| `tls` | TLS cert/key paths or `selfSigned: true` |
| `dashboardPassword` | Basic auth for dashboard and APIs |
| `shield` | L3, L4, L7 filter configs, adaptive mode, whitelist |
| `uam` | Proof-of-work challenge settings |
| `anomaly` | Traffic baseline learning, z-score thresholds |
| `tarpit` | Honeypot paths, tarpit byte rate, auto-blacklist |
| `correlation` | Coordinated attack detection thresholds |
| `ja3` | TLS fingerprinting and UA mismatch scoring |
| `geoip` | Country block/allow/challenge lists |
| `wsStream` | WebSocket streaming settings |
| `mlWaf` | ML WAF threshold, ensemble weight, learning mode |
| `circuitBreaker` | Failure threshold, reset timeout, error rate |
| `trafficShaper` | Per-class rate limits, premium headers/IPs |
| `biometric` | SDK injection, score TTL, human threshold |
| `threatIntel` | Feed URLs, refresh interval, max entries |
| `forensics` | Capture buffer size, body capture, min threat level |
| `plugins` | Plugin directory, hot-reload, sandbox, timeout |
| `zeroTrust` | mTLS, JWT validation, API key management |
| `http2` | HTTP/2 and rapid reset limits |
| `slowloris` | Socket timeout protection |
| `tlsGuard` | TLS handshake anomaly controls |

## CLI

```bash
node shield.js [options]
node shield.js --config shield.config.json
```

| Flag | Description |
|------|-------------|
| `--target <url>` | Target origin server |
| `--port <n>` | HTTP port |
| `--https-port <n>` | HTTPS port |
| `--cert <path>` | TLS certificate |
| `--key <path>` | TLS private key |
| `--self-signed` | Generate self-signed cert |
| `--password <pass>` | Dashboard password |
| `--config <path>` | Config file path |
| `--dstat` | Start live terminal monitor |
| `--dstat-only <url>` | Monitor an existing instance |
| `--help` | Show usage |

## Internal routes

| Route | Description |
|-------|-------------|
| `/shield-health` | Health JSON |
| `/shield-dashboard` | Dashboard UI |
| `/shield-api/metrics` | Metrics JSON (includes all 14 layers) |
| `/shield-api/stats` | Layer stats (L3, L4, L7, anomaly, correlation, GeoIP, ML WAF, threat intel, forensics, plugins) |
| `/shield-api/events` | Recent blocked events |
| `/shield-api/uam/on` | Enable UAM |
| `/shield-api/uam/off` | Disable UAM |
| `/shield-demo` | Built-in playground |
| `/shield-ws` | WebSocket real-time stream |
| `/shield-fp` | Biometric fingerprint endpoint |

## ML WAF

The neural network WAF runs alongside the regex WAF as an ensemble:

1. **Feature extraction** — each request is converted to a 22-dimensional feature vector:
   - URL length, entropy, special char ratio, uppercase ratio, digit ratio
   - Query param count, max param value length
   - Body length, entropy, special char ratio
   - Header count, cookie/referer/accept-language presence
   - Method score, content type score, path depth
   - Dangerous file extension, double encoding
   - SQL keyword density, HTML tag density, shell metachar density

2. **Inference** — 3-layer perceptron (ReLU → ReLU → Sigmoid) produces a 0-1 maliciousness score

3. **Ensemble** — regex WAF verdict + ML score → combined decision. Catches attacks regex misses while reducing false positives

4. **Self-learning** — requests caught by regex are labeled malicious, requests passing all filters labeled benign → continuous weight improvement

## Plugin System

Create `.js` files in the `plugins/` directory:

```javascript
// plugins/custom-rate-limiter.js
module.exports = {
  name: 'Custom Rate Limiter',
  version: '1.0.0',
  hooks: {
    onRequest(req) {
      if (req.url.startsWith('/api/') && !req.headers['x-api-key']) {
        return { action: 'BLOCK', reason: 'API key required' };
      }
      return { action: 'CONTINUE' };
    },
    onBlock(event) {
      console.log(`Blocked: ${event.ip} - ${event.reason}`);
    }
  }
};
```

Plugins support hot-reload — save a file and it's automatically loaded without restart.

## Zero-Trust Gateway

When enabled, the gateway provides layered authentication:

1. **mTLS** — server verifies client certificate (allowed CNs + fingerprints)
2. **JWT** — validates Bearer tokens (expiry, issuer, audience)
3. **API Keys** — per-key rate limits and path-based permissions

## WebSocket Stream

```javascript
const ws = new WebSocket('ws://localhost:8080/shield-ws');
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  // msg.type: 'welcome' | 'metrics' | 'event' | 'anomaly'
};
ws.send(JSON.stringify({
  action: 'subscribe',
  topics: ['metrics', 'events', 'anomaly']
}));
```

## Testing

```bash
npm test                # Full validation (typecheck + build + integration)
npm run test:smoke      # Smoke tests (server startup, proxying, WAF, UAM)
npm run test:attack     # Attack lab (harness + metrics capture)
bash test.sh            # Legacy bash suite with optional benchmarking
bash test.sh --benchmark
```

## GitHub Actions

- `CI`: typecheck, build, test, smoke on Ubuntu + Windows
- `Attack Lab`: manual attack harness with artifact upload
- `Release`: build, package, publish on version tags

## Project layout

```text
src/
  core/        shield engine, types, config, plugin loader
  dashboard/   dashboard UI and API handlers
  demo/        built-in demo/playground page
  layers/      L3/L4/L7 filters, UAM, TLS, Slowloris,
               anomaly, JA3, tarpit, GeoIP, correlation,
               ML WAF, feature extractor, biometric SDK, threat intel
  proxy/       HTTP/HTTP2 proxy, circuit breaker, traffic shaper, mTLS gateway
  stats/       terminal monitor, WebSocket stream, request forensics
  utils/       logger and data structures
```

## License

MIT
