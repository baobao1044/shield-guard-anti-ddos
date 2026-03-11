# Shield Guard

Shield Guard is a Node.js anti-DDoS reverse proxy for websites and APIs. It sits in front of your origin server, inspects traffic across L3, L4, and L7, and forwards clean requests to your backend through `http-proxy`.

## What it does

- Reverse proxies traffic to your origin server
- Applies layered protection at L3, L4, and L7
- Blocks common SQLi, XSS, path traversal, and command injection payloads
- Enforces global, per-IP, and per-endpoint rate limits
- Detects suspicious bots and can escalate to challenge mode
- Supports Under Attack Mode (UAM) with a browser proof-of-work challenge
- Exposes a dashboard, JSON APIs, and a health endpoint
- Includes optional HTTP/2 rapid reset detection, Slowloris protection, and TLS guard
- Ships with a terminal live monitor (`dstat`) and a bash test suite

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

## Development

Run from TypeScript source:

```bash
npm run dev -- --target http://localhost:3000 --port 8080
```

Build a bundled production file:

```bash
npm run build
```

## Configuration

Shield Guard reads `shield.config.json` if present. CLI flags override file config.

Create a config from the example:

```bash
cp shield.config.json.example shield.config.json
```

Example:

```json
{
  "target": "http://localhost:3000",
  "port": 80,
  "httpsPort": 443,
  "tls": {
    "selfSigned": true
  },
  "dashboardPassword": "changeme123",
  "shield": {
    "global": {
      "adaptiveMode": true,
      "emergencyThreshold": 100000,
      "whitelistIPs": []
    },
    "l3": {
      "enabled": true
    },
    "l4": {
      "enabled": true
    },
    "l7": {
      "enabled": true
    }
  }
}
```

Important config areas:

- `target`: upstream origin to proxy to
- `port`: HTTP listen port
- `httpsPort`: optional HTTPS listen port
- `tls`: TLS cert/key paths or `selfSigned: true`
- `dashboardPassword`: enables basic auth for dashboard and API routes
- `shield.global`: adaptive mode, emergency threshold, whitelist
- `shield.l3`: spoofing, packet size, ICMP/IP rate limits, reputation
- `shield.l4`: SYN flood, UDP flood, connection limits, port scan detection
- `shield.l7`: request rate limiting, WAF, bot detection, header validation
- `uam`: proof-of-work challenge settings and auto-activation threshold
- `http2`: HTTP/2 enablement and rapid reset limits
- `slowloris`: socket/header timeout protection
- `tlsGuard`: TLS handshake anomaly controls

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
- `--dstat-only <url>` run only the live monitor against an existing Shield Guard instance
- `--dstat-refresh <seconds>` dstat refresh interval
- `--help` show usage

## Internal routes

These routes are handled by Shield Guard itself:

- `/shield-health` health JSON
- `/shield-dashboard` dashboard UI
- `/shield-api/metrics` metrics JSON
- `/shield-api/stats` summarized stats
- `/shield-api/events` recent blocked events
- `/shield-api/uam/on` enable UAM
- `/shield-api/uam/off` disable UAM
- `/shield-demo` built-in playground/demo page

## Under Attack Mode

UAM works like a lightweight browser challenge:

- suspicious traffic can be escalated from normal filtering to challenge mode
- clients solve a SHA-256 proof-of-work in the browser
- successful clients receive a clearance cookie
- exempt paths such as health and dashboard APIs can bypass challenge flow

It can be activated manually through the API or automatically once request rate crosses the configured threshold.

## HTTP/2 protection

When `http2.enabled` is turned on, Shield Guard starts an HTTP/2 server with:

- per-session stream limits
- rapid reset detection for abusive `RST_STREAM` behavior
- per-IP blocking for repeated reset abuse
- HTTP/1.1 fallback via `allowHTTP1`

## Live monitor

Start Shield Guard with:

```bash
node shield.js --target http://localhost:3000 --port 8080 --dstat
```

Or monitor an already running instance:

```bash
node shield.js --dstat-only http://localhost:8080
```

The terminal monitor reads Shield Guard metrics and recent events from the internal JSON API.

## Testing

The repo includes a bash test suite that:

- builds the project
- starts a local backend
- starts Shield Guard
- verifies proxying, dashboard routes, WAF rules, UAM toggling, and metrics
- optionally runs a simple benchmark

Run it with:

```bash
bash test.sh
bash test.sh --benchmark
```

## Project layout

```text
src/
  core/        core types, defaults, shield engine
  dashboard/   dashboard UI and API handlers
  demo/        built-in demo page
  layers/      L3/L4/L7 filters, UAM, TLS, Slowloris
  proxy/       HTTP and HTTP/2 proxy servers
  stats/       terminal live monitor
  utils/       logger and data structures
```

## License

MIT
