// ============================================================================
// Shield Guard - Entry Point
// ============================================================================

import * as fs from 'fs';
import { AntiDDoSShield } from './core/shield';
import { createProxyServer } from './proxy/server';
import { ServerConfig } from './core/types';
import { Logger } from './utils/logger';
import { startDstat } from './stats/dstat';
import { ConfigValidationError, normalizeServerConfig } from './core/config';

const log = new Logger('Main');

// ============ CLI Argument Parser ============

function parseIntegerFlag(flag: string, value: string | undefined): number {
  if (value === undefined) {
    throw new ConfigValidationError(`${flag} requires a value`);
  }
  if (!/^\d+$/.test(value)) {
    throw new ConfigValidationError(`${flag} must be a positive integer`);
  }
  return Number.parseInt(value, 10);
}

function parseArgs(): Partial<ServerConfig> & { configFile?: string; dstat?: boolean; dstatOnly?: boolean; dstatUrl?: string; dstatRefresh?: number } {
  const args = process.argv.slice(2);
  const result: Partial<ServerConfig> & { configFile?: string; dstat?: boolean; dstatOnly?: boolean; dstatUrl?: string; dstatRefresh?: number } = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    switch (arg) {
      case '--target':   result.target = next; i++; break;
      case '--port':     result.port = parseIntegerFlag('--port', next); i++; break;
      case '--https-port': result.httpsPort = parseIntegerFlag('--https-port', next); i++; break;
      case '--password': result.dashboardPassword = next; i++; break;
      case '--cert':     result.tls = { ...result.tls, cert: next }; i++; break;
      case '--key':      result.tls = { ...result.tls, key: next }; i++; break;
      case '--self-signed': result.tls = { ...result.tls, selfSigned: true }; break;
      case '--config':   result.configFile = next; i++; break;
      case '--dstat':    result.dstat = true; break;
      case '--dstat-only': result.dstatOnly = true; result.dstatUrl = next ?? 'http://localhost:8080'; i++; break;
      case '--dstat-refresh': result.dstatRefresh = parseIntegerFlag('--dstat-refresh', next) * 1000; i++; break;
      case '--help': printHelp(); process.exit(0); break;
    }
  }

  return result;
}

let _parsedArgs: ReturnType<typeof parseArgs> | null = null;
function getParsedArgs() { return (_parsedArgs ??= parseArgs()); }

function loadConfig(): ServerConfig {
  const cli = getParsedArgs();

  // Load from config file if specified or if shield.config.json exists
  let fileConfig: Partial<ServerConfig> = {};
  const configPath = cli.configFile ?? 'shield.config.json';

  if (fs.existsSync(configPath)) {
    try {
      const raw = fs.readFileSync(configPath, 'utf8');
      fileConfig = JSON.parse(raw);
      log.info(`Loaded config from ${configPath}`);
    } catch (e) {
      log.warn(`Failed to parse ${configPath}`, { error: (e as Error).message });
    }
  }

  // CLI args override file config
  const merged: Partial<ServerConfig> = {
    target: cli.target ?? (fileConfig.target as string) ?? 'http://localhost:3000',
    port: cli.port ?? (fileConfig.port as number) ?? 8080,
    httpsPort: cli.httpsPort ?? (fileConfig.httpsPort as number | undefined),
    tls: cli.tls || fileConfig.tls
      ? { ...(fileConfig.tls as ServerConfig['tls'] | undefined), ...(cli.tls ?? {}) }
      : undefined,
    dashboardPassword: cli.dashboardPassword ?? (fileConfig.dashboardPassword as string | undefined),
    shield: (fileConfig as ServerConfig).shield,
    uam: (fileConfig as ServerConfig).uam,
    http2: (fileConfig as ServerConfig).http2,
    slowloris: (fileConfig as ServerConfig).slowloris,
    tlsGuard: (fileConfig as ServerConfig).tlsGuard,
  };

  return normalizeServerConfig(merged);
}

function printHelp(): void {
  console.log(`
\x1b[1m\x1b[36mShield Guard\x1b[0m - Anti-DDoS Reverse Proxy

\x1b[1mUSAGE:\x1b[0m
  node shield.js [options]
  node shield.js --config shield.config.json

\x1b[1mOPTIONS:\x1b[0m
  --target <url>        Target server URL (default: http://localhost:3000)
  --port <n>            HTTP listen port (default: 8080)
  --https-port <n>      HTTPS listen port (e.g. 443)
  --cert <path>         TLS certificate file (.pem)
  --key <path>          TLS private key file (.pem)
  --self-signed         Auto-generate self-signed certificate
  --password <pass>     Dashboard password (default: no auth)
  --config <path>       Config file path (default: shield.config.json)
  --help                Show this help

\x1b[1mEXAMPLES:\x1b[0m
  node shield.js --target http://localhost:3000 --port 80
  node shield.js --target http://localhost:3000 --port 80 --https-port 443 --self-signed
  node shield.js --config shield.config.json

\x1b[1mDASHBOARD:\x1b[0m
  http://localhost:<port>/shield-dashboard
  http://localhost:<port>/shield-health
`);
}

function printBanner(config: ServerConfig): void {
  const hasHttps = !!config.httpsPort;
  console.log(`
\x1b[1m\x1b[36m
  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ███████╗███████║██║█████╗  ██║     ██║  ██║
  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
\x1b[0m\x1b[1m          G U A R D  v1.0.0\x1b[0m

  \x1b[32m→\x1b[0m Target:    ${config.target}
  \x1b[32m→\x1b[0m HTTP:      http://0.0.0.0:${config.port}${hasHttps ? `\n  \x1b[32m→\x1b[0m HTTPS:     https://0.0.0.0:${config.httpsPort}` : ''}
  \x1b[32m→\x1b[0m Dashboard: http://localhost:${config.port}/shield-dashboard
  \x1b[32m→\x1b[0m Health:    http://localhost:${config.port}/shield-health
${config.dashboardPassword ? '  \x1b[33m→\x1b[0m Dashboard password: \x1b[90m[protected]\x1b[0m' : '  \x1b[33m⚠\x1b[0m  Dashboard: \x1b[33mno password set\x1b[0m (use --password)'}
`);
}

function printBannerClean(config: ServerConfig): void {
  const hasHttps = !!config.httpsPort;
  console.log(`
\x1b[1m\x1b[36m
   ____  _     _      _     ____                      _
  / ___|| |__ (_) ___| | __/ ___| _   _  __ _ _ __ __| |
  \\___ \\| '_ \\| |/ _ \\ |/ / |  _ | | | |/ _\` | '__/ _\` |
   ___) | | | | |  __/   <| |_| || |_| | (_| | | | (_| |
  |____/|_| |_|_|\\___|_|\\_\\\\____(_)__,_|\\__,_|_|  \\__,_|
\x1b[0m\x1b[1m          G U A R D  v1.0.0\x1b[0m

  \x1b[32m->\x1b[0m Target:    ${config.target}
  \x1b[32m->\x1b[0m HTTP:      http://0.0.0.0:${config.port}${hasHttps ? `\n  \x1b[32m->\x1b[0m HTTPS:     https://0.0.0.0:${config.httpsPort}` : ''}
  \x1b[32m->\x1b[0m Dashboard: http://localhost:${config.port}/shield-dashboard
  \x1b[32m->\x1b[0m Health:    http://localhost:${config.port}/shield-health
${config.dashboardPassword ? '  \x1b[33m->\x1b[0m Dashboard password: \x1b[90m[protected]\x1b[0m' : '  \x1b[33m!\x1b[0m  Dashboard: \x1b[33mno password set\x1b[0m (use --password)'}
`);
}

// ============ Main ============

function main(): void {
  let cli: ReturnType<typeof parseArgs>;
  try {
    cli = getParsedArgs();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to parse CLI arguments';
    log.error(message);
    process.exit(1);
  }

  // --dstat-only: just show terminal monitor, don't start proxy
  if (cli.dstatOnly) {
    const url = cli.dstatUrl ?? 'http://localhost:8080';
    startDstat(url, cli.dstatRefresh ?? 1000);
    return;
  }

  let config: ServerConfig;
  try {
    config = loadConfig();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid configuration';
    log.error(message);
    process.exit(1);
  }

  printBannerClean(config);

  const shield = new AntiDDoSShield(config.shield);
  const { uam } = createProxyServer(config, shield);

  // Start terminal dstat if --dstat flag
  if (cli.dstat) {
    const url = `http://localhost:${config.port}`;
    setTimeout(() => startDstat(url, cli.dstatRefresh ?? 1000), 500);
  }

  // HTTP/2 server (optional, when http2.enabled = true in config)
  if (config.http2?.enabled) {
    const { createHttp2Server } = require('./proxy/http2-server');
    const { DEFAULT_HTTP2_CONFIG } = require('./proxy/http2-server');
    createHttp2Server(config, { ...DEFAULT_HTTP2_CONFIG, ...config.http2 }, shield, uam);
  }

  // Graceful shutdown
  const shutdown = () => {
    log.info('Shutting down...');
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('uncaughtException', (err) => {
    log.error('Uncaught exception', { message: err.message });
  });
}

main();
