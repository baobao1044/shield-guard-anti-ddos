import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';

const repoRoot = process.cwd();
const shieldEntry = path.join(repoRoot, 'shield.js');
const artifactDir = process.env.SHIELD_ARTIFACT_DIR
  ? path.resolve(process.env.SHIELD_ARTIFACT_DIR)
  : path.join(repoRoot, 'tests', 'artifacts');

async function getFreePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitFor(url, timeoutMs = 8000) {
  const start = Date.now();
  let lastError;
  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
      lastError = new Error(`Unexpected status ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw lastError ?? new Error(`Timed out waiting for ${url}`);
}

function spawnLoggedProcess(command, args, options = {}) {
  return spawn(command, args, {
    cwd: repoRoot,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
}

async function stopProcess(child) {
  if (!child) return;
  if (process.platform === 'win32') {
    if (child.exitCode === null) {
      try {
        execFileSync('taskkill', ['/pid', String(child.pid), '/t', '/f'], { stdio: 'ignore' });
      } catch {
        // ignore: process may already be gone
      }
    }
    return;
  }
  if (child.exitCode === null) {
    child.kill('SIGTERM');
    await Promise.race([
      once(child, 'exit'),
      new Promise((resolve) => setTimeout(resolve, 4000)),
    ]);
    if (child.exitCode === null) {
      child.kill('SIGKILL');
      await once(child, 'exit');
    }
  }
}

async function main() {
  await mkdir(artifactDir, { recursive: true });

  const backendPort = await getFreePort();
  const shieldPort = await getFreePort();
  const tempDir = await mkdtemp(path.join(tmpdir(), 'shield-attack-lab-'));
  const configPath = path.join(tempDir, 'shield.config.json');
  const backendBase = `http://127.0.0.1:${backendPort}`;
  const shieldBase = `http://127.0.0.1:${shieldPort}`;

  const backend = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(Buffer.from(chunk));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      method: req.method,
      url: req.url,
      body: Buffer.concat(chunks).toString('utf8'),
    }));
  });

  const config = {
    target: backendBase,
    port: shieldPort,
    shield: {
      global: {
        adaptiveMode: true,
        emergencyThreshold: 400,
      },
      l3: {
        enabled: true,
        spoofDetection: {
          enabled: true,
          bogonFiltering: false,
        },
      },
      l7: {
        enabled: true,
        rateLimiting: {
          global: { windowMs: 1000, maxRequests: 100 },
          perIP: { maxRequests: 15, windowMs: 1000, burstSize: 20 },
          perEndpoint: { windowMs: 1000, maxRequests: 20 },
        },
        botDetection: {
          enabled: true,
          challengeThreshold: 25,
          fingerprintAnalysis: true,
        },
      },
    },
    uam: {
      enabled: false,
      difficulty: 2,
      cookieTTLSeconds: 600,
      autoActivateThreshold: 150,
      exemptPaths: ['/shield-health', '/shield-api/'],
    },
  };

  let shield;
  let dstat;

  try {
    await writeFile(configPath, JSON.stringify(config, null, 2), 'utf8');

    backend.listen(backendPort, '127.0.0.1');
    await once(backend, 'listening');

    shield = spawnLoggedProcess(process.execPath, [shieldEntry, '--config', configPath]);
    let shieldStdout = '';
    let shieldStderr = '';
    shield.stdout.on('data', (chunk) => { shieldStdout += chunk.toString('utf8'); });
    shield.stderr.on('data', (chunk) => { shieldStderr += chunk.toString('utf8'); });

    await waitFor(`${shieldBase}/shield-health`);

    const dashboardHtml = await fetch(`${shieldBase}/shield-dashboard`).then((response) => response.text());
    assert.match(dashboardHtml, /Shield Guard/i);

    await fetch(`${shieldBase}/hello`).then((response) => response.json());

    const wafPayloads = Array.from({ length: 12 }, (_, index) =>
      fetch(`${shieldBase}/?q=${encodeURIComponent(`1 UNION SELECT password FROM users_${index}`)}`, {
        headers: {
          'user-agent': 'sqlmap/1.0',
          accept: '*/*',
        },
      }),
    );
    await Promise.allSettled(wafPayloads);

    const floodRequests = Array.from({ length: 40 }, () =>
      fetch(`${shieldBase}/login`, {
        headers: {
          'user-agent': 'curl/7.0',
        },
      }),
    );
    await Promise.allSettled(floodRequests);

    let dstatOutput = 'dstat skipped on this platform';
    if (process.platform !== 'win32') {
      dstat = spawnLoggedProcess(process.execPath, [shieldEntry, '--dstat-only', shieldBase]);
      dstat.stdout.on('data', (chunk) => { dstatOutput += chunk.toString('utf8'); });
      dstat.stderr.on('data', (chunk) => { dstatOutput += chunk.toString('utf8'); });
      await new Promise((resolve) => setTimeout(resolve, 2500));
      await stopProcess(dstat);
    }

    const metrics = await fetch(`${shieldBase}/shield-api/metrics`).then((response) => response.json());
    const events = await fetch(`${shieldBase}/shield-api/events?limit=25`).then((response) => response.json());

    assert.ok(metrics.totalPackets > 0, 'expected packets to be recorded');
    assert.ok(
      metrics.totalDropped > 0 || metrics.totalRateLimited > 0 || metrics.totalChallenged > 0,
      'expected attack traffic to trigger a defensive action',
    );
    assert.ok(Array.isArray(events) && events.length > 0, 'expected recent events to be recorded');
    if (process.platform !== 'win32') {
      assert.match(dstatOutput, /Shield Guard|RPS|offline|Current/i);
    }

    await writeFile(path.join(artifactDir, 'attack-metrics.json'), JSON.stringify(metrics, null, 2), 'utf8');
    await writeFile(path.join(artifactDir, 'attack-events.json'), JSON.stringify(events, null, 2), 'utf8');
    await writeFile(path.join(artifactDir, 'shield-stdout.log'), shieldStdout, 'utf8');
    await writeFile(path.join(artifactDir, 'shield-stderr.log'), shieldStderr, 'utf8');
    await writeFile(path.join(artifactDir, 'dstat.log'), dstatOutput, 'utf8');
  } finally {
    await stopProcess(dstat);
    await stopProcess(shield);
    backend.closeAllConnections?.();
    backend.closeIdleConnections?.();
    backend.close(() => {});
    await rm(tempDir, { recursive: true, force: true });
  }

  process.exit(0);
}

main().catch(async (error) => {
  await mkdir(artifactDir, { recursive: true });
  await writeFile(
    path.join(artifactDir, 'attack-failure.log'),
    error instanceof Error ? error.stack ?? error.message : String(error),
    'utf8',
  );
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
