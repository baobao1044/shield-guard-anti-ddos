import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';

const repoRoot = process.cwd();
const shieldEntry = 'shield.js';
const configPath = process.env.SHIELD_CONFIG_PATH;

if (!configPath) {
  throw new Error('SHIELD_CONFIG_PATH is required');
}

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
  const backendPort = await getFreePort();
  const shieldPort = await getFreePort();
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

  backend.listen(backendPort, '127.0.0.1');
  await once(backend, 'listening');

  const config = JSON.parse(await readFile(configPath, 'utf8'));
  await writeFile(configPath, JSON.stringify({
    target: backendBase,
    port: shieldPort,
    shield: {
      global: {
        whitelistIPs: ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
      },
    },
    ...config,
  }), 'utf8');

  const shield = spawn(process.execPath, [shieldEntry, '--config', configPath], {
    cwd: repoRoot,
    stdio: ['ignore', 'ignore', 'ignore'],
  });

  try {
    await waitFor(`${shieldBase}/shield-health`);

    const health = await fetch(`${shieldBase}/shield-health`).then((response) => response.json());
    assert.equal(health.status, 'ok');

    const proxyResponse = await fetch(`${shieldBase}/hello`).then((response) => response.json());
    assert.equal(proxyResponse.ok, true);
    assert.equal(proxyResponse.method, 'GET');
    assert.equal(proxyResponse.url, '/hello');

    const metrics = await fetch(`${shieldBase}/shield-api/metrics`).then((response) => response.json());
    assert.equal(typeof metrics.totalPackets, 'number');
    assert.ok(metrics.totalPackets >= 1);

    const uamOn = await fetch(`${shieldBase}/shield-api/uam/on`).then((response) => response.json());
    assert.equal(uamOn.uamActive, true);

    const challengePage = await fetch(`${shieldBase}/`).then((response) => response.text());
    assert.match(challengePage, /Checking your browser/i);

    const uamOff = await fetch(`${shieldBase}/shield-api/uam/off`).then((response) => response.json());
    assert.equal(uamOff.uamActive, false);
  } finally {
    await stopProcess(shield);
    backend.closeAllConnections?.();
    backend.closeIdleConnections?.();
    backend.close(() => {});
  }

  process.exit(0);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
