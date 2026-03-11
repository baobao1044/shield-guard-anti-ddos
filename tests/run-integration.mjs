import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const repoRoot = process.cwd();
const shieldEntry = path.join(repoRoot, 'shield.js');

function runNode(args, options = {}) {
  return execFileSync(process.execPath, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 20000,
    ...options,
  });
}

function expectFailure(args, pattern) {
  try {
    runNode(args);
    throw new Error(`Expected command to fail: ${args.join(' ')}`);
  } catch (error) {
    const stderr = error && typeof error === 'object' && 'stderr' in error ? String(error.stderr) : '';
    const status = error && typeof error === 'object' && 'status' in error ? error.status : 0;
    assert.notEqual(status, 0);
    assert.match(stderr, pattern);
  }
}

async function main() {
  expectFailure([shieldEntry, '--target', 'http://localhost:3000', '--port', 'abc'], /--port must be a positive integer/i);
  console.log('PASS CLI validation rejects invalid port values');

  const tempDir = await mkdtemp(path.join(tmpdir(), 'shield-guard-test-'));
  try {
    const invalidConfig = path.join(tempDir, 'invalid-config.json');
    await writeFile(invalidConfig, JSON.stringify({
      target: 'http://localhost:3000',
      port: 18080,
      httpsPort: 18443,
    }), 'utf8');

    expectFailure([shieldEntry, '--config', invalidConfig], /httpsPort requires tls\.cert\/key or tls\.selfSigned=true/i);
    console.log('PASS config validation rejects https without tls material');

  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }

  console.log('PASS integration suite complete');
}

main().catch((error) => {
  console.error('FAIL integration suite');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
