import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const repoRoot = process.cwd();

async function main() {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'shield-guard-smoke-'));
  const configPath = path.join(tempDir, 'shield.config.json');

  try {
    await writeFile(configPath, JSON.stringify({}), 'utf8');

    execFileSync(process.execPath, ['tests/smoke-child.mjs'], {
      cwd: repoRoot,
      stdio: 'inherit',
      timeout: 30000,
      env: {
        ...process.env,
        SHIELD_CONFIG_PATH: configPath,
      },
    });
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
