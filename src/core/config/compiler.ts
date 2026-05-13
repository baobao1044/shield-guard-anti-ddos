import type { ServerConfig } from '../types';
import { Logger } from '../../utils/logger';
import { ConfigValidationError } from './errors';
import { DEFAULT_SERVER_CONFIG } from './defaults';
import type {
  CompileConfigInput,
  CompileConfigResult,
  DeepPartial,
  SecurityAuditEntry,
} from './types';
import { normalizeServerConfig } from './validator';

const log = new Logger('ConfigCompiler');

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function cloneValue<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => cloneValue(item)) as T;
  }
  if (isRecord(value)) {
    const clone: JsonRecord = {};
    for (const [key, nested] of Object.entries(value)) {
      clone[key] = cloneValue(nested);
    }
    return clone as T;
  }
  return value;
}

function deepMerge<T>(base: T, override?: DeepPartial<T>): T {
  if (override === undefined) {
    return cloneValue(base);
  }
  if (Array.isArray(base)) {
    return cloneValue((override as T) ?? base);
  }
  if (!isRecord(base) || !isRecord(override)) {
    return cloneValue((override as T) ?? base);
  }

  const result: JsonRecord = {};
  const keys = new Set([...Object.keys(base), ...Object.keys(override)]);
  for (const key of keys) {
    const baseValue = (base as JsonRecord)[key];
    const overrideValue = (override as JsonRecord)[key];
    if (overrideValue === undefined) {
      result[key] = cloneValue(baseValue);
      continue;
    }
    if (baseValue === undefined) {
      result[key] = cloneValue(overrideValue);
      continue;
    }
    result[key] = deepMerge(baseValue, overrideValue as DeepPartial<typeof baseValue>);
  }
  return result as T;
}

function freezeDeep<T>(value: T): T {
  if (Array.isArray(value)) {
    for (const item of value) {
      freezeDeep(item);
    }
  } else if (isRecord(value)) {
    for (const nested of Object.values(value)) {
      freezeDeep(nested);
    }
  }
  return Object.freeze(value);
}

export function getEnvironmentOverrides(env: NodeJS.ProcessEnv = process.env): DeepPartial<ServerConfig> {
  const overrides: DeepPartial<ServerConfig> = {};
  if (env.SHIELD_TARGET) overrides.target = env.SHIELD_TARGET;
  if (env.SHIELD_PORT) overrides.port = Number.parseInt(env.SHIELD_PORT, 10);
  if (env.SHIELD_HTTPS_PORT) overrides.httpsPort = Number.parseInt(env.SHIELD_HTTPS_PORT, 10);
  if (env.SHIELD_DASHBOARD_PASSWORD) overrides.dashboardPassword = env.SHIELD_DASHBOARD_PASSWORD;
  if (env.SHIELD_TLS_CERT || env.SHIELD_TLS_KEY || env.SHIELD_TLS_SELF_SIGNED === 'true') {
    overrides.tls = {
      cert: env.SHIELD_TLS_CERT,
      key: env.SHIELD_TLS_KEY,
      selfSigned: env.SHIELD_TLS_SELF_SIGNED === 'true',
    };
  }
  return overrides;
}

function buildSecurityAudit(config: ServerConfig): SecurityAuditEntry[] {
  const zeroTrust = config.zeroTrust!;
  return [
    {
      name: 'Rate limiting',
      enabled: !!config.shield?.l7?.enabled,
      enforced: !!config.shield?.l7?.enabled,
      detail: config.shield?.l7?.enabled ? 'L7 filter and rate limiting configured' : 'L7 filter disabled',
      blocking: false,
    },
    {
      name: 'JWT verification',
      enabled: !!zeroTrust.enabled && !!zeroTrust.jwt?.enabled,
      enforced: !!zeroTrust.enabled && !!zeroTrust.jwt?.enabled,
      detail: zeroTrust.jwt?.enabled ? `algorithms=${zeroTrust.jwt.algorithms.join(',')}` : 'JWT disabled',
      blocking: false,
    },
    {
      name: 'mTLS',
      enabled: !!zeroTrust.enabled && !!zeroTrust.mtls?.enabled,
      enforced: !!zeroTrust.enabled && !!zeroTrust.mtls?.enabled && !!config.httpsPort,
      detail: zeroTrust.mtls?.enabled ? 'client certificate checks configured' : 'mTLS disabled',
      blocking: !!zeroTrust.enabled && !!zeroTrust.mtls?.enabled && !config.httpsPort,
    },
    {
      name: 'API keys',
      enabled: !!zeroTrust.enabled && !!zeroTrust.apiKeys?.enabled,
      enforced: !!zeroTrust.enabled && !!zeroTrust.apiKeys?.enabled,
      detail: zeroTrust.apiKeys?.enabled ? `${zeroTrust.apiKeys.keys.length} active key(s)` : 'API keys disabled',
      blocking: false,
    },
    {
      name: 'TLS listener',
      enabled: !!config.httpsPort,
      enforced: !!config.httpsPort,
      detail: config.httpsPort ? `httpsPort=${config.httpsPort}` : 'HTTPS listener disabled',
      blocking: false,
    },
    {
      name: 'ML WAF',
      enabled: !!config.mlWaf?.enabled,
      enforced: !!config.mlWaf?.enabled,
      detail: config.mlWaf?.enabled ? `threshold=${config.mlWaf.threshold}` : 'ML WAF disabled',
      blocking: false,
    },
    {
      name: 'Threat intel',
      enabled: !!config.threatIntel?.enabled,
      enforced: !!config.threatIntel?.enabled,
      detail: config.threatIntel?.enabled ? `${config.threatIntel.feeds.length} feed(s)` : 'Threat intel disabled',
      blocking: false,
    },
  ];
}

function assertSecurityReadiness(config: ServerConfig): void {
  const zeroTrust = config.zeroTrust!;
  if (!zeroTrust.enabled) {
    return;
  }

  if (!zeroTrust.mtls.enabled && !zeroTrust.jwt.enabled && !zeroTrust.apiKeys.enabled) {
    throw new ConfigValidationError('zeroTrust.enabled=true requires at least one active control (mtls, jwt, or apiKeys)');
  }

  if (zeroTrust.mtls.enabled && !config.httpsPort) {
    throw new ConfigValidationError('zeroTrust.mtls.enabled=true requires httpsPort');
  }
  if (
    zeroTrust.mtls.enabled &&
    zeroTrust.mtls.allowedCNs.length === 0 &&
    zeroTrust.mtls.allowedFingerprints.length === 0
  ) {
    throw new ConfigValidationError('zeroTrust.mtls.enabled=true requires allowedCNs or allowedFingerprints');
  }

  if (zeroTrust.jwt.enabled) {
    if (!zeroTrust.jwt.issuer) {
      throw new ConfigValidationError('zeroTrust.jwt.issuer is required when JWT verification is enabled');
    }
    if (!zeroTrust.jwt.audience) {
      throw new ConfigValidationError('zeroTrust.jwt.audience is required when JWT verification is enabled');
    }
    if (!zeroTrust.jwt.sharedSecret && !zeroTrust.jwt.jwksUri && zeroTrust.jwt.publicKeys.length === 0) {
      throw new ConfigValidationError('zeroTrust.jwt requires sharedSecret, jwksUri, or publicKeys when enabled');
    }

    const needsSharedSecret = zeroTrust.jwt.algorithms.some((algorithm) => algorithm.startsWith('HS'));
    const needsAsymmetricKeys = zeroTrust.jwt.algorithms.some((algorithm) => !algorithm.startsWith('HS'));

    if (needsSharedSecret && !zeroTrust.jwt.sharedSecret) {
      throw new ConfigValidationError('HS* JWT algorithms require zeroTrust.jwt.sharedSecret');
    }
    if (needsAsymmetricKeys && !zeroTrust.jwt.jwksUri && zeroTrust.jwt.publicKeys.length === 0) {
      throw new ConfigValidationError('Asymmetric JWT algorithms require zeroTrust.jwt.jwksUri or zeroTrust.jwt.publicKeys');
    }
  }

  if (zeroTrust.apiKeys.enabled && zeroTrust.apiKeys.keys.length === 0) {
    throw new ConfigValidationError('zeroTrust.apiKeys.enabled=true requires at least one API key');
  }
}

export function renderSecurityAudit(audit: SecurityAuditEntry[]): string[] {
  return audit.map((entry) => {
    const marker = entry.enforced ? '✓' : entry.enabled ? '!' : '·';
    return `${marker} ${entry.name}: ${entry.detail}`;
  });
}

export function compileServerConfig(input: CompileConfigInput): CompileConfigResult {
  const mergedDefaults = deepMerge(DEFAULT_SERVER_CONFIG, input.fileConfig);
  const mergedEnvironment = deepMerge(mergedDefaults, getEnvironmentOverrides(input.environment));
  const mergedConfig = deepMerge(mergedEnvironment, input.cliOverrides);
  const config = normalizeServerConfig(mergedConfig);

  assertSecurityReadiness(config);
  const audit = buildSecurityAudit(config);
  log.info('Configuration compiled', {
    target: config.target,
    port: config.port,
    httpsPort: config.httpsPort,
    zeroTrust: config.zeroTrust?.enabled,
  });

  return {
    config: freezeDeep(config),
    audit,
  };
}
