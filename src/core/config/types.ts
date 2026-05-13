import type { ServerConfig } from '../types';

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends Array<infer U>
    ? U[]
    : T[K] extends (...args: never[]) => unknown
      ? T[K]
      : T[K] extends object
        ? DeepPartial<T[K]>
        : T[K];
};

export interface SecurityAuditEntry {
  name: string;
  enabled: boolean;
  enforced: boolean;
  detail: string;
  blocking: boolean;
}

export interface CompileConfigInput {
  fileConfig?: DeepPartial<ServerConfig>;
  cliOverrides?: DeepPartial<ServerConfig>;
  environment?: NodeJS.ProcessEnv;
}

export interface CompileConfigResult {
  config: Readonly<ServerConfig>;
  audit: SecurityAuditEntry[];
}
