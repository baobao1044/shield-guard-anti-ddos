// ============================================================================
// Plugin System — Hot-reload extensible filter plugins
// Scans plugins/ directory, loads .js modules, supports lifecycle hooks
// ============================================================================

import * as fs from 'fs';
import * as path from 'path';
import * as vm from 'vm';
import { Logger } from '../utils/logger';

const log = new Logger('Plugins');

export interface PluginConfig {
  enabled: boolean;
  pluginDir: string;             // Directory to scan for plugins (default: './plugins')
  hotReload: boolean;            // Watch for file changes
  sandboxed: boolean;            // Run in vm sandbox
  timeoutMs: number;             // Max execution time per hook (default: 100ms)
}

export const DEFAULT_PLUGIN_CONFIG: PluginConfig = {
  enabled: false,
  pluginDir: './plugins',
  hotReload: true,
  sandboxed: true,
  timeoutMs: 100,
};

export interface PluginHookResult {
  action: 'CONTINUE' | 'BLOCK' | 'CHALLENGE' | 'RATE_LIMIT';
  reason?: string;
  metadata?: Record<string, unknown>;
}

export interface PluginDefinition {
  name: string;
  version: string;
  description?: string;
  hooks: {
    onInit?: () => void;
    onRequest?: (req: PluginRequest) => PluginHookResult;
    onBlock?: (event: PluginBlockEvent) => void;
    onDestroy?: () => void;
  };
}

export interface PluginRequest {
  ip: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  userAgent: string;
  timestamp: number;
}

export interface PluginBlockEvent {
  ip: string;
  reason: string;
  layer: string;
  timestamp: number;
}

interface LoadedPlugin {
  definition: PluginDefinition;
  filepath: string;
  loadedAt: number;
}

export class PluginLoader {
  private readonly config: PluginConfig;
  private plugins: Map<string, LoadedPlugin> = new Map();
  private watcher: fs.FSWatcher | null = null;

  private stats = {
    pluginsLoaded: 0,
    hookExecutions: 0,
    hookErrors: 0,
    hookTimeouts: 0,
    lastReload: 0,
  };

  constructor(config: PluginConfig) {
    this.config = config;
  }

  /**
   * Initialize: scan directory, load plugins, optionally start watching
   */
  init(): void {
    if (!this.config.enabled) return;

    const dir = path.resolve(this.config.pluginDir);

    // Create plugins dir if it doesn't exist
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });
        log.info(`Created plugins directory: ${dir}`);
      } catch {
        log.warn(`Could not create plugins directory: ${dir}`);
        return;
      }
    }

    this.scanAndLoad(dir);

    // Hot reload watcher
    if (this.config.hotReload) {
      try {
        this.watcher = fs.watch(dir, (eventType, filename) => {
          if (filename && filename.endsWith('.js')) {
            log.info(`Plugin file changed: ${filename}, reloading...`);
            setTimeout(() => this.scanAndLoad(dir), 500); // Debounce
          }
        });
        this.watcher.unref();
      } catch {
        log.warn('Could not start plugin file watcher');
      }
    }
  }

  /**
   * Execute onRequest hook on all loaded plugins
   */
  executeOnRequest(req: PluginRequest): PluginHookResult {
    if (!this.config.enabled || this.plugins.size === 0) {
      return { action: 'CONTINUE' };
    }

    for (const [name, plugin] of this.plugins) {
      if (!plugin.definition.hooks.onRequest) continue;

      try {
        const start = Date.now();
        const result = plugin.definition.hooks.onRequest(req);
        const elapsed = Date.now() - start;

        this.stats.hookExecutions++;

        if (elapsed > this.config.timeoutMs) {
          this.stats.hookTimeouts++;
          log.warn(`Plugin '${name}' onRequest exceeded timeout (${elapsed}ms)`);
        }

        if (result && result.action !== 'CONTINUE') {
          return { ...result, reason: result.reason || `Blocked by plugin: ${name}` };
        }
      } catch (e) {
        this.stats.hookErrors++;
        log.error(`Plugin '${name}' onRequest error: ${e instanceof Error ? e.message : 'unknown'}`);
      }
    }

    return { action: 'CONTINUE' };
  }

  /**
   * Execute onBlock hook on all loaded plugins
   */
  executeOnBlock(event: PluginBlockEvent): void {
    for (const [name, plugin] of this.plugins) {
      if (!plugin.definition.hooks.onBlock) continue;
      try {
        plugin.definition.hooks.onBlock(event);
      } catch {
        log.error(`Plugin '${name}' onBlock error`);
      }
    }
  }

  private scanAndLoad(dir: string): void {
    let files: string[];
    try {
      files = fs.readdirSync(dir).filter(f => f.endsWith('.js'));
    } catch {
      return;
    }

    // Destroy old plugins
    for (const plugin of this.plugins.values()) {
      try { plugin.definition.hooks.onDestroy?.(); } catch { /* ignore */ }
    }
    this.plugins.clear();

    for (const file of files) {
      const filepath = path.join(dir, file);
      try {
        const pluginDef = this.loadPlugin(filepath);
        if (pluginDef) {
          this.plugins.set(pluginDef.name, {
            definition: pluginDef,
            filepath,
            loadedAt: Date.now(),
          });

          try { pluginDef.hooks.onInit?.(); } catch { /* ignore init errors */ }

          log.info(`Loaded plugin: ${pluginDef.name} v${pluginDef.version}`);
        }
      } catch (e) {
        log.error(`Failed to load plugin ${file}: ${e instanceof Error ? e.message : 'unknown'}`);
      }
    }

    this.stats.pluginsLoaded = this.plugins.size;
    this.stats.lastReload = Date.now();
  }

  private loadPlugin(filepath: string): PluginDefinition | null {
    const code = fs.readFileSync(filepath, 'utf8');

    if (this.config.sandboxed) {
      const sandbox = {
        module: { exports: {} as Record<string, unknown> },
        exports: {} as Record<string, unknown>,
        console: { log: () => {}, warn: () => {}, error: () => {} },
        setTimeout: () => {},
        setInterval: () => {},
        Date,
        Math,
        JSON,
        Array,
        Object,
        String,
        Number,
        RegExp,
        Map,
        Set,
      };

      try {
        const script = new vm.Script(code, { filename: filepath });
        script.runInNewContext(sandbox, { timeout: 5000 });

        const exported = (sandbox.module.exports as Record<string, unknown>) ||
                         (sandbox.exports as Record<string, unknown>);
        return this.validatePlugin(exported);
      } catch (e) {
        log.error(`Sandbox error for ${filepath}: ${e instanceof Error ? e.message : 'unknown'}`);
        return null;
      }
    } else {
      // Direct require (less safe, more compatible)
      delete require.cache[filepath];
      const exported = require(filepath);
      return this.validatePlugin(exported.default || exported);
    }
  }

  private validatePlugin(obj: unknown): PluginDefinition | null {
    if (!obj || typeof obj !== 'object') return null;
    const p = obj as Record<string, unknown>;
    if (typeof p.name !== 'string' || typeof p.version !== 'string') return null;
    if (!p.hooks || typeof p.hooks !== 'object') return null;
    return p as unknown as PluginDefinition;
  }

  getLoadedPlugins(): Array<{ name: string; version: string; loadedAt: number }> {
    return [...this.plugins.values()].map(p => ({
      name: p.definition.name,
      version: p.definition.version,
      loadedAt: p.loadedAt,
    }));
  }

  getStats() {
    return {
      ...this.stats,
      plugins: this.getLoadedPlugins(),
    };
  }

  destroy(): void {
    for (const plugin of this.plugins.values()) {
      try { plugin.definition.hooks.onDestroy?.(); } catch { /* ignore */ }
    }
    this.plugins.clear();
    if (this.watcher) this.watcher.close();
  }
}
