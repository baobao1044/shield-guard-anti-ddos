// ============================================================================
// Logger - Colored console output
// ============================================================================

const RESET = '\x1b[0m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const GRAY = '\x1b[90m';
const BOLD = '\x1b[1m';

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
type LogLevel = keyof typeof LEVELS;

export class Logger {
  private readonly prefix: string;
  private readonly level: number;

  constructor(prefix: string, level: string = 'info') {
    this.prefix = prefix;
    this.level = LEVELS[level as LogLevel] ?? LEVELS.info;
  }

  private timestamp(): string {
    return new Date().toISOString().replace('T', ' ').substring(0, 19);
  }

  private format(color: string, levelTag: string, msg: string, meta?: object): string {
    const ts = `${GRAY}${this.timestamp()}${RESET}`;
    const tag = `${BOLD}${color}[${this.prefix}]${RESET}`;
    const lvl = `${color}${levelTag}${RESET}`;
    const message = `${msg}`;
    const metaStr = meta ? ` ${GRAY}${JSON.stringify(meta)}${RESET}` : '';
    return `${ts} ${tag} ${lvl} ${message}${metaStr}`;
  }

  debug(msg: string, meta?: object): void {
    if (this.level <= LEVELS.debug) {
      console.log(this.format(GRAY, 'DEBUG', msg, meta));
    }
  }

  info(msg: string, meta?: object): void {
    if (this.level <= LEVELS.info) {
      console.log(this.format(CYAN, 'INFO ', msg, meta));
    }
  }

  warn(msg: string, meta?: object): void {
    if (this.level <= LEVELS.warn) {
      console.warn(this.format(YELLOW, 'WARN ', msg, meta));
    }
  }

  error(msg: string, meta?: object): void {
    if (this.level <= LEVELS.error) {
      console.error(this.format(RED, 'ERROR', msg, meta));
    }
  }

  success(msg: string, meta?: object): void {
    console.log(this.format(GREEN, 'OK   ', msg, meta));
  }
}
