// ============================================================================
// Anomaly Detection Engine - AI-lite Traffic Pattern Analysis
// Uses EMA baselines + z-score for zero-day attack detection
// ============================================================================

import { Logger } from '../utils/logger';
import { SlidingWindowCounter } from '../utils/data-structures';

const log = new Logger('AnomalyEngine');

export interface AnomalyConfig {
  enabled: boolean;
  learningPeriodMs: number;       // Time to observe before enforcing (default: 30 min)
  snapshotIntervalMs: number;     // How often to capture a traffic snapshot (default: 5s)
  emaAlpha: number;               // EMA smoothing factor 0-1 (lower = smoother)
  zScoreThreshold: number;        // Z-score > this = anomaly (default: 3.0)
  criticalZScoreThreshold: number;// Z-score > this = critical anomaly (default: 5.0)
  minSamples: number;             // Min snapshots before anomaly detection activates
}

export const DEFAULT_ANOMALY_CONFIG: AnomalyConfig = {
  enabled: true,
  learningPeriodMs: 30 * 60 * 1000,  // 30 minutes
  snapshotIntervalMs: 5000,
  emaAlpha: 0.1,
  zScoreThreshold: 3.0,
  criticalZScoreThreshold: 5.0,
  minSamples: 20,
};

export interface TrafficSnapshot {
  timestamp: number;
  rps: number;
  uniqueIPs: number;
  avgPayloadSize: number;
  errorRate: number;          // fraction of blocked requests
  endpointEntropy: number;    // Shannon entropy of endpoint distribution
  methodDistribution: Record<string, number>;
}

export interface AnomalyResult {
  isAnomaly: boolean;
  score: number;              // 0-100 composite anomaly score
  zScores: Record<string, number>;
  anomalyTypes: string[];
  suggestedAction: 'none' | 'tighten' | 'uam' | 'emergency';
}

interface EMAState {
  mean: number;
  variance: number;
  count: number;
}

export class AnomalyEngine {
  private readonly config: AnomalyConfig;
  private startTime: number;
  private isLearning: boolean;

  // EMA baselines for each metric
  private baselines: Map<string, EMAState> = new Map();

  // Current window accumulators
  private requestCounter: SlidingWindowCounter;
  private uniqueIPSet: Set<string> = new Set();
  private payloadSizes: number[] = [];
  private blockedCount = 0;
  private totalCount = 0;
  private endpointCounts: Map<string, number> = new Map();
  private methodCounts: Map<string, number> = new Map();

  // Snapshot history for dashboard
  private snapshotHistory: TrafficSnapshot[] = [];
  private readonly maxHistory = 720; // 1 hour at 5s intervals

  // Last anomaly result
  private lastResult: AnomalyResult = {
    isAnomaly: false,
    score: 0,
    zScores: {},
    anomalyTypes: [],
    suggestedAction: 'none',
  };

  private snapshotTimer: ReturnType<typeof setInterval> | null = null;

  private stats = {
    totalSnapshots: 0,
    anomaliesDetected: 0,
    criticalAnomalies: 0,
    tightenSuggestions: 0,
    uamSuggestions: 0,
    emergencySuggestions: 0,
  };

  constructor(config: AnomalyConfig) {
    this.config = config;
    this.startTime = Date.now();
    this.isLearning = true;
    this.requestCounter = new SlidingWindowCounter(this.config.snapshotIntervalMs);

    if (config.enabled) {
      this.snapshotTimer = setInterval(() => this.captureSnapshot(), config.snapshotIntervalMs);
      this.snapshotTimer.unref();
      log.info('Anomaly Detection Engine initialized', {
        learningPeriod: `${config.learningPeriodMs / 60000}min`,
        zThreshold: config.zScoreThreshold,
      });
    }
  }

  /**
   * Record an incoming request for anomaly tracking
   */
  recordRequest(ip: string, method: string, path: string, payloadSize: number, wasBlocked: boolean): void {
    if (!this.config.enabled) return;

    this.requestCounter.increment();
    this.uniqueIPSet.add(ip);
    this.payloadSizes.push(payloadSize);
    this.totalCount++;
    if (wasBlocked) this.blockedCount++;

    const normalizedPath = path.split('?')[0].split('#')[0] || '/';
    this.endpointCounts.set(normalizedPath, (this.endpointCounts.get(normalizedPath) || 0) + 1);
    this.methodCounts.set(method, (this.methodCounts.get(method) || 0) + 1);
  }

  /**
   * Capture a traffic snapshot and run anomaly detection
   */
  private captureSnapshot(): void {
    const now = Date.now();

    // Check if we're still in learning phase
    if (this.isLearning && (now - this.startTime) >= this.config.learningPeriodMs) {
      this.isLearning = false;
      log.info('Learning phase complete — anomaly detection now active');
    }

    const snapshot: TrafficSnapshot = {
      timestamp: now,
      rps: this.requestCounter.getRate(),
      uniqueIPs: this.uniqueIPSet.size,
      avgPayloadSize: this.payloadSizes.length > 0
        ? this.payloadSizes.reduce((a, b) => a + b, 0) / this.payloadSizes.length
        : 0,
      errorRate: this.totalCount > 0 ? this.blockedCount / this.totalCount : 0,
      endpointEntropy: this.calculateEntropy(this.endpointCounts),
      methodDistribution: Object.fromEntries(this.methodCounts),
    };

    // Update EMA baselines
    this.updateBaseline('rps', snapshot.rps);
    this.updateBaseline('uniqueIPs', snapshot.uniqueIPs);
    this.updateBaseline('avgPayloadSize', snapshot.avgPayloadSize);
    this.updateBaseline('errorRate', snapshot.errorRate);
    this.updateBaseline('endpointEntropy', snapshot.endpointEntropy);

    // Store snapshot
    this.snapshotHistory.push(snapshot);
    if (this.snapshotHistory.length > this.maxHistory) {
      this.snapshotHistory.shift();
    }
    this.stats.totalSnapshots++;

    // Run anomaly detection (skip during learning)
    if (!this.isLearning) {
      this.lastResult = this.detectAnomalies(snapshot);
      if (this.lastResult.isAnomaly) {
        this.stats.anomaliesDetected++;
        log.warn(`Anomaly detected! Score: ${this.lastResult.score.toFixed(1)}, Types: [${this.lastResult.anomalyTypes.join(', ')}], Action: ${this.lastResult.suggestedAction}`);
      }
    }

    // Reset window accumulators
    this.uniqueIPSet.clear();
    this.payloadSizes = [];
    this.blockedCount = 0;
    this.totalCount = 0;
    this.endpointCounts.clear();
    this.methodCounts.clear();
  }

  /**
   * Update EMA baseline for a metric
   */
  private updateBaseline(metric: string, value: number): void {
    let state = this.baselines.get(metric);
    if (!state) {
      state = { mean: value, variance: 0, count: 0 };
      this.baselines.set(metric, state);
      return;
    }

    state.count++;
    const alpha = this.config.emaAlpha;

    // EMA mean
    const prevMean = state.mean;
    state.mean = alpha * value + (1 - alpha) * state.mean;

    // EMA variance (Welford-like with EMA)
    const diff = value - prevMean;
    state.variance = (1 - alpha) * (state.variance + alpha * diff * diff);
  }

  /**
   * Calculate z-scores and detect anomalies
   */
  private detectAnomalies(snapshot: TrafficSnapshot): AnomalyResult {
    const zScores: Record<string, number> = {};
    const anomalyTypes: string[] = [];
    let compositeScore = 0;

    const metrics: [string, number][] = [
      ['rps', snapshot.rps],
      ['uniqueIPs', snapshot.uniqueIPs],
      ['avgPayloadSize', snapshot.avgPayloadSize],
      ['errorRate', snapshot.errorRate],
      ['endpointEntropy', snapshot.endpointEntropy],
    ];

    for (const [name, value] of metrics) {
      const state = this.baselines.get(name);
      if (!state || state.count < this.config.minSamples) continue;

      const stddev = Math.sqrt(state.variance);
      const z = stddev > 0 ? (value - state.mean) / stddev : 0;
      zScores[name] = Math.round(z * 100) / 100;

      if (Math.abs(z) > this.config.zScoreThreshold) {
        anomalyTypes.push(this.classifyAnomaly(name, z));
        compositeScore += Math.min(25, Math.abs(z) * 5);
      }
    }

    // Special: entropy drop = many requests to same endpoint = likely attack
    const entropyZ = zScores['endpointEntropy'] || 0;
    if (entropyZ < -this.config.zScoreThreshold) {
      anomalyTypes.push('ENDPOINT_CONCENTRATION');
      compositeScore += 15;
    }

    // Special: error rate spike
    const errorZ = zScores['errorRate'] || 0;
    if (errorZ > this.config.zScoreThreshold) {
      compositeScore += 10;
    }

    compositeScore = Math.min(100, compositeScore);
    const isAnomaly = compositeScore > 0;

    let suggestedAction: AnomalyResult['suggestedAction'] = 'none';
    if (compositeScore >= 80) {
      suggestedAction = 'emergency';
      this.stats.emergencySuggestions++;
    } else if (compositeScore >= 50) {
      suggestedAction = 'uam';
      this.stats.uamSuggestions++;
    } else if (compositeScore >= 20) {
      suggestedAction = 'tighten';
      this.stats.tightenSuggestions++;
    }

    if (compositeScore >= 80) {
      this.stats.criticalAnomalies++;
    }

    return { isAnomaly, score: compositeScore, zScores, anomalyTypes, suggestedAction };
  }

  private classifyAnomaly(metric: string, z: number): string {
    const direction = z > 0 ? 'SPIKE' : 'DROP';
    switch (metric) {
      case 'rps': return `RPS_${direction}`;
      case 'uniqueIPs': return z > 0 ? 'IP_SURGE' : 'IP_CONCENTRATION';
      case 'avgPayloadSize': return `PAYLOAD_${direction}`;
      case 'errorRate': return 'ERROR_RATE_SPIKE';
      default: return `${metric.toUpperCase()}_${direction}`;
    }
  }

  /**
   * Shannon entropy of a frequency distribution
   */
  private calculateEntropy(counts: Map<string, number>): number {
    const total = Array.from(counts.values()).reduce((a, b) => a + b, 0);
    if (total === 0) return 0;

    let entropy = 0;
    for (const count of counts.values()) {
      if (count === 0) continue;
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  // === Public API ===

  getLastResult(): AnomalyResult {
    return { ...this.lastResult };
  }

  isLearningPhase(): boolean {
    return this.isLearning;
  }

  getBaselines(): Record<string, { mean: number; stddev: number; samples: number }> {
    const result: Record<string, { mean: number; stddev: number; samples: number }> = {};
    for (const [key, state] of this.baselines) {
      result[key] = {
        mean: Math.round(state.mean * 100) / 100,
        stddev: Math.round(Math.sqrt(state.variance) * 100) / 100,
        samples: state.count,
      };
    }
    return result;
  }

  getSnapshotHistory(): TrafficSnapshot[] {
    return [...this.snapshotHistory];
  }

  getStats() {
    return {
      ...this.stats,
      isLearning: this.isLearning,
      currentScore: this.lastResult.score,
      currentAction: this.lastResult.suggestedAction,
      baselines: this.getBaselines(),
    };
  }

  destroy(): void {
    if (this.snapshotTimer) {
      clearInterval(this.snapshotTimer);
      this.snapshotTimer = null;
    }
  }
}
