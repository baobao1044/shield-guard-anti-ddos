// ============================================================================
// JA3/JA4 TLS Fingerprinting
// Detects bot frameworks by their TLS handshake characteristics
// ============================================================================

import * as tls from 'tls';
import * as crypto from 'crypto';
import { Logger } from '../utils/logger';
import { LRUCache } from '../utils/data-structures';

const log = new Logger('JA3');

export interface JA3Config {
  enabled: boolean;
  blockUnknownFingerprints: boolean;   // Block TLS clients with unknown fingerprints
  mismatchScoreBoost: number;          // Bot score boost for UA/JA3 mismatch (default: 40)
  logFingerprints: boolean;            // Log all fingerprints for analysis
}

export const DEFAULT_JA3_CONFIG: JA3Config = {
  enabled: true,
  blockUnknownFingerprints: false,
  mismatchScoreBoost: 40,
  logFingerprints: false,
};

// Known good JA3 fingerprints → expected UA families
// In production these would be populated from a maintained database
// These are representative examples of TLS behavior patterns
const KNOWN_FINGERPRINTS: Map<string, string[]> = new Map([
  // Modern Chrome-based browsers (TLS 1.3 typical ciphersuites)
  ['chrome_modern', ['chrome', 'edge', 'opera', 'brave']],
  // Firefox
  ['firefox_modern', ['firefox']],
  // Safari / WebKit
  ['safari_modern', ['safari']],
  // curl (OpenSSL)
  ['curl_openssl', ['curl']],
  // Python requests (urllib3/OpenSSL)
  ['python_openssl', ['python']],
  // Go standard library
  ['go_stdlib', ['go']],
  // Node.js (OpenSSL variant)
  ['node_openssl', ['node']],
]);

// TLS version mapping
const TLS_VERSION_MAP: Record<string, number> = {
  'TLSv1': 0x0301,
  'TLSv1.1': 0x0302,
  'TLSv1.2': 0x0303,
  'TLSv1.3': 0x0304,
};

export interface FingerprintResult {
  ja3Hash: string;
  tlsVersion: string;
  cipherSuite: string;
  isKnown: boolean;
  expectedUAFamilies: string[];
  mismatch: boolean;
  mismatchScore: number;
}

export class JA3Fingerprinter {
  private readonly config: JA3Config;

  // IP → fingerprint data
  private fingerprints: LRUCache<FingerprintResult>;
  // Fingerprint hash → count (for analytics)
  private fingerprintCounts: Map<string, number> = new Map();
  // IP → resolved fingerprint hash
  private ipToFingerprint: LRUCache<string>;

  private stats = {
    fingerprintsExtracted: 0,
    knownFingerprints: 0,
    unknownFingerprints: 0,
    mismatchesDetected: 0,
    mismatchBlocked: 0,
  };

  constructor(config: JA3Config) {
    this.config = config;
    this.fingerprints = new LRUCache(100000, 600000);
    this.ipToFingerprint = new LRUCache(100000, 600000);
  }

  /**
   * Extract TLS fingerprint from a secure socket
   */
  extractFingerprint(socket: tls.TLSSocket): FingerprintResult | null {
    if (!this.config.enabled) return null;

    try {
      const ip = socket.remoteAddress ?? '0.0.0.0';
      const protocol = socket.getProtocol?.() ?? 'unknown';
      const cipher = socket.getCipher?.();

      if (!cipher) return null;

      // Build a JA3-like fingerprint from available info
      // Note: Node.js doesn't expose the full ClientHello, so we use
      // the negotiated parameters as a proxy fingerprint
      const components = [
        TLS_VERSION_MAP[protocol] ?? 0,
        cipher.name ?? 'unknown',
        cipher.standardName ?? '',
        cipher.version ?? '',
      ];

      const ja3Raw = components.join(',');
      const ja3Hash = crypto.createHash('md5').update(ja3Raw).digest('hex');

      // Classify the fingerprint
      const classification = this.classifyFingerprint(protocol, cipher.name ?? '', cipher.standardName ?? '');

      const result: FingerprintResult = {
        ja3Hash,
        tlsVersion: protocol,
        cipherSuite: cipher.name ?? 'unknown',
        isKnown: classification.isKnown,
        expectedUAFamilies: classification.expectedFamilies,
        mismatch: false,
        mismatchScore: 0,
      };

      // Store fingerprint for IP
      this.fingerprints.set(ip, result);
      this.ipToFingerprint.set(ip, ja3Hash);
      this.stats.fingerprintsExtracted++;

      // Count fingerprint frequency
      this.fingerprintCounts.set(ja3Hash, (this.fingerprintCounts.get(ja3Hash) || 0) + 1);

      if (classification.isKnown) {
        this.stats.knownFingerprints++;
      } else {
        this.stats.unknownFingerprints++;
      }

      if (this.config.logFingerprints) {
        log.debug(`TLS fingerprint: ${ip} → ${ja3Hash} (${protocol}, ${cipher.name})`);
      }

      return result;
    } catch {
      return null;
    }
  }

  /**
   * Check for JA3/User-Agent mismatch
   * Call this during L7 processing
   */
  checkMismatch(ip: string, userAgent: string): number {
    if (!this.config.enabled) return 0;

    const fp = this.fingerprints.get(ip);
    if (!fp || !fp.isKnown || fp.expectedUAFamilies.length === 0) return 0;

    const uaFamily = this.extractUAFamily(userAgent);

    // Check if UA family matches expected families for this TLS fingerprint
    if (uaFamily !== 'other' && uaFamily !== 'empty' && !fp.expectedUAFamilies.includes(uaFamily)) {
      fp.mismatch = true;
      fp.mismatchScore = this.config.mismatchScoreBoost;
      this.stats.mismatchesDetected++;

      log.debug(`JA3/UA mismatch: ${ip} — TLS expects [${fp.expectedUAFamilies.join(',')}] but UA says '${uaFamily}'`);

      return this.config.mismatchScoreBoost;
    }

    return 0;
  }

  /**
   * Classify a TLS fingerprint based on negotiated parameters
   */
  private classifyFingerprint(
    protocol: string,
    cipherName: string,
    standardName: string,
  ): { isKnown: boolean; expectedFamilies: string[] } {
    const lower = cipherName.toLowerCase();
    const std = standardName.toLowerCase();

    // TLS 1.3 with modern AEAD ciphers → likely modern browser
    if (protocol === 'TLSv1.3') {
      if (std.includes('aes_256_gcm') || std.includes('chacha20')) {
        return { isKnown: true, expectedFamilies: ['chrome', 'firefox', 'safari', 'edge'] };
      }
    }

    // TLS 1.2 with specific cipher suites
    if (protocol === 'TLSv1.2') {
      if (lower.includes('ecdhe') && lower.includes('aes')) {
        return { isKnown: true, expectedFamilies: ['chrome', 'firefox', 'safari', 'edge', 'curl', 'python', 'node'] };
      }
      if (lower.includes('rsa') && !lower.includes('ecdhe')) {
        // RSA key exchange without ECDHE is common in older/simpler clients
        return { isKnown: true, expectedFamilies: ['curl', 'python', 'go', 'java', 'php'] };
      }
    }

    // Older TLS versions
    if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
      return { isKnown: true, expectedFamilies: ['curl', 'python', 'go', 'java', 'php', 'perl'] };
    }

    return { isKnown: false, expectedFamilies: [] };
  }

  private extractUAFamily(ua: string): string {
    const lower = ua.toLowerCase();
    if (lower.includes('chrome') && !lower.includes('edge') && !lower.includes('opr')) return 'chrome';
    if (lower.includes('firefox')) return 'firefox';
    if (lower.includes('safari') && !lower.includes('chrome')) return 'safari';
    if (lower.includes('edg')) return 'edge';
    if (lower.includes('opr') || lower.includes('opera')) return 'chrome'; // Opera uses Chromium
    if (lower.includes('python')) return 'python';
    if (lower.includes('go-http')) return 'go';
    if (lower.includes('curl')) return 'curl';
    if (lower.includes('node')) return 'node';
    if (lower.includes('java')) return 'java';
    if (lower.includes('php')) return 'php';
    if (lower.includes('perl')) return 'perl';
    if (lower.includes('ruby')) return 'ruby';
    if (ua.trim() === '') return 'empty';
    return 'other';
  }

  /**
   * Get fingerprint for an IP
   */
  getFingerprint(ip: string): FingerprintResult | undefined {
    return this.fingerprints.get(ip);
  }

  /**
   * Get top fingerprints by frequency
   */
  getTopFingerprints(limit = 20): Array<{ hash: string; count: number }> {
    return Array.from(this.fingerprintCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([hash, count]) => ({ hash, count }));
  }

  getStats() {
    return {
      ...this.stats,
      uniqueFingerprints: this.fingerprintCounts.size,
    };
  }
}
