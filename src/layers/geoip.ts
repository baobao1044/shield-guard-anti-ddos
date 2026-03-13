// ============================================================================
// GeoIP Intelligence - Country-level IP geolocation (zero-dependency)
// Uses embedded binary IP range lookup table
// ============================================================================

import { Logger } from '../utils/logger';

const log = new Logger('GeoIP');

export interface GeoIPConfig {
  enabled: boolean;
  blockedCountries: string[];
  allowedCountries: string[];
  challengeCountries: string[];
  action: 'block' | 'challenge' | 'log';
}

export const DEFAULT_GEOIP_CONFIG: GeoIPConfig = {
  enabled: false,
  blockedCountries: [],
  allowedCountries: [],
  challengeCountries: [],
  action: 'block',
};

export interface GeoIPResult {
  countryCode: string;
  countryName: string;
  action: 'allow' | 'block' | 'challenge' | 'unknown';
}

interface IPRange { start: number; end: number; country: string; }

const COUNTRY_NAMES: Record<string, string> = {
  US:'United States',CN:'China',RU:'Russia',DE:'Germany',FR:'France',
  GB:'United Kingdom',JP:'Japan',KR:'South Korea',BR:'Brazil',IN:'India',
  CA:'Canada',AU:'Australia',NL:'Netherlands',SG:'Singapore',HK:'Hong Kong',
  TW:'Taiwan',VN:'Vietnam',TH:'Thailand',ID:'Indonesia',MY:'Malaysia',
  UA:'Ukraine',PL:'Poland',RO:'Romania',SE:'Sweden',NO:'Norway',
  FI:'Finland',CH:'Switzerland',IT:'Italy',ES:'Spain',IE:'Ireland',
  IL:'Israel',AE:'UAE',ZA:'South Africa',MX:'Mexico',AR:'Argentina',
};

// Embedded /8 and /16 ranges: [startOctet1, startOctet2, endOctet1, endOctet2, country]
const RANGES: Array<[number,number,number,number,string]> = [
  [3,0,3,255,'US'],[4,0,4,255,'US'],[6,0,6,255,'US'],[8,0,8,255,'US'],
  [9,0,9,255,'US'],[11,0,11,255,'US'],[13,0,13,255,'US'],[15,0,15,255,'US'],
  [16,0,16,255,'US'],[17,0,17,255,'US'],[18,0,18,255,'US'],[20,0,20,255,'US'],
  [23,0,23,255,'US'],[24,0,24,255,'US'],[32,0,32,255,'US'],[34,0,34,255,'US'],
  [44,0,44,255,'US'],[45,0,45,255,'US'],[48,0,48,255,'US'],[50,0,50,255,'US'],
  [52,0,52,255,'US'],[54,0,54,255,'US'],[63,0,63,255,'US'],[64,0,64,255,'US'],
  [65,0,65,255,'US'],[66,0,66,255,'US'],[67,0,67,255,'US'],[68,0,68,255,'US'],
  [69,0,69,255,'US'],[70,0,70,255,'US'],[71,0,71,255,'US'],[72,0,72,255,'US'],
  [1,0,1,255,'CN'],[14,0,14,255,'CN'],[27,0,27,255,'CN'],[36,0,36,255,'CN'],
  [39,0,39,255,'CN'],[42,0,42,255,'CN'],[49,0,49,255,'CN'],[58,0,58,255,'CN'],
  [59,0,59,255,'CN'],[60,0,60,255,'CN'],[61,0,61,255,'CN'],[101,0,101,255,'CN'],
  [110,0,110,255,'CN'],[111,0,111,255,'CN'],[112,0,112,255,'CN'],[113,0,113,255,'CN'],
  [114,0,114,255,'CN'],[115,0,115,255,'CN'],[116,0,116,255,'CN'],[117,0,117,255,'CN'],
  [118,0,118,255,'CN'],[119,0,119,255,'CN'],[120,0,120,255,'CN'],[121,0,121,255,'CN'],
  [122,0,122,255,'CN'],[123,0,123,255,'CN'],[124,0,124,255,'CN'],[125,0,125,255,'CN'],
  [2,0,2,255,'RU'],[5,0,5,255,'RU'],[31,0,31,255,'RU'],[37,0,37,255,'RU'],
  [46,0,46,255,'RU'],[77,0,77,255,'RU'],[78,0,78,255,'RU'],[79,0,79,255,'RU'],
  [80,0,80,255,'RU'],[81,0,81,255,'RU'],[82,0,82,255,'RU'],[83,0,83,255,'RU'],
  [85,0,85,255,'RU'],[86,0,86,255,'RU'],[87,0,87,255,'RU'],[88,0,88,255,'RU'],
  [89,0,89,255,'RU'],[90,0,90,255,'RU'],[91,0,91,255,'RU'],[92,0,92,255,'RU'],
  [51,0,51,255,'GB'],[62,0,62,255,'DE'],[84,0,84,255,'DE'],[130,0,130,255,'DE'],
  [136,0,136,255,'FR'],[137,0,137,255,'FR'],[138,0,138,255,'NL'],
  [126,0,126,255,'JP'],[133,0,133,255,'JP'],[139,0,139,255,'JP'],[150,0,150,255,'JP'],
  [175,0,175,255,'KR'],[210,0,210,255,'KR'],[211,0,211,255,'KR'],
  [14,160,14,191,'VN'],[27,64,27,79,'VN'],[42,112,42,119,'VN'],[113,160,113,191,'VN'],
  [14,128,14,159,'IN'],[43,224,43,255,'IN'],[49,32,49,47,'IN'],
  [177,0,177,255,'BR'],[179,0,179,255,'BR'],[186,0,186,255,'BR'],[200,0,200,255,'BR'],
];

export class GeoIPLookup {
  private readonly config: GeoIPConfig;
  private readonly ranges: IPRange[];
  private countryStats: Map<string, number> = new Map();
  private stats = { totalLookups: 0, blocked: 0, challenged: 0, allowed: 0, unknown: 0 };

  constructor(config: GeoIPConfig) {
    this.config = config;
    this.ranges = RANGES.map(([s1,s2,e1,e2,c]) => ({
      start: ((s1<<24)|(s2<<16))>>>0,
      end: ((e1<<24)|(e2<<16)|0xFFFF)>>>0,
      country: c,
    })).sort((a,b) => a.start - b.start);

    if (config.enabled) {
      log.info('GeoIP initialized', { ranges: this.ranges.length,
        blocked: config.blockedCountries.join(',') || 'none',
        allowOnly: config.allowedCountries.join(',') || 'all' });
    }
  }

  lookup(ip: string): GeoIPResult {
    if (!this.config.enabled) return { countryCode: 'XX', countryName: 'Unknown', action: 'allow' };
    this.stats.totalLookups++;

    const ipNum = this.ipToNumber(ip);
    if (ipNum === 0) { this.stats.unknown++; return { countryCode: 'XX', countryName: 'Unknown', action: 'unknown' }; }

    const country = this.binarySearch(ipNum);
    if (!country) { this.stats.unknown++; return { countryCode: 'XX', countryName: 'Unknown', action: 'unknown' }; }

    this.countryStats.set(country, (this.countryStats.get(country) || 0) + 1);
    const action = this.determineAction(country);
    switch (action) { case 'block': this.stats.blocked++; break; case 'challenge': this.stats.challenged++; break; default: this.stats.allowed++; }
    return { countryCode: country, countryName: COUNTRY_NAMES[country] || country, action };
  }

  private determineAction(cc: string): GeoIPResult['action'] {
    const c = cc.toUpperCase();
    if (this.config.allowedCountries.length > 0) return this.config.allowedCountries.includes(c) ? 'allow' : 'block';
    if (this.config.blockedCountries.includes(c)) return 'block';
    if (this.config.challengeCountries.includes(c)) return 'challenge';
    return 'allow';
  }

  private binarySearch(ipNum: number): string | null {
    let lo = 0, hi = this.ranges.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const r = this.ranges[mid];
      if (ipNum < r.start) hi = mid - 1;
      else if (ipNum > r.end) lo = mid + 1;
      else return r.country;
    }
    return null;
  }

  private ipToNumber(ip: string): number {
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    const p = ip.split('.');
    if (p.length !== 4) return 0;
    const n = p.map(Number);
    if (n.some(v => isNaN(v) || v < 0 || v > 255)) return 0;
    return ((n[0]<<24)|(n[1]<<16)|(n[2]<<8)|n[3])>>>0;
  }

  getTopCountries(limit = 20): Array<{code:string; name:string; count:number}> {
    return Array.from(this.countryStats.entries())
      .sort((a,b) => b[1]-a[1]).slice(0, limit)
      .map(([code,count]) => ({ code, name: COUNTRY_NAMES[code]||code, count }));
  }

  getStats() { return { ...this.stats, topCountries: this.getTopCountries(10) }; }
}
