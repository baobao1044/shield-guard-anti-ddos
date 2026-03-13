// ============================================================================
// Feature Extractor — Converts HTTP requests into ML feature vectors
// ============================================================================

/**
 * A feature vector for ML WAF classification.
 * Each feature is normalized to roughly [0, 1] range for the perceptron.
 */
export interface FeatureVector {
  urlLength: number;
  urlEntropy: number;
  queryParamCount: number;
  specialCharRatio: number;
  uppercaseRatio: number;
  digitRatio: number;
  maxParamValueLength: number;
  bodyLength: number;
  bodyEntropy: number;
  bodySpecialCharRatio: number;
  headerCount: number;
  hasCookie: number;
  hasReferer: number;
  hasAcceptLanguage: number;
  methodScore: number;
  contentTypeScore: number;
  pathDepth: number;
  fileExtensionScore: number;
  doubleEncodingScore: number;
  sqlKeywordDensity: number;
  htmlTagDensity: number;
  shellMetacharDensity: number;
}

export const FEATURE_COUNT = 22;

const METHOD_SCORES: Record<string, number> = { GET: 0.1, POST: 0.3, PUT: 0.4, PATCH: 0.4, DELETE: 0.5, OPTIONS: 0.2, HEAD: 0.1 };
const DANGEROUS_EXTS = new Set(['php', 'asp', 'aspx', 'jsp', 'cgi', 'sh', 'bat', 'exe', 'env', 'sql', 'bak', 'config']);
const SQL_KEYWORDS = /\b(select|union|insert|update|delete|drop|alter|exec|execute|cast|declare|nchar|char|varchar|waitfor|delay|benchmark|sleep|load_file|into\s+outfile|information_schema)\b/gi;
const HTML_TAGS = /<[a-z][a-z0-9]*[\s>\/]/gi;
const SHELL_META = /[;|`$(){}[\]<>&!\\]/g;
const DOUBLE_ENCODE = /%25[0-9a-f]{2}/gi;

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function countSpecialChars(s: string): number {
  let count = 0;
  for (const c of s) {
    const code = c.charCodeAt(0);
    if (!((code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 32 || code === 47 || code === 46 || code === 45 || code === 95)) {
      count++;
    }
  }
  return count;
}

function countUppercase(s: string): number {
  let c = 0;
  for (const ch of s) if (ch >= 'A' && ch <= 'Z') c++;
  return c;
}

function countDigits(s: string): number {
  let c = 0;
  for (const ch of s) if (ch >= '0' && ch <= '9') c++;
  return c;
}

function clamp01(v: number): number {
  return Math.max(0, Math.min(1, v));
}

export function extractFeatures(
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: string,
): FeatureVector {
  const decodedUrl = (() => { try { return decodeURIComponent(url); } catch { return url; } })();
  const [pathPart, queryPart] = decodedUrl.split('?', 2);
  const queryParams = queryPart ? queryPart.split('&') : [];
  const maxParamLen = queryParams.reduce((max, p) => Math.max(max, (p.split('=', 2)[1] || '').length), 0);
  const pathSegments = pathPart.split('/').filter(Boolean);
  const fileExt = pathPart.includes('.') ? pathPart.split('.').pop()?.toLowerCase() || '' : '';
  const bodyText = body || '';

  // SQL keyword density in URL + body
  const fullText = decodedUrl + ' ' + bodyText;
  const sqlMatches = fullText.match(SQL_KEYWORDS);
  const htmlMatches = fullText.match(HTML_TAGS);
  const shellMatches = fullText.match(SHELL_META);
  const doubleEncodeMatches = url.match(DOUBLE_ENCODE);

  return {
    urlLength: clamp01(decodedUrl.length / 2000),
    urlEntropy: clamp01(shannonEntropy(decodedUrl) / 6),
    queryParamCount: clamp01(queryParams.length / 20),
    specialCharRatio: decodedUrl.length > 0 ? clamp01(countSpecialChars(decodedUrl) / decodedUrl.length) : 0,
    uppercaseRatio: decodedUrl.length > 0 ? clamp01(countUppercase(decodedUrl) / decodedUrl.length) : 0,
    digitRatio: decodedUrl.length > 0 ? clamp01(countDigits(decodedUrl) / decodedUrl.length) : 0,
    maxParamValueLength: clamp01(maxParamLen / 500),
    bodyLength: clamp01(bodyText.length / 10000),
    bodyEntropy: clamp01(shannonEntropy(bodyText.substring(0, 2000)) / 6),
    bodySpecialCharRatio: bodyText.length > 0 ? clamp01(countSpecialChars(bodyText.substring(0, 2000)) / Math.min(bodyText.length, 2000)) : 0,
    headerCount: clamp01(Object.keys(headers).length / 50),
    hasCookie: headers['cookie'] ? 1 : 0,
    hasReferer: headers['referer'] ? 1 : 0,
    hasAcceptLanguage: headers['accept-language'] ? 1 : 0,
    methodScore: METHOD_SCORES[method.toUpperCase()] ?? 0.8,
    contentTypeScore: headers['content-type']?.includes('json') ? 0.2 : headers['content-type']?.includes('form') ? 0.4 : headers['content-type'] ? 0.5 : 0,
    pathDepth: clamp01(pathSegments.length / 10),
    fileExtensionScore: DANGEROUS_EXTS.has(fileExt) ? 1 : fileExt ? 0.3 : 0,
    doubleEncodingScore: clamp01((doubleEncodeMatches?.length || 0) / 3),
    sqlKeywordDensity: clamp01((sqlMatches?.length || 0) / 5),
    htmlTagDensity: clamp01((htmlMatches?.length || 0) / 5),
    shellMetacharDensity: clamp01((shellMatches?.length || 0) / 10),
  };
}

/**
 * Convert FeatureVector to a flat number array for the perceptron
 */
export function featureVectorToArray(fv: FeatureVector): number[] {
  return [
    fv.urlLength, fv.urlEntropy, fv.queryParamCount, fv.specialCharRatio,
    fv.uppercaseRatio, fv.digitRatio, fv.maxParamValueLength,
    fv.bodyLength, fv.bodyEntropy, fv.bodySpecialCharRatio,
    fv.headerCount, fv.hasCookie, fv.hasReferer, fv.hasAcceptLanguage,
    fv.methodScore, fv.contentTypeScore, fv.pathDepth, fv.fileExtensionScore,
    fv.doubleEncodingScore, fv.sqlKeywordDensity, fv.htmlTagDensity, fv.shellMetacharDensity,
  ];
}
