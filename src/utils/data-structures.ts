// ============================================================================
// Data Structures for High-Performance DDoS Mitigation
// ============================================================================

// ============ TOKEN BUCKET ============

export class TokenBucket {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillRate: number; // tokens per ms
  private lastRefill: number;

  constructor(capacity: number, refillRatePerSec: number) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillRate = refillRatePerSec / 1000;
    this.lastRefill = Date.now();
  }

  consume(count = 1): boolean {
    this.refill();
    if (this.tokens >= count) {
      this.tokens -= count;
      return true;
    }
    return false;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillRate);
    this.lastRefill = now;
  }

  getTokens(): number {
    this.refill();
    return this.tokens;
  }
}

// ============ SLIDING WINDOW COUNTER ============

export class SlidingWindowCounter {
  private readonly windowMs: number;
  private readonly buckets: number[];
  private readonly bucketCount: number;
  private readonly bucketSizeMs: number;
  private lastBucketIndex: number;
  private lastBucketTime: number;

  constructor(windowMs: number, bucketCount = 10) {
    this.windowMs = windowMs;
    this.bucketCount = bucketCount;
    this.bucketSizeMs = windowMs / bucketCount;
    this.buckets = new Array(bucketCount).fill(0);
    this.lastBucketIndex = 0;
    this.lastBucketTime = Date.now();
  }

  increment(timestamp?: number): void {
    const now = timestamp ?? Date.now();
    this.advance(now);
    this.buckets[this.lastBucketIndex]++;
  }

  getRate(timestamp?: number): number {
    const now = timestamp ?? Date.now();
    this.advance(now);
    const total = this.buckets.reduce((a, b) => a + b, 0);
    return (total / this.windowMs) * 1000; // per second
  }

  getCount(): number {
    return this.buckets.reduce((a, b) => a + b, 0);
  }

  private advance(now: number): void {
    const elapsed = now - this.lastBucketTime;
    const bucketsToAdvance = Math.floor(elapsed / this.bucketSizeMs);

    if (bucketsToAdvance <= 0) return;

    const steps = Math.min(bucketsToAdvance, this.bucketCount);
    for (let i = 1; i <= steps; i++) {
      const idx = (this.lastBucketIndex + i) % this.bucketCount;
      this.buckets[idx] = 0;
    }

    this.lastBucketIndex = (this.lastBucketIndex + steps) % this.bucketCount;
    this.lastBucketTime = now;
  }
}

// ============ LRU CACHE ============

interface LRUNode<T> {
  key: string;
  value: T;
  expiresAt: number;
  prev: LRUNode<T> | null;
  next: LRUNode<T> | null;
}

export class LRUCache<T> {
  private readonly maxSize: number;
  private readonly ttlMs: number;
  private readonly map: Map<string, LRUNode<T>>;
  private head: LRUNode<T> | null = null; // MRU
  private tail: LRUNode<T> | null = null; // LRU
  private size = 0;

  constructor(maxSize: number, ttlMs: number) {
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
    this.map = new Map();
  }

  get(key: string): T | undefined {
    const node = this.map.get(key);
    if (!node) return undefined;

    if (Date.now() > node.expiresAt) {
      this.removeNode(node);
      this.map.delete(key);
      this.size--;
      return undefined;
    }

    this.moveToHead(node);
    return node.value;
  }

  set(key: string, value: T): void {
    const existing = this.map.get(key);

    if (existing) {
      existing.value = value;
      existing.expiresAt = Date.now() + this.ttlMs;
      this.moveToHead(existing);
      return;
    }

    const node: LRUNode<T> = {
      key,
      value,
      expiresAt: Date.now() + this.ttlMs,
      prev: null,
      next: this.head,
    };

    if (this.head) this.head.prev = node;
    this.head = node;
    if (!this.tail) this.tail = node;

    this.map.set(key, node);
    this.size++;

    if (this.size > this.maxSize) {
      this.evictLRU();
    }
  }

  delete(key: string): void {
    const node = this.map.get(key);
    if (!node) return;
    this.removeNode(node);
    this.map.delete(key);
    this.size--;
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  getSize(): number {
    return this.size;
  }

  private moveToHead(node: LRUNode<T>): void {
    if (node === this.head) return;
    this.removeNode(node);
    node.prev = null;
    node.next = this.head;
    if (this.head) this.head.prev = node;
    this.head = node;
    if (!this.tail) this.tail = node;
    this.size++;
  }

  private removeNode(node: LRUNode<T>): void {
    if (node.prev) node.prev.next = node.next;
    else this.head = node.next;

    if (node.next) node.next.prev = node.prev;
    else this.tail = node.prev;

    node.prev = null;
    node.next = null;
    this.size--;
  }

  private evictLRU(): void {
    if (!this.tail) return;
    const key = this.tail.key;
    this.removeNode(this.tail);
    this.map.delete(key);
  }
}

// ============ CIRCULAR BUFFER ============

export class CircularBuffer<T> {
  private readonly buffer: (T | undefined)[];
  private readonly capacity: number;
  private head = 0;
  private count = 0;

  constructor(capacity: number) {
    this.capacity = capacity;
    this.buffer = new Array(capacity);
  }

  push(item: T): void {
    this.buffer[this.head] = item;
    this.head = (this.head + 1) % this.capacity;
    if (this.count < this.capacity) this.count++;
  }

  toArray(): T[] {
    if (this.count === 0) return [];
    const start = this.count < this.capacity ? 0 : this.head;
    const result: T[] = [];
    for (let i = 0; i < this.count; i++) {
      const idx = (start + i) % this.capacity;
      result.push(this.buffer[idx] as T);
    }
    return result;
  }

  getCount(): number {
    return this.count;
  }
}

// ============ BLOOM FILTER ============

export class BloomFilter {
  private readonly bits: Uint8Array;
  private readonly size: number;
  private readonly hashCount: number;

  constructor(expectedItems: number, falsePositiveRate: number) {
    const m = Math.ceil(-(expectedItems * Math.log(falsePositiveRate)) / (Math.LN2 ** 2));
    const k = Math.ceil((m / expectedItems) * Math.LN2);
    this.size = m;
    this.hashCount = k;
    this.bits = new Uint8Array(Math.ceil(m / 8));
  }

  add(item: string): void {
    for (let i = 0; i < this.hashCount; i++) {
      const pos = this.hash(item, i) % this.size;
      this.bits[Math.floor(pos / 8)] |= 1 << (pos % 8);
    }
  }

  has(item: string): boolean {
    for (let i = 0; i < this.hashCount; i++) {
      const pos = this.hash(item, i) % this.size;
      if (!(this.bits[Math.floor(pos / 8)] & (1 << (pos % 8)))) return false;
    }
    return true;
  }

  private hash(str: string, seed: number): number {
    let h = seed * 2654435761;
    for (let i = 0; i < str.length; i++) {
      h = Math.imul(h ^ str.charCodeAt(i), 2246822519);
      h = (h << 13) | (h >>> 19);
    }
    return Math.abs(h);
  }
}

// ============ HYPERLOGLOG ============

export class HyperLogLog {
  private readonly registers: Uint8Array;
  private readonly m: number;
  private readonly alphaMM: number;

  constructor(precision: number) {
    this.m = 1 << Math.max(4, Math.min(16, precision));
    this.registers = new Uint8Array(this.m);

    const alpha =
      this.m === 16 ? 0.673 :
      this.m === 32 ? 0.697 :
      this.m === 64 ? 0.709 :
      0.7213 / (1 + 1.079 / this.m);
    this.alphaMM = alpha * this.m * this.m;
  }

  add(item: string): void {
    const h = this.murmurhash(item);
    const idx = h >>> (32 - Math.log2(this.m));
    const w = h & ((1 << (32 - Math.log2(this.m))) - 1);
    const rho = w === 0 ? 32 - Math.log2(this.m) + 1 : this.clz32(w);
    this.registers[idx] = Math.max(this.registers[idx], rho);
  }

  count(): number {
    let Z = 0;
    for (const r of this.registers) Z += 1 / (1 << r);
    const E = this.alphaMM / Z;

    if (E <= 2.5 * this.m) {
      const V = this.registers.filter(r => r === 0).length;
      if (V > 0) return Math.round(this.m * Math.log(this.m / V));
    }
    return Math.round(E);
  }

  private clz32(n: number): number {
    if (n === 0) return 32;
    return 31 - Math.floor(Math.log2(n));
  }

  private murmurhash(str: string): number {
    let h = 0xdeadbeef;
    for (let i = 0; i < str.length; i++) {
      h = Math.imul(h ^ str.charCodeAt(i), 0x5bd1e995);
      h ^= h >>> 15;
    }
    return h >>> 0;
  }
}
