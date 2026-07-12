/**
 * `IdempotencyCache` -- the primitive behind `governTool()`'s optional `idempotency` option.
 *
 * SCOPE AND LIMITATIONS (read before relying on this for anything beyond a single-process
 * first pass):
 *  - This is a plain in-process `Map`. It does NOT survive a process restart, and it is NOT
 *    shared across multiple processes or replicas (e.g. horizontally-scaled workers behind a
 *    load balancer, or a serverless function that spins up a fresh instance per invocation).
 *    Two replicas each hold their own independent cache, so a retry that happens to land on a
 *    different replica than the original call will NOT be deduplicated.
 *  - This is intentionally scoped as a first pass for the common single-process case (a
 *    long-running agent runtime, a single server instance, a CLI run). Cross-process /
 *    distributed idempotency (e.g. backed by Redis, or a database row with a unique constraint)
 *    is future work and is explicitly out of scope for this cache.
 *  - A new cache is created per `governTool()` call, so it is scoped to that one gated tool
 *    instance -- it is never shared globally across every gate in a process.
 */

import { canonicalJson } from '../trace/canonical-json.js';

/** Options for `governTool()`'s optional idempotency dedup. Omitting this option entirely (the
 *  default) leaves `governTool()`'s behavior completely unchanged -- every call executes
 *  independently, exactly as before this option existed. */
export interface IdempotencyOptions {
  /** Turn on idempotency dedup for this gated tool. */
  readonly enabled: boolean;
  /** How long a completed result stays eligible to be replayed for an identical retry, in
   *  milliseconds. Defaults to 60_000 (60s). */
  readonly ttlMs?: number;
}

const DEFAULT_IDEMPOTENCY_TTL_MS = 60_000;

interface CacheEntry<Result> {
  /** The in-flight or settled execution. Concurrent identical calls made before the first one
   *  resolves share this same promise instead of each re-invoking the underlying tool -- this is
   *  the "claim" half of claim-if-absent: the slot is claimed synchronously (the entry is stored
   *  in the map before anyone `await`s the run), so there is no race window between the cache
   *  check and the cache write for calls issued back-to-back on the same tick. */
  readonly promise: Promise<Result>;
  /** `null` while `promise` is still pending -- a pending claim never expires out from under a
   *  call that is still running. Set to a concrete timestamp once `promise` settles, so the TTL
   *  clock starts counting from completion rather than from when the call was first issued. */
  expiresAt: number | null;
}

/**
 * A scoped, in-memory `claim_if_absent` cache keyed on a stable serialization of tool name +
 * arguments. See the module doc comment above for what this does and does not cover.
 */
export class IdempotencyCache<Result> {
  private readonly entries = new Map<string, CacheEntry<Result>>();
  private readonly ttlMs: number;

  constructor(ttlMs: number = DEFAULT_IDEMPOTENCY_TTL_MS) {
    this.ttlMs = ttlMs;
  }

  /** Stable key for one tool+args combination. `canonicalJson` sorts object keys recursively, so
   *  `{a:1,b:2}` and `{b:2,a:1}` hash identically -- argument insertion order must never cause two
   *  logically-identical calls to miss each other. */
  static keyFor(tool: string, args: Readonly<Record<string, unknown>>): string {
    return `${tool}:${canonicalJson(args)}`;
  }

  /**
   * Returns the cached result for `key` if a live (non-expired) entry exists, executing `run`
   * only when there is no live claim. A failed execution is evicted immediately -- it is never
   * cached as if it had succeeded, so a transient failure remains retryable (the next call with
   * the same key genuinely re-executes the tool). Only a completed result is eligible to be
   * replayed for a retry within the TTL window.
   */
  async claimIfAbsent(key: string, run: () => Promise<Result>): Promise<Result> {
    const now = Date.now();
    const existing = this.entries.get(key);
    if (existing && (existing.expiresAt === null || existing.expiresAt > now)) {
      return existing.promise;
    }
    if (existing) {
      // Expired -- prune it so it doesn't linger, then fall through to claim a fresh slot.
      this.entries.delete(key);
    }

    const promise = run();
    const entry: CacheEntry<Result> = { promise, expiresAt: null };
    this.entries.set(key, entry);

    try {
      await promise;
      entry.expiresAt = Date.now() + this.ttlMs;
    } catch {
      this.entries.delete(key);
    }
    return promise;
  }
}
