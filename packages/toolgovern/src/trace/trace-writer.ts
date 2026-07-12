/**
 * Signed, append-only JSON Lines trace writer.
 *
 * Every gate decision -- allow, deny, or require-approval -- gets one line. `prior_trace_id`
 * chains each entry to the one before it in the same session, so a reader can walk the chain and
 * detect a missing, reordered, or tampered entry.
 *
 * By default, "signed" means a `sha256:` content hash, not a keyed signature -- a deliberate v0.1
 * default that needs no key management: it proves an entry has not changed since it was written,
 * but it does not stop someone with write access to the trace file from editing an entry and
 * recomputing a signature that still passes, since the hash itself requires no secret to
 * reproduce. Pass `secretKey` in `TraceWriterOptions` to sign with `hmac-sha256:` instead, which
 * closes that gap for anyone who does not also hold the key. See `docs/security-model.md`.
 */

import { appendFile, mkdir } from 'node:fs/promises';
import { createHash, createHmac, type BinaryLike } from 'node:crypto';
import { dirname } from 'node:path';
import type { Decision, TraceEntry, TraceEntryInput } from '../types.js';
import { canonicalJson } from './canonical-json.js';

function sha256Hex(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function hmacSha256Hex(key: BinaryLike, content: string): string {
  return createHmac('sha256', key).update(content).digest('hex');
}

function entryContent(entry: Omit<TraceEntry, 'signature'>): string {
  return canonicalJson({
    trace_id: entry.trace_id,
    timestamp: entry.timestamp,
    session_id: entry.session_id,
    agent_id: entry.agent_id,
    tool: entry.tool,
    arguments_hash: entry.arguments_hash,
    decision: entry.decision,
    rule_fired: entry.rule_fired,
    declared_scope: entry.declared_scope,
    agent_id_source: entry.agent_id_source,
    prior_trace_id: entry.prior_trace_id,
  });
}

/** Computes the content hash a `TraceEntry` should have, given everything except `signature`.
 *  This is the unkeyed form -- kept for backward compatibility and as the fallback `sha256:`
 *  scheme `computeEntrySignature()` uses when no secret key is configured. */
export function computeEntryContentHash(entry: Omit<TraceEntry, 'signature'>): string {
  return sha256Hex(entryContent(entry));
}

/**
 * Computes what `signature` should be for `entry` (everything except `signature`).
 *
 * With no `secretKey`, this is `sha256:<hex>` of the entry's canonicalized content -- proves the
 * entry has not changed since it was written, but the hash is reproducible by anyone (no secret
 * required), so it does not stop an attacker who has write access to the trace file from editing
 * an entry and recomputing a signature that still verifies.
 *
 * With a `secretKey`, this is `hmac-sha256:<hex>` -- only someone holding the same key can
 * produce a signature that verifies. This is what makes the trace tamper-evident against an
 * attacker who can write to the trace file but does not also hold the key. See
 * `docs/security-model.md` for the residual limitation (an attacker who reads both the trace file
 * and the key file can still forge a valid trace -- v0.1 has no external anchor or key-management
 * service).
 */
export function computeEntrySignature(
  entry: Omit<TraceEntry, 'signature'>,
  secretKey?: BinaryLike,
): string {
  const content = entryContent(entry);
  return secretKey
    ? `hmac-sha256:${hmacSha256Hex(secretKey, content)}`
    : `sha256:${sha256Hex(content)}`;
}

export interface TraceWriterOptions {
  /** When provided, every entry is signed with `hmac-sha256:<hex>` using this key instead of
   *  the unkeyed `sha256:<hex>` content hash. toolgovern does not generate, store, or rotate
   *  this key -- the caller is responsible for its lifecycle (e.g. a locally generated file
   *  with restrictive permissions, or a secret manager). Pass the same key to `verifyChain()`. */
  readonly secretKey?: BinaryLike;
}

export class TraceWriter {
  /** Tracks the last trace_id written per session so entries chain correctly across calls. */
  private readonly lastTraceIdBySession = new Map<string, string | null>();
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly filePath: string,
    private readonly options: TraceWriterOptions = {},
  ) {}

  /** Appends one gate decision to the trace file and returns the entry that was written. */
  async append(input: TraceEntryInput): Promise<TraceEntry> {
    const priorTraceId = this.lastTraceIdBySession.get(input.sessionId) ?? null;
    const timestamp = new Date().toISOString();
    const argumentsHash = `sha256:${sha256Hex(canonicalJson(input.args))}`;
    const ruleFired = [...input.ruleFired];

    const withoutIds: Omit<TraceEntry, 'signature' | 'trace_id'> = {
      timestamp,
      session_id: input.sessionId,
      agent_id: input.agentId,
      tool: input.tool,
      arguments_hash: argumentsHash,
      decision: input.decision as Decision,
      rule_fired: ruleFired,
      declared_scope: input.declaredScope,
      agent_id_source: input.agentIdSource,
      prior_trace_id: priorTraceId,
    };
    // trace_id is derived from the entry's own (unkeyed) content hash -- it is an identifier, not
    // a security boundary, so it stays reproducible/public even when the signature is keyed.
    const idSeedHash = sha256Hex(canonicalJson(withoutIds));
    const traceId = `tg_${timestamp.slice(0, 10)}_${idSeedHash.slice(0, 6)}`;

    const signature = computeEntrySignature(
      { ...withoutIds, trace_id: traceId },
      this.options.secretKey,
    );
    const entry: TraceEntry = {
      trace_id: traceId,
      ...withoutIds,
      signature,
    };

    // Serialize writes so concurrent calls within one process never interleave lines or race on
    // `lastTraceIdBySession`, which would silently break the chain.
    this.writeQueue = this.writeQueue.then(async () => {
      await mkdir(dirname(this.filePath), { recursive: true });
      await appendFile(this.filePath, `${JSON.stringify(entry)}\n`, 'utf8');
    });
    await this.writeQueue;

    this.lastTraceIdBySession.set(input.sessionId, traceId);
    return entry;
  }
}
