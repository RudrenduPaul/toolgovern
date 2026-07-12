/**
 * Signed, append-only JSON Lines trace writer.
 *
 * Every gate decision -- allow, deny, or require-approval -- gets one line. `prior_trace_id`
 * chains each entry to the one before it in the same session, so a reader can walk the chain and
 * detect a missing, reordered, or tampered entry. "Signed" here means a sha256 content hash, not
 * a PKI signature -- that is a deliberate v0.1 scope choice: it proves the entry has not been
 * altered since it was written, which is what a local, self-hosted trace needs, without requiring
 * key management.
 */

import { appendFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';
import type { Decision, TraceEntry, TraceEntryInput } from '../types.js';
import { canonicalJson } from './canonical-json.js';

function sha256Hex(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

/** Computes the content hash a `TraceEntry` should have, given everything except `signature`. */
export function computeEntryContentHash(entry: Omit<TraceEntry, 'signature'>): string {
  return sha256Hex(
    canonicalJson({
      trace_id: entry.trace_id,
      timestamp: entry.timestamp,
      session_id: entry.session_id,
      agent_id: entry.agent_id,
      tool: entry.tool,
      arguments_hash: entry.arguments_hash,
      decision: entry.decision,
      rule_fired: entry.rule_fired,
      declared_scope: entry.declared_scope,
      prior_trace_id: entry.prior_trace_id,
    }),
  );
}

export class TraceWriter {
  /** Tracks the last trace_id written per session so entries chain correctly across calls. */
  private readonly lastTraceIdBySession = new Map<string, string | null>();
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(private readonly filePath: string) {}

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
      prior_trace_id: priorTraceId,
    };
    // trace_id is derived from the entry's own content hash (minus trace_id/signature, which
    // don't exist yet), so it is unique per distinct entry and reproducible for verification.
    const idSeedHash = sha256Hex(canonicalJson(withoutIds));
    const traceId = `tg_${timestamp.slice(0, 10)}_${idSeedHash.slice(0, 6)}`;

    const contentHash = computeEntryContentHash({ ...withoutIds, trace_id: traceId });
    const entry: TraceEntry = {
      trace_id: traceId,
      ...withoutIds,
      signature: `sha256:${contentHash}`,
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
