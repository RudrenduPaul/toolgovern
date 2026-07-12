/**
 * Reads a JSON Lines trace file for local inspection, filtering, and chain verification.
 * Powers both `toolgovern-cli audit` and any programmatic post-session review.
 */

import { readFile } from 'node:fs/promises';
import type { Decision, TraceEntry } from '../types.js';
import { computeEntryContentHash } from './trace-writer.js';

export interface TraceQuery {
  /** A relative time window, e.g. `'24h'`, `'7d'`, `'30m'`, or an absolute ISO 8601 timestamp. */
  readonly since?: string;
  readonly decision?: Decision;
  readonly agentId?: string;
  /** Matches entries where this rule ID appears anywhere in `rule_fired`. */
  readonly ruleId?: string;
}

export interface ChainVerificationIssue {
  readonly traceId: string;
  readonly reason: string;
}

export interface ChainVerificationResult {
  readonly valid: boolean;
  readonly issues: readonly ChainVerificationIssue[];
}

/** Reads and parses every line of a JSON Lines trace file. Blank lines are skipped. */
export async function readTrace(filePath: string): Promise<TraceEntry[]> {
  const raw = await readFile(filePath, 'utf8');
  const entries: TraceEntry[] = [];
  for (const [index, line] of raw.split('\n').entries()) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      entries.push(JSON.parse(trimmed) as TraceEntry);
    } catch (cause) {
      throw new Error(`Malformed trace line ${index + 1} in ${filePath}: not valid JSON`, {
        cause,
      });
    }
  }
  return entries;
}

const SINCE_PATTERN = /^(\d+)(m|h|d)$/;

/** Parses a `since` window string into an absolute cutoff `Date`. */
export function parseSince(since: string, now: Date = new Date()): Date {
  const match = since.match(SINCE_PATTERN);
  if (!match) {
    const asDate = new Date(since);
    if (Number.isNaN(asDate.getTime())) {
      throw new Error(
        `Invalid --since value "${since}". Use "<n>m", "<n>h", "<n>d", or an ISO 8601 timestamp.`,
      );
    }
    return asDate;
  }
  const amount = Number(match[1]);
  const unit = match[2];
  const msPerUnit = unit === 'm' ? 60_000 : unit === 'h' ? 3_600_000 : 86_400_000;
  return new Date(now.getTime() - amount * msPerUnit);
}

/** Filters trace entries by time window, decision, agent identity, and/or fired rule ID. */
export function filterTrace(entries: readonly TraceEntry[], query: TraceQuery): TraceEntry[] {
  const cutoff = query.since ? parseSince(query.since) : undefined;
  return entries.filter((entry) => {
    if (cutoff && new Date(entry.timestamp).getTime() < cutoff.getTime()) return false;
    if (query.decision && entry.decision !== query.decision) return false;
    if (query.agentId && entry.agent_id !== query.agentId) return false;
    if (query.ruleId && !entry.rule_fired.includes(query.ruleId)) return false;
    return true;
  });
}

/**
 * Recomputes each entry's content hash and confirms it matches `signature`, and confirms
 * `prior_trace_id` correctly links to the previous entry in the same session. Returns every
 * issue found rather than stopping at the first one, so a reviewer can see the full extent of a
 * broken or tampered trace file.
 */
export function verifyChain(entries: readonly TraceEntry[]): ChainVerificationResult {
  const issues: ChainVerificationIssue[] = [];
  const lastSeenBySession = new Map<string, string | null>();

  for (const entry of entries) {
    const expectedHash = computeEntryContentHash(entry);
    const [, actualHash] = entry.signature.split('sha256:');
    if (actualHash !== expectedHash) {
      issues.push({ traceId: entry.trace_id, reason: 'Signature does not match entry content.' });
    }

    const expectedPrior = lastSeenBySession.get(entry.session_id) ?? null;
    if (entry.prior_trace_id !== expectedPrior) {
      issues.push({
        traceId: entry.trace_id,
        reason: `prior_trace_id "${entry.prior_trace_id ?? 'null'}" does not match the expected previous entry "${expectedPrior ?? 'null'}" for session "${entry.session_id}".`,
      });
    }
    lastSeenBySession.set(entry.session_id, entry.trace_id);
  }

  return { valid: issues.length === 0, issues };
}
