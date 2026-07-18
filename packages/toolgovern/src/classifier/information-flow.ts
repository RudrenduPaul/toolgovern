/**
 * TG08 -- Information-Flow Control (confidentiality-label propagation)
 *
 * A categorically different question from TG01-TG05: those all ask "should this call happen"
 * (is this argument dangerous, is this path/host/credential in scope). This asks "can this *data*
 * flow here" -- does a call read from a source the caller has labeled confidential-or-higher, and
 * write/send that data to a destination whose declared trust tier is lower (or not declared at
 * all)? That is the same governance question Microsoft Agent Framework's FIDES answers with a
 * full confidentiality-label lattice tracked across an MCP gateway boundary -- this module is
 * deliberately NOT that. It is the smallest real primitive that lets a genuine label-propagation
 * check exist at all: one flat, closed label order (`ConfidentialityLabel` in `../types.js`), a
 * caller-declared source/sink labeling (`IfcPolicy`), and a single per-call rule.
 *
 * What this explicitly does NOT do, disclosed rather than hidden:
 *
 * - No automatic label inference. toolgovern cannot know that `args.table === 'customers.ssn'` is
 *   confidential, or that `args.webhook` points at an untrusted third party -- those are business
 *   facts only the integrator has. `IfcPolicy.sources` / `IfcPolicy.sinkTrust` are a real, if
 *   minimal, labeling API the caller must declare; this rule only evaluates what was declared.
 * - No cross-call / session-level taint tracking. Each call is evaluated in isolation, exactly
 *   like every other TG0x rule -- if confidential data is read in one call and only handed to an
 *   untrusted sink two calls later (e.g. stashed in an intermediate variable/tool result), this
 *   rule does not see that. A real IFC system tracks a label across an entire flow graph, not one
 *   call's own source/sink arguments; that is out of scope here, the same way TG06/TG07's
 *   cross-call session state is out of scope for the rest of the v0.1 classifier.
 * - No reader/principal-scoped lattice. `ConfidentialityLabel` is one flat total order
 *   (`public < internal < confidential < restricted`), not a set of readers or a join/meet
 *   lattice over multiple simultaneous principals the way a fuller IFC model would need.
 * - No result-value inspection. This evaluates the *call's declared source/sink arguments*, not
 *   the actual data a tool call returns -- there is no taint applied to a tool's return value the
 *   way `_meta.ifc` result-label parsing does in a full MCP-aware IFC system.
 *
 * Fail-closed posture (the one property this module does commit to): a call whose source is
 * labeled confidential-or-higher and whose destination's trust tier is NOT declared in
 * `IfcPolicy.sinkTrust` never silently allows -- it requires human approval. Only a destination
 * explicitly declared trustworthy enough (rank >= the source's label) is allowed through
 * unchallenged; a destination explicitly declared LOWER-trust is denied outright.
 */

import type { ConfidentialityLabel, IfcPolicy, Rule, RuleMatch } from '../types.js';

const category = 'TG08' as const;

/** Total order for `ConfidentialityLabel`, least to most sensitive. Kept local to this module --
 *  nothing else in the classifier needs to rank labels, and keeping the order colocated with the
 *  one rule that uses it avoids a shared-constant import cycle for a single array literal. */
const LABEL_ORDER: readonly ConfidentialityLabel[] = [
  'public',
  'internal',
  'confidential',
  'restricted',
];

function labelRank(label: ConfidentialityLabel): number {
  return LABEL_ORDER.indexOf(label);
}

/** Argument key names a caller may use to name the source of a labeled data flow. Deliberately a
 *  separate, small, explicit key set from TG02/TG04's `path`/`credential`-style keys -- reusing
 *  those would mean silently *inferring* that any path or credential argument is "the source" of
 *  a two-sided flow, which is exactly the automatic-inference this module disclaims. A caller
 *  opts into TG08 by naming the source explicitly under one of these keys. */
const SOURCE_KEYS = ['source', 'sourceId', 'from', 'readFrom'];

/** Argument key names a caller may use to name the destination of a labeled data flow. Same
 *  rationale as `SOURCE_KEYS`: explicit and separate from TG03's `host`/`url`-style keys. */
const SINK_KEYS = ['sink', 'sinkId', 'to', 'destination', 'sendTo', 'forwardTo'];

function firstString(
  args: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): string | undefined {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return undefined;
}

/** Whether `identifier` matches an entry in a declared `IfcPolicy` label map -- exact match, a
 *  trailing path-segment match, or a substring match. Mirrors `isCredentialGranted()`'s matching
 *  style in `util.ts` so the same "declare a prefix/name once, match loosely at call time"
 *  ergonomics apply here too. Exact match is checked across the whole map first so a longer,
 *  more specific declared key is never shadowed by an unrelated shorter key that merely happens
 *  to be a substring of it. */
function lookupLabel(
  identifier: string,
  labels: Readonly<Record<string, ConfidentialityLabel>>,
): ConfidentialityLabel | undefined {
  const lower = identifier.toLowerCase();
  for (const [key, label] of Object.entries(labels)) {
    if (key.toLowerCase() === lower) return label;
  }
  for (const [key, label] of Object.entries(labels)) {
    const k = key.toLowerCase();
    if (k.length > 0 && (lower.endsWith(`/${k}`) || lower.includes(k))) return label;
  }
  return undefined;
}

function match(
  rule: Pick<Rule, 'id' | 'category'>,
  decision: RuleMatch['decision'],
  reason: string,
  matchedArgument: string,
): RuleMatch {
  return { ruleId: rule.id, category: rule.category, decision, reason, matchedArgument };
}

const confidentialSourceToUntrustedSink: Rule = {
  id: 'TG08-confidential-source-to-untrusted-sink',
  category,
  description:
    'A call reads from a source labeled confidential-or-higher and writes/sends to a ' +
    "destination whose declared trust tier is lower than the source's label, or whose trust " +
    'tier was never declared at all (fails closed to require-approval, not allow).',
  evaluate(ctx) {
    const ifc: IfcPolicy | undefined = ctx.scope.ifc;
    if (!ifc) return null;

    const source = firstString(ctx.args, SOURCE_KEYS);
    if (!source) return null;
    const sourceLabel = lookupLabel(source, ifc.sources);
    if (!sourceLabel || sourceLabel === 'public') return null;

    const sink = firstString(ctx.args, SINK_KEYS);
    if (!sink) return null;

    const sinkTrust = lookupLabel(sink, ifc.sinkTrust);
    if (sinkTrust === undefined) {
      return match(
        this,
        'require-approval',
        `Call reads from "${source}" labeled "${sourceLabel}" and sends to "${sink}", whose ` +
          'trust tier is not declared in the IFC policy. Failing closed pending human review.',
        sink,
      );
    }
    if (labelRank(sinkTrust) < labelRank(sourceLabel)) {
      return match(
        this,
        'deny',
        `Call reads from "${source}" labeled "${sourceLabel}" but destination "${sink}" is only ` +
          `trusted for "${sinkTrust}" data.`,
        sink,
      );
    }
    return null;
  },
};

export const informationFlowRules: readonly Rule[] = [confidentialSourceToUntrustedSink];
