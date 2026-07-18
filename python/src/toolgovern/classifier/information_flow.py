"""TG08 -- Information-Flow Control (confidentiality-label propagation).

Ported from ``packages/toolgovern/src/classifier/information-flow.ts``.

A categorically different question from TG01-TG05: those all ask "should this call happen" (is
this argument dangerous, is this path/host/credential in scope). This asks "can this *data* flow
here" -- does a call read from a source the caller has labeled confidential-or-higher, and
write/send that data to a destination whose declared trust tier is lower (or not declared at
all)? That is the same governance question Microsoft Agent Framework's FIDES answers with a full
confidentiality-label lattice tracked across an MCP gateway boundary -- this module is
deliberately NOT that. It is the smallest real primitive that lets a genuine label-propagation
check exist at all: one flat, closed label order (``ConfidentialityLabel`` in ``../types.py``), a
caller-declared source/sink labeling (``IfcPolicy``), and a single per-call rule.

What this explicitly does NOT do, disclosed rather than hidden:

- No automatic label inference. toolgovern cannot know that ``args["table"] == "customers.ssn"``
  is confidential, or that ``args["webhook"]`` points at an untrusted third party -- those are
  business facts only the integrator has. ``IfcPolicy.sources`` / ``IfcPolicy.sink_trust`` are a
  real, if minimal, labeling API the caller must declare; this rule only evaluates what was
  declared.
- No cross-call / session-level taint tracking. Each call is evaluated in isolation, exactly like
  every other TG0x rule -- if confidential data is read in one call and only handed to an
  untrusted sink two calls later, this rule does not see that.
- No reader/principal-scoped lattice. ``ConfidentialityLabel`` is one flat total order, not a set
  of readers or a join/meet lattice over multiple simultaneous principals.
- No result-value inspection. This evaluates the call's declared source/sink arguments, not the
  actual data a tool call returns.

Fail-closed posture (the one property this module does commit to): a call whose source is
labeled confidential-or-higher and whose destination's trust tier is NOT declared in
``IfcPolicy.sink_trust`` never silently allows -- it requires human approval. Only a destination
explicitly declared trustworthy enough (rank >= the source's label) is allowed through
unchallenged; a destination explicitly declared LOWER-trust is denied outright.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, List, Mapping, Optional, Sequence

from ..types import ConfidentialityLabel, RuleContext, RuleMatch

_CATEGORY = "TG08"

# Total order for ConfidentialityLabel, least to most sensitive.
_LABEL_ORDER: Sequence[str] = ("public", "internal", "confidential", "restricted")

# Argument key names a caller may use to name the source/sink of a labeled data flow.
# Deliberately separate, explicit key sets from TG02/TG04's path/credential-style keys and TG03's
# host/url-style keys -- reusing those would mean silently *inferring* that any path/host/
# credential argument is "the source" or "the sink" of a two-sided flow, which is exactly the
# automatic inference this module disclaims. A caller opts into TG08 by naming the source and
# sink explicitly under one of these keys.
_SOURCE_KEYS = ["source", "sourceId", "from", "readFrom"]
_SINK_KEYS = ["sink", "sinkId", "to", "destination", "sendTo", "forwardTo"]


@dataclass
class _Rule:
    id: str
    category: str
    description: str
    _evaluate: Callable[[RuleContext], Optional[RuleMatch]]

    def evaluate(self, ctx: RuleContext) -> Optional[RuleMatch]:
        return self._evaluate(ctx)


def _label_rank(label: str) -> int:
    return _LABEL_ORDER.index(label)


def _first_string(args: Mapping[str, Any], keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and len(value) > 0:
            return value
    return None


def _lookup_label(identifier: str, labels: Mapping[str, str]) -> Optional[str]:
    """Whether ``identifier`` matches an entry in a declared IfcPolicy label map -- exact match,
    a trailing path-segment match, or a substring match. Mirrors ``is_credential_granted()``'s
    matching style in ``util.py``. Exact match is checked across the whole map first so a
    longer, more specific declared key is never shadowed by an unrelated shorter key that
    merely happens to be a substring of it."""
    lower = identifier.lower()
    for key, label in labels.items():
        if key.lower() == lower:
            return label
    for key, label in labels.items():
        k = key.lower()
        if k and (lower.endswith(f"/{k}") or k in lower):
            return label
    return None


def _match(rule_id: str, decision: str, reason: str, matched_argument: str) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        category=_CATEGORY,  # type: ignore[arg-type]
        decision=decision,  # type: ignore[arg-type]
        reason=reason,
        matched_argument=matched_argument,
    )


def _confidential_source_to_untrusted_sink_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    ifc = ctx.scope.ifc
    if ifc is None:
        return None

    source = _first_string(ctx.args, _SOURCE_KEYS)
    if not source:
        return None
    source_label = _lookup_label(source, ifc.sources)
    if not source_label or source_label == "public":
        return None

    sink = _first_string(ctx.args, _SINK_KEYS)
    if not sink:
        return None

    sink_trust = _lookup_label(sink, ifc.sink_trust)
    if sink_trust is None:
        return _match(
            "TG08-confidential-source-to-untrusted-sink",
            "require-approval",
            f'Call reads from "{source}" labeled "{source_label}" and sends to "{sink}", whose '
            "trust tier is not declared in the IFC policy. Failing closed pending human review.",
            sink,
        )
    if _label_rank(sink_trust) < _label_rank(source_label):
        return _match(
            "TG08-confidential-source-to-untrusted-sink",
            "deny",
            f'Call reads from "{source}" labeled "{source_label}" but destination "{sink}" is '
            f'only trusted for "{sink_trust}" data.',
            sink,
        )
    return None


information_flow_rules: List[_Rule] = [
    _Rule(
        "TG08-confidential-source-to-untrusted-sink",
        _CATEGORY,
        "A call reads from a source labeled confidential-or-higher and writes/sends to a "
        "destination whose declared trust tier is lower than the source's label, or whose "
        "trust tier was never declared at all (fails closed to require-approval, not allow).",
        _confidential_source_to_untrusted_sink_evaluate,
    ),
]
