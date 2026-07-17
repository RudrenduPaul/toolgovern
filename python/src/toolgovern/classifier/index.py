"""The classifier: runs every rule in the TG01-TG05 pack against one normalized call context
and aggregates the result.

Ported from ``packages/toolgovern/src/classifier/index.ts``.

Decision severity order is ``deny`` > ``require-approval`` > ``allow`` -- if any rule denies,
the call is denied, no matter how many other rules would have allowed it.

Every non-allow decision is traceable to the specific rule ID(s) that fired and the argument
that tripped each one. There is no unexplained black-box denial in this classifier: if
``fired_rules`` is empty, the decision is (and can only be) ``allow``.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import List, Sequence

from ..types import ClassifierResult, Decision, RuleContext, RuleMatch
from .credential_access import credential_access_rules
from .cross_agent_inheritance import cross_agent_inheritance_rules
from .filesystem_scope import filesystem_scope_rules
from .network_egress import network_egress_rules
from .shell_risk import shell_risk_rules

rule_registry = [
    *shell_risk_rules,
    *filesystem_scope_rules,
    *network_egress_rules,
    *credential_access_rules,
    *cross_agent_inheritance_rules,
]


@dataclass(frozen=True)
class ClassifyOptions:
    """Options for ``classify()``."""

    disabled_rules: Sequence[str] = field(default_factory=tuple)
    """Rule IDs to skip entirely regardless of arguments (from Policy.rules.disable)."""
    downgrade_to_approval: Sequence[str] = field(default_factory=tuple)
    """Rule IDs whose deny verdict should be downgraded to require-approval
    (from Policy.rules.require_approval)."""


def _severity(decision: Decision) -> int:
    if decision == "deny":
        return 2
    if decision == "require-approval":
        return 1
    return 0


def classify(ctx: RuleContext, options: ClassifyOptions = None) -> ClassifierResult:
    """Evaluates one tool call against every enabled rule and returns the aggregate verdict."""
    options = options or ClassifyOptions()
    disabled = set(options.disabled_rules)
    downgrade = set(options.downgrade_to_approval)

    fired_rules: List[RuleMatch] = []
    for rule in rule_registry:
        if rule.id in disabled:
            continue
        result = rule.evaluate(ctx)
        if not result:
            continue
        if result.decision == "deny" and result.rule_id in downgrade:
            fired_rules.append(dataclasses.replace(result, decision="require-approval"))
        else:
            fired_rules.append(result)

    decision: Decision = "allow"
    for r in fired_rules:
        if _severity(r.decision) > _severity(decision):
            decision = r.decision

    return ClassifierResult(decision=decision, fired_rules=fired_rules)
