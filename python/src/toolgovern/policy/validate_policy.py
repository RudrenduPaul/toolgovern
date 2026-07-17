"""Structural and rule-reference validation for a policy file.

Ported from ``packages/toolgovern/src/policy/validatePolicy.ts``. Used both by ``load_policy()``
(raises on failure -- a program should not start with a broken policy) and by
``toolgovern-cli validate`` (reports every error found, without raising, so a developer gets one
full list instead of fixing errors one at a time).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence

from ..classifier import rule_registry
from ..scoping import is_valid_scope_declaration
from ..types import Policy, RuleOverrides, ScopeDeclaration

_VALID_RULE_IDS = {r.id for r in rule_registry}
_VALID_DECISIONS = {"allow", "deny", "require-approval"}


@dataclass(frozen=True)
class PolicyValidationResult:
    valid: bool
    errors: Sequence[str] = field(default_factory=tuple)


def validate_policy(raw: Any) -> PolicyValidationResult:
    """Validates a parsed (but untyped) policy object. Returns every error found, not just the
    first."""
    errors: List[str] = []

    if not isinstance(raw, dict):
        return PolicyValidationResult(
            valid=False, errors=["Policy file must define a single YAML mapping (object)."]
        )
    candidate = raw

    if "name" in candidate and candidate["name"] is not None and not isinstance(candidate["name"], str):
        errors.append('"name" must be a string if present.')
    if (
        "policy" in candidate
        and candidate["policy"] is not None
        and not isinstance(candidate["policy"], str)
    ):
        errors.append('"policy" must be a string if present.')

    if not is_valid_scope_declaration(candidate.get("scope")):
        errors.append(
            '"scope" is required and must have network (boolean or string[]), filesystem '
            "(string[]), and credentials (string[])."
        )

    if "defaultDecision" in candidate or "default_decision" in candidate:
        default_decision = candidate.get("defaultDecision", candidate.get("default_decision"))
        if not isinstance(default_decision, str) or default_decision not in _VALID_DECISIONS:
            errors.append('"defaultDecision" must be one of: allow, deny, require-approval.')

    rules = candidate.get("rules")
    if rules is not None:
        if not isinstance(rules, dict):
            errors.append('"rules" must be an object with optional "disable" and "requireApproval" arrays.')
        else:
            for field_name in ("disable", "requireApproval"):
                value = rules.get(field_name)
                if value is None:
                    continue
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    errors.append(f'"rules.{field_name}" must be an array of rule ID strings.')
                    continue
                for rule_id in value:
                    if rule_id not in _VALID_RULE_IDS:
                        errors.append(
                            f'"rules.{field_name}" references unknown rule ID "{rule_id}". '
                            f'Valid rule IDs: {", ".join(sorted(_VALID_RULE_IDS))}.'
                        )

    return PolicyValidationResult(valid=len(errors) == 0, errors=errors)


def as_policy(raw: dict) -> Policy:
    """Narrows ``raw`` to a ``Policy`` after ``validate_policy`` has confirmed it is
    structurally valid."""
    scope_raw = raw.get("scope", {})
    scope = ScopeDeclaration(
        network=scope_raw.get("network", False),
        filesystem=tuple(scope_raw.get("filesystem", ())),
        credentials=tuple(scope_raw.get("credentials", ())),
    )
    rules_raw = raw.get("rules")
    rules: Optional[RuleOverrides] = None
    if rules_raw is not None:
        rules = RuleOverrides(
            disable=tuple(rules_raw.get("disable", ())),
            require_approval=tuple(rules_raw.get("requireApproval", ())),
        )
    return Policy(
        scope=scope,
        policy=raw.get("policy"),
        name=raw.get("name"),
        rules=rules,
        default_decision=raw.get("defaultDecision", raw.get("default_decision", "allow")),
        agent_id=raw.get("agentId", raw.get("agent_id")),
        session_id=raw.get("sessionId", raw.get("session_id")),
        coordinator_id=raw.get("coordinatorId", raw.get("coordinator_id")),
    )
