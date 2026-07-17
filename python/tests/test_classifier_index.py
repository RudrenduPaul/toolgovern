"""Classifier aggregation tests. Ported in spirit from
packages/toolgovern/test/classifier/index.test.ts -- severity ordering, disable/downgrade
options, and the overall 34-rule registry count.
"""

from toolgovern import ScopeDeclaration
from toolgovern.classifier.index import ClassifyOptions, classify, rule_registry


def test_rule_registry_has_34_rules_total():
    assert len(rule_registry) == 34
    assert len({r.id for r in rule_registry}) == 34


def test_rule_registry_category_breakdown():
    counts = {}
    for r in rule_registry:
        counts[r.category] = counts.get(r.category, 0) + 1
    assert counts == {"TG01": 9, "TG02": 7, "TG03": 6, "TG04": 6, "TG05": 6}


def test_no_fired_rules_means_allow(ctx_factory):
    ctx = ctx_factory({"command": "ls -la /workspace"}, scope=ScopeDeclaration(filesystem=["/workspace"]))
    result = classify(ctx)
    assert result.decision == "allow"
    assert result.fired_rules == []


def test_deny_outranks_require_approval(ctx_factory):
    # sudo (require-approval) + rm -rf / (deny) in one command -- deny must win.
    ctx = ctx_factory({"command": "sudo rm -rf /"}, scope=ScopeDeclaration())
    result = classify(ctx)
    assert result.decision == "deny"
    ids = {r.rule_id for r in result.fired_rules}
    assert "TG01-sudo" in ids
    assert "TG01-rm-rf" in ids


def test_disabled_rule_never_fires(ctx_factory):
    ctx = ctx_factory({"command": "sudo apt-get update"}, scope=ScopeDeclaration())
    result = classify(ctx, ClassifyOptions(disabled_rules=["TG01-sudo"]))
    assert result.decision == "allow"
    assert result.fired_rules == []


def test_downgrade_to_approval_changes_deny_decision(ctx_factory):
    ctx = ctx_factory({"command": "rm -rf /"}, scope=ScopeDeclaration())
    result = classify(ctx, ClassifyOptions(downgrade_to_approval=["TG01-rm-rf"]))
    assert result.decision == "require-approval"
    assert result.fired_rules[0].rule_id == "TG01-rm-rf"
    assert result.fired_rules[0].decision == "require-approval"


def test_every_rule_evaluate_is_pure_null_or_rule_match(ctx_factory):
    # Sanity check across the whole registry: evaluate() never raises on a benign call and
    # always returns either None or a RuleMatch.
    ctx = ctx_factory({"command": "echo hello"}, scope=ScopeDeclaration())
    for rule in rule_registry:
        result = rule.evaluate(ctx)
        assert result is None or hasattr(result, "rule_id")
