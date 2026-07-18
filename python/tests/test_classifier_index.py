"""Classifier aggregation tests. Ported in spirit from
packages/toolgovern/test/classifier/index.test.ts -- severity ordering, disable/downgrade
options, and the overall 35-rule registry count (34 original + TG03-dns-resolves-private).
"""

from toolgovern import ScopeDeclaration
from toolgovern.classifier.index import ClassifyOptions, classify, rule_registry


def test_rule_registry_has_35_rules_total():
    assert len(rule_registry) == 35
    assert len({r.id for r in rule_registry}) == 35


def test_rule_registry_category_breakdown():
    counts = {}
    for r in rule_registry:
        counts[r.category] = counts.get(r.category, 0) + 1
    assert counts == {"TG01": 9, "TG02": 7, "TG03": 7, "TG04": 6, "TG05": 6}


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


def test_classify_catches_a_hostname_that_resolves_to_loopback_via_real_dns(ctx_factory):
    # Unlike the TypeScript port (whose synchronous classify() cannot run an async DNS lookup,
    # hence classifyAsync()), Python's classify() is fully synchronous end-to-end -- socket.
    # getaddrinfo() is itself a blocking call, so this DNS-resolution rule runs as a completely
    # ordinary member of rule_registry with no separate async entry point required. This uses
    # "localhost" against the real OS resolver (no mocking) precisely to prove that wiring.
    ctx = ctx_factory({"host": "localhost"}, scope=ScopeDeclaration(network=["other.example"]))
    result = classify(ctx)
    assert result.decision == "deny"
    assert "TG03-dns-resolves-private" in {r.rule_id for r in result.fired_rules}
