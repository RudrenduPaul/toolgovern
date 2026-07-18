"""TG08 information-flow-control tests. Ported from
packages/toolgovern/test/classifier/information-flow.test.ts.
"""

from toolgovern import IfcPolicy, ScopeDeclaration
from toolgovern.classifier.information_flow import information_flow_rules

_RULE_ID = "TG08-confidential-source-to-untrusted-sink"

_CUSTOMER_DB_CONFIDENTIAL = IfcPolicy(
    sources={"db.customers": "confidential"},
    sink_trust={"internal.dashboard": "confidential", "public.webhook": "public"},
)


def _rule():
    found = next((r for r in information_flow_rules if r.id == _RULE_ID), None)
    assert found is not None, f"No such rule: {_RULE_ID}"
    return found


def _fire(ctx_factory, args, ifc=None):
    ctx = ctx_factory(args, scope=ScopeDeclaration(ifc=ifc))
    return _rule().evaluate(ctx)


def test_does_not_fire_when_no_ifc_policy_declared(ctx_factory):
    result = _fire(ctx_factory, {"source": "db.customers", "to": "public.webhook"}, None)
    assert result is None


def test_does_not_fire_without_a_recognized_source_argument(ctx_factory):
    result = _fire(
        ctx_factory,
        {"query": "select * from customers", "to": "public.webhook"},
        _CUSTOMER_DB_CONFIDENTIAL,
    )
    assert result is None


def test_does_not_fire_when_source_is_unlabeled(ctx_factory):
    result = _fire(
        ctx_factory,
        {"source": "db.public_prices", "to": "public.webhook"},
        _CUSTOMER_DB_CONFIDENTIAL,
    )
    assert result is None


def test_does_not_fire_when_source_labeled_public(ctx_factory):
    policy = IfcPolicy(sources={"db.marketing": "public"}, sink_trust={})
    result = _fire(ctx_factory, {"source": "db.marketing", "to": "public.webhook"}, policy)
    assert result is None


def test_does_not_fire_when_confidential_source_has_no_sink_argument(ctx_factory):
    result = _fire(ctx_factory, {"source": "db.customers"}, _CUSTOMER_DB_CONFIDENTIAL)
    assert result is None


def test_allows_when_sink_trust_at_or_above_source_label(ctx_factory):
    result = _fire(
        ctx_factory,
        {"source": "db.customers", "to": "internal.dashboard"},
        _CUSTOMER_DB_CONFIDENTIAL,
    )
    assert result is None


def test_denies_when_declared_sink_trust_is_explicitly_lower(ctx_factory):
    result = _fire(
        ctx_factory,
        {"source": "db.customers", "to": "public.webhook"},
        _CUSTOMER_DB_CONFIDENTIAL,
    )
    assert result is not None
    assert result.decision == "deny"
    assert result.rule_id == _RULE_ID
    assert result.matched_argument == "public.webhook"


def test_fails_closed_to_require_approval_when_sink_trust_undeclared(ctx_factory):
    result = _fire(
        ctx_factory,
        {"source": "db.customers", "to": "unknown.third-party.example"},
        _CUSTOMER_DB_CONFIDENTIAL,
    )
    assert result is not None
    assert result.decision == "require-approval"
    assert result.matched_argument == "unknown.third-party.example"


def test_matches_via_trailing_segment_and_substring(ctx_factory):
    policy = IfcPolicy(
        sources={"customers": "restricted"}, sink_trust={"dashboard": "restricted"}
    )
    result = _fire(
        ctx_factory, {"source": "db.prod.customers", "to": "internal.dashboard"}, policy
    )
    assert result is None


def test_recognizes_alternate_declared_argument_key_names(ctx_factory):
    result = _fire(
        ctx_factory,
        {"from": "db.customers", "destination": "public.webhook"},
        _CUSTOMER_DB_CONFIDENTIAL,
    )
    assert result is not None
    assert result.decision == "deny"


def test_restricted_source_cannot_flow_to_a_confidential_only_sink(ctx_factory):
    policy = IfcPolicy(
        sources={"db.secrets": "restricted"}, sink_trust={"internal.dashboard": "confidential"}
    )
    result = _fire(ctx_factory, {"source": "db.secrets", "to": "internal.dashboard"}, policy)
    assert result is not None
    assert result.decision == "deny"


def test_classify_end_to_end_requires_approval_on_undeclared_sink(ctx_factory):
    # Exercises the full classify() aggregation path, not just the rule in isolation.
    from toolgovern.classifier.index import classify

    ctx = ctx_factory(
        {"source": "db.customers", "to": "unknown.third-party.example"},
        scope=ScopeDeclaration(ifc=_CUSTOMER_DB_CONFIDENTIAL),
    )
    result = classify(ctx)
    assert result.decision == "require-approval"
    assert _RULE_ID in {r.rule_id for r in result.fired_rules}
