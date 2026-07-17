"""Tests for load_policy / validate_policy. Ported in spirit from
packages/toolgovern/test/policy/loadPolicy.test.ts and validatePolicy.test.ts.
"""

import pytest

from toolgovern import PolicyValidationError, load_policy, validate_policy


VALID_POLICY_YAML = """
name: strict-shell
scope:
  network: false
  filesystem:
    - ./workspace
  credentials: []
defaultDecision: allow
rules:
  disable: []
  requireApproval: []
"""


def test_load_valid_policy(tmp_path):
    path = tmp_path / "policy.yml"
    path.write_text(VALID_POLICY_YAML, encoding="utf-8")
    policy = load_policy(str(path))
    assert policy.name == "strict-shell"
    assert policy.scope.network is False
    assert list(policy.scope.filesystem) == ["./workspace"]
    assert policy.default_decision == "allow"


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_policy(str(tmp_path / "does-not-exist.yml"))


def test_load_invalid_policy_raises_policy_validation_error(tmp_path):
    path = tmp_path / "bad-policy.yml"
    path.write_text("name: bad\n# missing required scope field\n", encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_policy(str(path))


def test_load_malformed_yaml_raises(tmp_path):
    path = tmp_path / "malformed.yml"
    path.write_text("scope: [unterminated\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(str(path))


class TestValidatePolicy:
    def test_valid_minimal_policy(self):
        result = validate_policy({"scope": {"network": False, "filesystem": [], "credentials": []}})
        assert result.valid

    def test_missing_scope_invalid(self):
        result = validate_policy({"name": "no-scope"})
        assert not result.valid
        assert any("scope" in e for e in result.errors)

    def test_non_object_raw_invalid(self):
        result = validate_policy("just a string")
        assert not result.valid

    def test_invalid_default_decision(self):
        result = validate_policy(
            {
                "scope": {"network": False, "filesystem": [], "credentials": []},
                "defaultDecision": "maybe",
            }
        )
        assert not result.valid
        assert any("defaultDecision" in e for e in result.errors)

    def test_unknown_rule_id_in_disable_list(self):
        result = validate_policy(
            {
                "scope": {"network": False, "filesystem": [], "credentials": []},
                "rules": {"disable": ["TG99-not-a-real-rule"]},
            }
        )
        assert not result.valid
        assert any("unknown rule ID" in e for e in result.errors)

    def test_valid_rule_id_in_disable_list(self):
        result = validate_policy(
            {
                "scope": {"network": False, "filesystem": [], "credentials": []},
                "rules": {"disable": ["TG01-sudo"]},
            }
        )
        assert result.valid

    def test_reports_every_error_not_just_first(self):
        result = validate_policy({"name": 123, "policy": 456})
        assert not result.valid
        assert len(result.errors) >= 3  # name, policy, and missing scope
