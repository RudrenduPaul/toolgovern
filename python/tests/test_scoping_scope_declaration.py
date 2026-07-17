"""Tests for scope_declaration.py -- is_valid_scope_declaration and is_valid_agent_id. Ported
in spirit from packages/toolgovern/test/scoping/scope-declaration.test.ts.
"""

from toolgovern import EMPTY_SCOPE, is_valid_agent_id, is_valid_scope_declaration, normalize_scope


class TestIsValidScopeDeclaration:
    def test_valid_full_scope(self):
        assert is_valid_scope_declaration(
            {"network": ["example.com"], "filesystem": ["/workspace"], "credentials": ["aws"]}
        )

    def test_valid_network_bool(self):
        assert is_valid_scope_declaration({"network": False, "filesystem": [], "credentials": []})
        assert is_valid_scope_declaration({"network": True, "filesystem": [], "credentials": []})

    def test_missing_scope_is_invalid(self):
        assert not is_valid_scope_declaration(None)
        assert not is_valid_scope_declaration("not-a-scope")

    def test_wrong_type_network_is_invalid(self):
        assert not is_valid_scope_declaration({"network": 123, "filesystem": [], "credentials": []})

    def test_non_string_filesystem_entries_invalid(self):
        assert not is_valid_scope_declaration({"network": False, "filesystem": [1, 2], "credentials": []})

    def test_missing_field_invalid(self):
        assert not is_valid_scope_declaration({"network": False, "filesystem": []})


class TestNormalizeScope:
    def test_defaults_to_empty_scope(self):
        scope = normalize_scope(None)
        assert scope.network == EMPTY_SCOPE.network
        assert list(scope.filesystem) == []
        assert list(scope.credentials) == []

    def test_partial_scope_fills_defaults(self):
        scope = normalize_scope({"filesystem": ["/workspace"]})
        assert scope.network is False
        assert list(scope.filesystem) == ["/workspace"]
        assert list(scope.credentials) == []


class TestIsValidAgentId:
    def test_realistic_uuid_is_valid(self):
        assert is_valid_agent_id("550e8400-e29b-41d4-a716-446655440000")

    def test_namespaced_string_is_valid(self):
        assert is_valid_agent_id("coordinator/sub-agent-1")

    def test_empty_string_invalid(self):
        assert not is_valid_agent_id("")

    def test_non_string_invalid(self):
        assert not is_valid_agent_id(12345)
        assert not is_valid_agent_id(None)

    def test_over_length_string_invalid(self):
        assert not is_valid_agent_id("a" * 257)

    def test_at_length_limit_valid(self):
        assert is_valid_agent_id("a" * 256)

    def test_embedded_null_byte_invalid(self):
        assert not is_valid_agent_id("agent\x00-evil")

    def test_embedded_newline_invalid(self):
        assert not is_valid_agent_id("agent\nFAKE_LOG_LINE evil=true")

    def test_control_characters_invalid(self):
        assert not is_valid_agent_id("agent\x1b[31mred")

    def test_unicode_line_separator_invalid(self):
        assert not is_valid_agent_id("agent" + chr(0x2028) + "injected")
