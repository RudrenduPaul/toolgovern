"""TG02 filesystem-scope classifier tests. Ported in spirit from
packages/toolgovern/test/classifier/filesystem-scope.test.ts -- covers all 7 TG02 rules.
"""

from toolgovern import ScopeDeclaration
from toolgovern.classifier.filesystem_scope import filesystem_scope_rules
from toolgovern.classifier.index import classify


def _fired(ctx):
    result = classify(ctx)
    return result.decision, [r.rule_id for r in result.fired_rules]


class TestWriteOutsideScope:
    def test_fires_outside_scope(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/etc/passwd", "operation": "write"},
            scope=ScopeDeclaration(filesystem=["/workspace"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-write-outside-scope" in ids

    def test_does_not_fire_inside_scope(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/workspace/file.txt", "operation": "write"},
            scope=ScopeDeclaration(filesystem=["/workspace"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-write-outside-scope" not in ids

    def test_infers_write_from_tool_name(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/etc/passwd"},
            tool="write_file",
            scope=ScopeDeclaration(filesystem=["/workspace"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-write-outside-scope" in ids


class TestDeleteOutsideScope:
    def test_fires(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/important/data.db", "operation": "delete"},
            scope=ScopeDeclaration(filesystem=["/tmp"]),
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG02-delete-outside-scope" in ids

    def test_does_not_fire_inside_scope(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/tmp/scratch.txt", "operation": "delete"},
            scope=ScopeDeclaration(filesystem=["/tmp"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-delete-outside-scope" not in ids


class TestChmodOutsideScope:
    def test_fires(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/usr/bin/sudo", "operation": "chmod"},
            scope=ScopeDeclaration(filesystem=["/workspace"]),
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG02-chmod-outside-scope" in ids

    def test_no_operation_does_not_fire(self, ctx_factory):
        ctx = ctx_factory({"path": "/usr/bin/sudo"}, scope=ScopeDeclaration(filesystem=["/workspace"]))
        decision, ids = _fired(ctx)
        assert "TG02-chmod-outside-scope" not in ids


class TestReadOutsideScope:
    def test_fires(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/etc/shadow", "operation": "read"},
            scope=ScopeDeclaration(filesystem=["/workspace"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-read-outside-scope" in ids

    def test_credential_granted_path_does_not_fire(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/home/user/.aws/credentials", "operation": "read"},
            scope=ScopeDeclaration(filesystem=[], credentials=["aws"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-read-outside-scope" not in ids

    def test_empty_filesystem_scope_still_checked(self, ctx_factory):
        # A caller with filesystem: [] but a non-empty network/credential grant is a realistic
        # partial grant -- its reads must still be checked, not treated as zero-capability.
        ctx = ctx_factory(
            {"path": "/some/file.txt", "operation": "read"},
            scope=ScopeDeclaration(network=["example.com"], filesystem=[], credentials=[]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-read-outside-scope" in ids


class TestPathTraversal:
    def test_fires_on_dotdot(self, ctx_factory):
        ctx = ctx_factory({"path": "../../etc/passwd"}, scope=ScopeDeclaration(filesystem=["/workspace"]))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG02-path-traversal" in ids

    def test_no_traversal_does_not_fire(self, ctx_factory):
        ctx = ctx_factory({"path": "/workspace/sub/file.txt"}, scope=ScopeDeclaration(filesystem=["/workspace"]))
        decision, ids = _fired(ctx)
        assert "TG02-path-traversal" not in ids

    def test_traversal_embedded_in_code_arg(self, ctx_factory):
        ctx = ctx_factory(
            {"code": 'open("../../etc/passwd")'}, scope=ScopeDeclaration(filesystem=["/workspace"])
        )
        decision, ids = _fired(ctx)
        assert "TG02-path-traversal" in ids


class TestSymlinkEscape:
    def test_fires_outside_scope(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/etc/passwd", "operation": "symlink"},
            scope=ScopeDeclaration(filesystem=["/workspace"]),
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG02-symlink-escape" in ids

    def test_inside_scope_does_not_fire(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/workspace/link", "operation": "symlink"},
            scope=ScopeDeclaration(filesystem=["/workspace"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-symlink-escape" not in ids


class TestSensitiveSystemPath:
    def test_fires_on_etc_write(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/etc/passwd", "operation": "write"}, scope=ScopeDeclaration(filesystem=["/"])
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG02-sensitive-system-path" in ids

    def test_fires_regardless_of_declared_scope(self, ctx_factory):
        # Sensitive system paths are denied outright, even inside a declared scope.
        ctx = ctx_factory(
            {"path": "/usr/local/bin/tool", "operation": "delete"},
            scope=ScopeDeclaration(filesystem=["/usr"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-sensitive-system-path" in ids

    def test_scoped_user_dir_does_not_fire(self, ctx_factory):
        ctx = ctx_factory(
            {"path": "/workspace/output.txt", "operation": "write"},
            scope=ScopeDeclaration(filesystem=["/workspace"]),
        )
        decision, ids = _fired(ctx)
        assert "TG02-sensitive-system-path" not in ids


def test_rule_registry_has_seven_tg02_rules():
    assert len(filesystem_scope_rules) == 7
    assert len({r.id for r in filesystem_scope_rules}) == 7
