using ToolGovern;
using ToolGovern.Classifier;
using Xunit;

namespace ToolGovern.Tests.Classifier;

public class FilesystemScopeRulesTests
{
    private static RuleContext Ctx(Dictionary<string, object?> args, IReadOnlyList<string>? filesystem = null) => new()
    {
        AgentId = "agent-1",
        SessionId = "session-1",
        Tool = "fs.write",
        Args = args,
        Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = filesystem ?? ["./workspace"], Credentials = [] },
    };

    private static bool Fires(string ruleId, Dictionary<string, object?> args, IReadOnlyList<string>? filesystem = null)
    {
        var rule = FilesystemScopeRules.Rules.First(r => r.Id == ruleId);
        return rule.Evaluate(Ctx(args, filesystem)) is not null;
    }

    [Fact]
    public void write_outside_scope_flags_a_write_outside_the_declared_prefix() =>
        Assert.True(Fires("TG02-write-outside-scope", new() { ["path"] = "/tmp/export.csv", ["operation"] = "write" }));

    [Fact]
    public void write_outside_scope_flags_create_outside_scope() =>
        Assert.True(Fires("TG02-write-outside-scope", new() { ["path"] = "/etc/hosts", ["operation"] = "create" }));

    [Fact]
    public void write_outside_scope_flags_append_outside_scope() =>
        Assert.True(Fires("TG02-write-outside-scope", new() { ["path"] = "/var/log/app.log", ["operation"] = "append" }));

    [Fact]
    public void write_outside_scope_does_not_flag_write_inside_scope() =>
        Assert.False(Fires("TG02-write-outside-scope", new() { ["path"] = "./workspace/out.txt", ["operation"] = "write" }));

    [Fact]
    public void write_outside_scope_does_not_flag_write_at_exactly_declared_prefix() =>
        Assert.False(Fires("TG02-write-outside-scope", new() { ["path"] = "./workspace", ["operation"] = "write" }));

    [Fact]
    public void write_outside_scope_does_not_flag_read_outside_scope() =>
        Assert.False(Fires("TG02-write-outside-scope", new() { ["path"] = "/tmp/export.csv", ["operation"] = "read" }));

    [Fact]
    public void write_outside_scope_flags_write_embedded_in_code() =>
        Assert.True(Fires("TG02-write-outside-scope", new() { ["code"] = "open(\"/tmp/export.csv\", \"w\").write(data)" }));

    [Fact]
    public void write_outside_scope_does_not_flag_write_embedded_in_code_in_scope() =>
        Assert.False(Fires("TG02-write-outside-scope", new() { ["code"] = "open(\"./workspace/out.txt\", \"w\").write(data)" }));

    [Fact]
    public void write_outside_scope_does_not_flag_plain_read_embedded_in_code()
    {
        var rule = FilesystemScopeRules.Rules.First(r => r.Id == "TG02-write-outside-scope");
        var ctx = new RuleContext
        {
            AgentId = "agent-1",
            SessionId = "session-1",
            Tool = "exec.run_code",
            Args = new Dictionary<string, object?> { ["code"] = "open(\"/tmp/export.csv\").read()" },
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] },
        };
        Assert.Null(rule.Evaluate(ctx));
    }

    [Fact]
    public void delete_outside_scope_flags_delete_outside_scope() =>
        Assert.True(Fires("TG02-delete-outside-scope", new() { ["path"] = "/etc/passwd", ["operation"] = "delete" }));

    [Fact]
    public void delete_outside_scope_flags_rm_outside_scope() =>
        Assert.True(Fires("TG02-delete-outside-scope", new() { ["path"] = "/var/data", ["operation"] = "rm" }));

    [Fact]
    public void delete_outside_scope_flags_unlink_outside_scope() =>
        Assert.True(Fires("TG02-delete-outside-scope", new() { ["path"] = "/home/user/file", ["operation"] = "unlink" }));

    [Fact]
    public void delete_outside_scope_does_not_flag_delete_inside_scope() =>
        Assert.False(Fires("TG02-delete-outside-scope", new() { ["path"] = "./workspace/tmp.txt", ["operation"] = "delete" }));

    [Fact]
    public void delete_outside_scope_does_not_flag_write_outside_scope() =>
        Assert.False(Fires("TG02-delete-outside-scope", new() { ["path"] = "/etc/passwd", ["operation"] = "write" }));

    [Fact]
    public void delete_outside_scope_flags_os_remove_in_code() =>
        Assert.True(Fires("TG02-delete-outside-scope", new() { ["code"] = "import os\nos.remove(\"/etc/passwd\")" }));

    [Fact]
    public void delete_outside_scope_flags_shutil_rmtree_in_code() =>
        Assert.True(Fires("TG02-delete-outside-scope", new() { ["code"] = "import shutil\nshutil.rmtree(\"/var/data\")" }));

    [Fact]
    public void delete_outside_scope_does_not_flag_delete_in_code_in_scope() =>
        Assert.False(Fires("TG02-delete-outside-scope", new() { ["code"] = "import os\nos.remove(\"./workspace/tmp.txt\")" }));

    [Fact]
    public void chmod_outside_scope_flags_chmod_outside_scope() =>
        Assert.True(Fires("TG02-chmod-outside-scope", new() { ["path"] = "/usr/bin/sudo", ["operation"] = "chmod" }));

    [Fact]
    public void chmod_outside_scope_flags_chown_outside_scope() =>
        Assert.True(Fires("TG02-chmod-outside-scope", new() { ["path"] = "/etc/shadow", ["operation"] = "chown" }));

    [Fact]
    public void chmod_outside_scope_does_not_flag_chmod_inside_scope() =>
        Assert.False(Fires("TG02-chmod-outside-scope", new() { ["path"] = "./workspace/run.sh", ["operation"] = "chmod" }));

    [Fact]
    public void chmod_outside_scope_flags_os_chmod_in_code() =>
        Assert.True(Fires("TG02-chmod-outside-scope", new() { ["code"] = "import os\nos.chmod(\"/usr/bin/sudo\", 0o777)" }));

    [Fact]
    public void chmod_outside_scope_does_not_flag_chmod_in_code_in_scope() =>
        Assert.False(Fires("TG02-chmod-outside-scope", new() { ["code"] = "import os\nos.chmod(\"./workspace/run.sh\", 0o755)" }));

    [Fact]
    public void read_outside_scope_flags_a_read_outside_the_declared_scope() =>
        Assert.True(Fires("TG02-read-outside-scope", new() { ["path"] = "/etc/passwd", ["operation"] = "read" }));

    [Fact]
    public void read_outside_scope_flags_a_get_outside_the_declared_scope() =>
        Assert.True(Fires("TG02-read-outside-scope", new() { ["path"] = "/tmp/secrets.json", ["operation"] = "get" }));

    [Fact]
    public void read_outside_scope_flags_a_fetch_load_outside_the_declared_scope() =>
        Assert.True(Fires("TG02-read-outside-scope", new() { ["path"] = "/var/data/report.csv", ["operation"] = "fetch" }));

    [Fact]
    public void read_outside_scope_does_not_flag_a_read_inside_the_declared_scope() =>
        Assert.False(Fires("TG02-read-outside-scope", new() { ["path"] = "./workspace/notes.txt", ["operation"] = "read" }));

    [Fact]
    public void read_outside_scope_does_not_flag_a_write_outside_scope() =>
        Assert.False(Fires("TG02-read-outside-scope", new() { ["path"] = "/etc/passwd", ["operation"] = "write" }));

    [Fact]
    public void read_outside_scope_flags_a_read_when_no_filesystem_boundary_declared_at_all() =>
        Assert.True(Fires("TG02-read-outside-scope", new() { ["path"] = "/etc/passwd", ["operation"] = "read" }, []));

    [Fact]
    public void read_outside_scope_flags_partial_grant_agent()
    {
        var rule = FilesystemScopeRules.Rules.First(r => r.Id == "TG02-read-outside-scope");
        var ctx = new RuleContext
        {
            AgentId = "agent-1",
            SessionId = "session-1",
            Tool = "fs.readFile",
            Args = new Dictionary<string, object?> { ["path"] = "/etc/passwd", ["operation"] = "read" },
            Scope = new ScopeDeclaration { Network = NetworkScope.True, Filesystem = [], Credentials = [] },
        };
        var result = rule.Evaluate(ctx);
        Assert.NotNull(result);
        Assert.True(result!.Decision is Decision.Deny or Decision.RequireApproval);
    }

    [Fact]
    public void read_outside_scope_infers_read_from_tool_name()
    {
        var rule = FilesystemScopeRules.Rules.First(r => r.Id == "TG02-read-outside-scope");
        var ctx = new RuleContext
        {
            AgentId = "agent-1",
            SessionId = "session-1",
            Tool = "fs.readFile",
            Args = new Dictionary<string, object?> { ["path"] = "/etc/passwd" },
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] },
        };
        Assert.NotNull(rule.Evaluate(ctx));
    }

    [Fact]
    public void read_outside_scope_flags_read_only_payload_embedded_in_code() =>
        Assert.True(Fires("TG02-read-outside-scope", new() { ["code"] = "open(\"/etc/passwd\").read()", ["operation"] = "read" }));

    [Fact]
    public void path_traversal_flags_a_path_with_dotdot_segments() =>
        Assert.True(Fires("TG02-path-traversal", new() { ["path"] = "./workspace/../../etc/passwd", ["operation"] = "write" }));

    [Fact]
    public void path_traversal_flags_a_bare_traversal_path() =>
        Assert.True(Fires("TG02-path-traversal", new() { ["path"] = "../../secrets", ["operation"] = "read" }));

    [Fact]
    public void path_traversal_does_not_flag_a_clean_nested_path() =>
        Assert.False(Fires("TG02-path-traversal", new() { ["path"] = "./workspace/sub/dir/file.txt", ["operation"] = "write" }));

    [Fact]
    public void path_traversal_flags_traversal_payload_embedded_in_code() =>
        Assert.True(Fires("TG02-path-traversal", new()
        {
            ["code"] = "with open(\"../../etc/passwd\") as f:\n    data = f.read()\n    print(data)",
        }));

    [Fact]
    public void path_traversal_flags_node_style_traversal_payload_embedded_in_code() =>
        Assert.True(Fires("TG02-path-traversal", new()
        {
            ["code"] = "const fs = require('fs');\nfs.readFileSync('../../../etc/shadow', 'utf8');",
        }));

    [Fact]
    public void path_traversal_does_not_flag_code_with_no_path_like_literal() =>
        Assert.False(Fires("TG02-path-traversal", new() { ["code"] = "print(1 + 1)" }));

    [Fact]
    public void path_traversal_does_not_flag_clean_path_embedded_in_code() =>
        Assert.False(Fires("TG02-path-traversal", new() { ["code"] = "open(\"./workspace/report.txt\").read()" }));

    [Fact]
    public void symlink_escape_flags_a_symlink_target_outside_scope() =>
        Assert.True(Fires("TG02-symlink-escape", new() { ["path"] = "/etc/passwd", ["operation"] = "symlink" }));

    [Fact]
    public void symlink_escape_does_not_flag_a_symlink_target_inside_scope() =>
        Assert.False(Fires("TG02-symlink-escape", new() { ["path"] = "./workspace/link", ["operation"] = "symlink" }));

    [Fact]
    public void symlink_escape_does_not_flag_a_non_symlink_operation() =>
        Assert.False(Fires("TG02-symlink-escape", new() { ["path"] = "/etc/passwd", ["operation"] = "write" }));

    [Fact]
    public void sensitive_system_path_flags_a_write_to_etc() =>
        Assert.True(Fires("TG02-sensitive-system-path", new() { ["path"] = "/etc/passwd", ["operation"] = "write" }, ["/etc"]));

    [Fact]
    public void sensitive_system_path_flags_a_delete_under_usr() =>
        Assert.True(Fires("TG02-sensitive-system-path", new() { ["path"] = "/usr/bin/node", ["operation"] = "delete" }, ["/usr"]));

    [Fact]
    public void sensitive_system_path_does_not_flag_a_write_under_allowed_workspace_prefix() =>
        Assert.False(Fires("TG02-sensitive-system-path", new() { ["path"] = "./workspace/file", ["operation"] = "write" }));

    [Fact]
    public void sensitive_system_path_still_fires_on_double_leading_slash_scoped_to_etc() =>
        Assert.True(Fires("TG02-sensitive-system-path", new() { ["path"] = "//etc/passwd", ["operation"] = "write" }, ["/etc"]));

    [Fact]
    public void sensitive_system_path_still_fires_on_double_leading_slash_no_scope() =>
        Assert.True(Fires("TG02-sensitive-system-path", new() { ["path"] = "//etc/shadow", ["operation"] = "delete" }));

    [Fact]
    public void sensitive_system_path_fires_with_zero_width_space_in_path() =>
        Assert.True(Fires("TG02-sensitive-system-path", new() { ["path"] = "/e​tc/passwd", ["operation"] = "write" }, ["/etc"]));

    [Fact]
    public void write_outside_scope_fires_with_embedded_zero_width_space() =>
        Assert.True(Fires("TG02-write-outside-scope", new() { ["path"] = "/tmp/ex​port.csv", ["operation"] = "write" }));

    [Fact]
    public void sensitive_system_path_does_not_false_fire_on_in_scope_workspace_path_with_formatting_chars() =>
        Assert.False(Fires("TG02-sensitive-system-path", new() { ["path"] = "./work​space/file", ["operation"] = "write" }));

    [Fact]
    public void every_rule_has_a_unique_id_and_belongs_to_TG02()
    {
        var ids = FilesystemScopeRules.Rules.Select(r => r.Id).ToHashSet();
        Assert.Equal(FilesystemScopeRules.Rules.Count, ids.Count);
        foreach (var rule in FilesystemScopeRules.Rules)
        {
            Assert.Equal("TG02", rule.Category);
        }
    }
}
