namespace ToolGovern.Classifier;

/// <summary>
/// TG02 -- Filesystem Scope Escalation. Fires when a call attempts a write, delete, or permission
/// change outside the caller's declared filesystem scope, or targets a small set of sensitive
/// absolute system directories regardless of scope.
/// </summary>
public static class FilesystemScopeRules
{
    private const string Category = "TG02";

    private static readonly HashSet<string> WriteOps = ["write", "create", "append", "put", "save"];
    private static readonly HashSet<string> DeleteOps = ["delete", "remove", "unlink", "rm", "rmdir"];
    private static readonly HashSet<string> ChmodOps = ["chmod", "chown", "setpermissions", "set_permissions"];
    private static readonly HashSet<string> ReadOps = ["read", "get", "load", "fetch", "cat", "open"];
    private static readonly string[] SensitiveSystemPrefixes = ["/etc", "/usr", "/bin", "/sbin", "/system", "/private/etc"];

    private static string? ExtractNormalizedPath(IReadOnlyDictionary<string, object?> args)
    {
        var raw = RuleUtil.ExtractPath(args);
        return raw is not null ? RuleUtil.NormalizeForMatch(raw) : null;
    }

    private static bool IsWithinScope(string path, IReadOnlyList<string> filesystem) =>
        filesystem.Count != 0 && filesystem.Any(prefix => RuleUtil.IsPathWithin(path, prefix));

    private static RuleMatch Match(string ruleId, Decision decision, string reason, string matchedArgument) =>
        new(ruleId, Category, decision, reason, matchedArgument);

    private sealed class WriteOutsideScopeRule : IRule
    {
        public string Id => "TG02-write-outside-scope";
        public string Category => FilesystemScopeRules.Category;
        public string Description => "A write/create targets a path outside the declared filesystem scope.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var path = ExtractNormalizedPath(ctx.Args);
            if (path is null) return null;
            var op = RuleUtil.ExtractOperation(ctx.Args) ?? (ctx.Tool.Contains("write", StringComparison.OrdinalIgnoreCase) ? "write" : "");
            if (!WriteOps.Contains(op)) return null;
            if (IsWithinScope(path, ctx.Scope.Filesystem)) return null;
            return Match(Id, Decision.RequireApproval, $"Write target \"{path}\" is outside the declared filesystem scope.", path);
        }
    }

    private sealed class DeleteOutsideScopeRule : IRule
    {
        public string Id => "TG02-delete-outside-scope";
        public string Category => FilesystemScopeRules.Category;
        public string Description => "A delete targets a path outside the declared filesystem scope.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var path = ExtractNormalizedPath(ctx.Args);
            if (path is null) return null;
            var op = RuleUtil.ExtractOperation(ctx.Args) ?? (ctx.Tool.Contains("delete", StringComparison.OrdinalIgnoreCase) ? "delete" : "");
            if (!DeleteOps.Contains(op)) return null;
            if (IsWithinScope(path, ctx.Scope.Filesystem)) return null;
            return Match(Id, Decision.Deny, $"Delete target \"{path}\" is outside the declared filesystem scope.", path);
        }
    }

    private sealed class ChmodOutsideScopeRule : IRule
    {
        public string Id => "TG02-chmod-outside-scope";
        public string Category => FilesystemScopeRules.Category;
        public string Description => "A permission change targets a path outside the declared filesystem scope.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var path = ExtractNormalizedPath(ctx.Args);
            if (path is null) return null;
            var op = RuleUtil.ExtractOperation(ctx.Args);
            if (op is null || !ChmodOps.Contains(op)) return null;
            if (IsWithinScope(path, ctx.Scope.Filesystem)) return null;
            return Match(Id, Decision.Deny, $"Permission change on \"{path}\" is outside the declared filesystem scope.", path);
        }
    }

    private sealed class ReadOutsideScopeRule : IRule
    {
        public string Id => "TG02-read-outside-scope";
        public string Category => FilesystemScopeRules.Category;
        public string Description =>
            "A read targets a path outside the caller's declared filesystem scope. An empty filesystem " +
            "scope means nothing is in scope, so any concrete path read is out of scope and flagged, unless " +
            "the path matches an entry explicitly granted via scope.credentials.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var path = ExtractNormalizedPath(ctx.Args);
            if (path is null) return null;
            var op = RuleUtil.ExtractOperation(ctx.Args) ?? (ctx.Tool.Contains("read", StringComparison.OrdinalIgnoreCase) ? "read" : "");
            if (!ReadOps.Contains(op)) return null;
            if (IsWithinScope(path, ctx.Scope.Filesystem)) return null;
            if (RuleUtil.IsCredentialGranted(path, ctx.Scope.Credentials)) return null;
            return Match(Id, Decision.RequireApproval, $"Read target \"{path}\" is outside the declared filesystem scope.", path);
        }
    }

    private sealed class PathTraversalRule : IRule
    {
        public string Id => "TG02-path-traversal";
        public string Category => FilesystemScopeRules.Category;
        public string Description => "A path uses \"..\" segments that could escape a scoped prefix.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var path = ExtractNormalizedPath(ctx.Args);
            if (path is null) return null;
            if (!RuleUtil.ContainsPathTraversal(path)) return null;
            return Match(Id, Decision.Deny, $"Path \"{path}\" contains traversal segments (\"..\").", path);
        }
    }

    private sealed class SymlinkEscapeRule : IRule
    {
        public string Id => "TG02-symlink-escape";
        public string Category => FilesystemScopeRules.Category;
        public string Description => "A symlink/link operation targets a path outside the declared filesystem scope.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var op = RuleUtil.ExtractOperation(ctx.Args) ?? "";
            if (!op.Contains("symlink", StringComparison.Ordinal) && !op.Contains("link", StringComparison.Ordinal)) return null;
            var path = ExtractNormalizedPath(ctx.Args);
            if (path is null) return null;
            if (IsWithinScope(path, ctx.Scope.Filesystem)) return null;
            return Match(Id, Decision.Deny, $"Symlink target \"{path}\" is outside the declared filesystem scope.", path);
        }
    }

    private sealed class SensitiveSystemPathRule : IRule
    {
        public string Id => "TG02-sensitive-system-path";
        public string Category => FilesystemScopeRules.Category;
        public string Description => "A write/delete targets a sensitive absolute system directory.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var path = ExtractNormalizedPath(ctx.Args);
            if (path is null) return null;
            var op = RuleUtil.ExtractOperation(ctx.Args) ?? "";
            if (!WriteOps.Contains(op) && !DeleteOps.Contains(op) && !ChmodOps.Contains(op)) return null;
            var lower = path.ToLowerInvariant();
            var hit = SensitiveSystemPrefixes.FirstOrDefault(prefix => RuleUtil.IsPathWithin(lower, prefix));
            if (hit is null) return null;
            return Match(Id, Decision.Deny, $"Target \"{path}\" is under a sensitive system directory ({hit}).", path);
        }
    }

    public static readonly IReadOnlyList<IRule> Rules =
    [
        new WriteOutsideScopeRule(),
        new DeleteOutsideScopeRule(),
        new ChmodOutsideScopeRule(),
        new ReadOutsideScopeRule(),
        new PathTraversalRule(),
        new SymlinkEscapeRule(),
        new SensitiveSystemPathRule(),
    ];
}
