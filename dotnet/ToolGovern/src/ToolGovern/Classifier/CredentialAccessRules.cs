using System.Text.RegularExpressions;

namespace ToolGovern.Classifier;

/// <summary>
/// TG04 -- Credential/Secret Access. Fires when a call reads .env, .ssh, .aws/credentials, OS
/// keychain entries, or dumps the bulk process environment, and that resource is not present in
/// the caller's declared credential scope.
/// </summary>
public static partial class CredentialAccessRules
{
    private const string Category = "TG04";

    private static RuleMatch Match(string ruleId, Decision decision, string reason, string matchedArgument) =>
        new(ruleId, Category, decision, reason, matchedArgument);

    private static (string? Path, string Text) PathOrCommandText(RuleContext ctx)
    {
        var path = RuleUtil.ExtractPath(ctx.Args);
        var text = RuleUtil.NormalizeForMatch(path ?? RuleUtil.ExtractCommand(ctx.Args) ?? RuleUtil.StringifyArgs(ctx.Args)).ToLowerInvariant();
        return (path, text);
    }

    private sealed partial class DotenvAccessRule : IRule
    {
        public string Id => "TG04-dotenv-access";
        public string Category => CredentialAccessRules.Category;
        public string Description => "Access to a .env-style file outside the declared credential scope.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var (path, text) = PathOrCommandText(ctx);
            var found = DotenvRegex().Match(text);
            if (!found.Success) return null;
            var identifier = path ?? found.Value.Trim();
            if (RuleUtil.IsCredentialGranted(identifier, ctx.Scope.Credentials)) return null;
            return Match(Id, Decision.Deny, $"Access to \".env\" file \"{identifier}\" not in declared credential scope.", identifier);
        }

        [GeneratedRegex(@"(^|[/\s])\.env(\.\w+)?\b")]
        private static partial Regex DotenvRegex();
    }

    private sealed partial class SshKeyAccessRule : IRule
    {
        public string Id => "TG04-ssh-key-access";
        public string Category => CredentialAccessRules.Category;
        public string Description => "Access to a private SSH key or the .ssh directory.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var (path, text) = PathOrCommandText(ctx);
            var found = SshRegex().Match(text);
            if (!found.Success) return null;
            var identifier = path ?? found.Value;
            if (RuleUtil.IsCredentialGranted(identifier, ctx.Scope.Credentials)) return null;
            return Match(Id, Decision.Deny, $"Access to SSH credential material \"{identifier}\" not in declared credential scope.", identifier);
        }

        [GeneratedRegex(@"\.ssh/(id_\w+|config|authorized_keys)?")]
        private static partial Regex SshRegex();
    }

    private sealed partial class CloudCredentialFileRule : IRule
    {
        public string Id => "TG04-cloud-credential-file";
        public string Category => CredentialAccessRules.Category;
        public string Description => "Access to a cloud provider credential/config file.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var (path, text) = PathOrCommandText(ctx);
            var found = CloudCredentialRegex().Match(text);
            if (!found.Success) return null;
            var identifier = path ?? found.Value;
            if (RuleUtil.IsCredentialGranted(identifier, ctx.Scope.Credentials)) return null;
            return Match(Id, Decision.Deny, $"Access to cloud credential file \"{identifier}\" not in declared credential scope.", identifier);
        }

        [GeneratedRegex(@"\.(aws/(credentials|config)|gcp/[\w.-]+|azure/[\w.-]+|kube/config)")]
        private static partial Regex CloudCredentialRegex();
    }

    private sealed partial class KeychainAccessRule : IRule
    {
        public string Id => "TG04-keychain-access";
        public string Category => CredentialAccessRules.Category;
        public string Description => "Access to an OS-level keychain/secret store.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = RuleUtil.NormalizeForMatch(RuleUtil.ExtractCommand(ctx.Args) ?? RuleUtil.StringifyArgs(ctx.Args)).ToLowerInvariant();
            var found = KeychainRegex().Match(text);
            if (!found.Success) return null;
            return Match(Id, Decision.Deny, "Access to OS keychain/secret-store credential material.", found.Value);
        }

        [GeneratedRegex(@"(security\s+find-generic-password|secret-tool\s+lookup|keytar)")]
        private static partial Regex KeychainRegex();
    }

    private sealed partial class BulkEnvDumpRule : IRule
    {
        public string Id => "TG04-bulk-env-dump";
        public string Category => CredentialAccessRules.Category;
        public string Description => "Unfiltered dump of the full process environment.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = RuleUtil.NormalizeForMatch(RuleUtil.ExtractCommand(ctx.Args) ?? "").ToLowerInvariant().Trim();
            var found = BulkEnvDumpRegex().Match(text);
            if (!found.Success) return null;
            var matched = found.Groups[1].Success ? found.Groups[1].Value : found.Value;
            return Match(Id, Decision.RequireApproval, "Bulk, unfiltered process-environment dump.", matched);
        }

        [GeneratedRegex(@"(?:^|[;&|`]|\$\()\s*(env|printenv|export\s+-p)\s*(?:$|[;&`]|\n|>|\|\s*(?:nc|ncat|curl|wget|ssh|scp|socat|telnet|ftp)\b)")]
        private static partial Regex BulkEnvDumpRegex();
    }

    private sealed class CredentialNameNotInScopeRule : IRule
    {
        public string Id => "TG04-credential-name-not-in-scope";
        public string Category => CredentialAccessRules.Category;
        public string Description => "An explicitly named credential/secret argument is not in the declared scope.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var name = RuleUtil.ExtractCredentialName(ctx.Args);
            if (name is null) return null;
            if (RuleUtil.IsCredentialGranted(name, ctx.Scope.Credentials)) return null;
            return Match(Id, Decision.Deny, $"Credential \"{name}\" is not in the declared credential scope.", name);
        }
    }

    public static readonly IReadOnlyList<IRule> Rules =
    [
        new DotenvAccessRule(),
        new SshKeyAccessRule(),
        new CloudCredentialFileRule(),
        new KeychainAccessRule(),
        new BulkEnvDumpRule(),
        new CredentialNameNotInScopeRule(),
    ];
}
