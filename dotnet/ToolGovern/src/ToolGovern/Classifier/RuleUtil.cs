using System.Text;
using System.Text.RegularExpressions;
using ToolGovern.Shared;

namespace ToolGovern.Classifier;

/// <summary>
/// Shared argument-extraction helpers for rule implementations. Ported faithfully from the
/// TypeScript original's <c>classifier/util.ts</c>. Real tool-call argument shapes vary a lot
/// across frameworks, so each rule looks for a small set of common key names and falls back to
/// scanning the stringified argument bag -- deliberately permissive (a false negative here is
/// worse than a rare false positive from the string fallback).
/// </summary>
public static partial class RuleUtil
{
    private static readonly string[] CommandKeys = ["command", "cmd", "script", "shell", "code"];
    private static readonly string[] PathKeys = ["path", "target", "dest", "destination", "file", "filepath", "file_path"];
    private static readonly string[] OperationKeys = ["operation", "op", "action", "mode"];
    private static readonly string[] HostKeys = ["host", "hostname", "url", "uri", "endpoint", "address"];
    private static readonly string[] CredentialKeys = ["credential", "secret", "secretName", "credentialId"];

    private static string? FirstString(IReadOnlyDictionary<string, object?> args, IReadOnlyList<string> keys)
    {
        foreach (var key in keys)
        {
            if (args.TryGetValue(key, out var value) && value is string s && s.Length > 0)
            {
                return s;
            }
        }
        return null;
    }

    /// <summary>Extracts a shell-command-like string from common argument key names.</summary>
    public static string? ExtractCommand(IReadOnlyDictionary<string, object?> args) => FirstString(args, CommandKeys);

    /// <summary>Extracts the raw "code" string argument a code-execution tool was invoked with, if any.</summary>
    public static string? ExtractCodeText(IReadOnlyDictionary<string, object?> args) =>
        args.TryGetValue("code", out var value) && value is string s && s.Length > 0 ? s : null;

    /// <summary>Scans a code-execution tool's code string for a path-like literal.</summary>
    public static string? ExtractPathFromCode(string code)
    {
        var callMatch = CodeFileCallRegex().Match(code);
        if (callMatch.Success && callMatch.Groups[1].Success) return callMatch.Groups[1].Value;
        var bareMatch = CodeBarePathRegex().Match(code);
        if (bareMatch.Success && bareMatch.Groups[1].Success) return bareMatch.Groups[1].Value;
        return null;
    }

    /// <summary>Infers a write/delete/chmod operation from a code string's recognized call shapes.</summary>
    public static string? ExtractOperationFromCode(string code)
    {
        if (CodeDeleteRegex().IsMatch(code)) return "delete";
        if (CodeChmodRegex().IsMatch(code)) return "chmod";
        if (CodeWriteCallRegex().IsMatch(code) || CodeOpenWriteModeRegex().IsMatch(code)) return "write";
        return null;
    }

    /// <summary>Extracts a filesystem-path-like string from common argument key names, falling
    /// back to scanning a code string argument.</summary>
    public static string? ExtractPath(IReadOnlyDictionary<string, object?> args)
    {
        var direct = FirstString(args, PathKeys);
        if (direct is not null) return direct;
        var code = ExtractCodeText(args);
        return code is not null ? ExtractPathFromCode(code) : null;
    }

    /// <summary>Extracts a declared filesystem operation, falling back to inferring one from a
    /// code string argument.</summary>
    public static string? ExtractOperation(IReadOnlyDictionary<string, object?> args)
    {
        var direct = FirstString(args, OperationKeys)?.ToLowerInvariant();
        if (direct is not null) return direct;
        var code = ExtractCodeText(args);
        return code is not null ? ExtractOperationFromCode(code) : null;
    }

    /// <summary>Extracts a network host/URL-like string from common argument key names.</summary>
    public static string? ExtractHost(IReadOnlyDictionary<string, object?> args) => FirstString(args, HostKeys);

    /// <summary>Extracts a declared credential identifier from common argument key names.</summary>
    public static string? ExtractCredentialName(IReadOnlyDictionary<string, object?> args) => FirstString(args, CredentialKeys);

    /// <summary>Flattens every string value in the argument bag into one lowercase blob, used as
    /// a fallback scan target for pattern rules when no known key name matches.</summary>
    public static string StringifyArgs(IReadOnlyDictionary<string, object?> args)
    {
        var parts = new List<string>();
        foreach (var value in args.Values)
        {
            switch (value)
            {
                case string s:
                    parts.Add(s);
                    break;
                case null:
                    break;
                case IReadOnlyDictionary<string, object?>:
                case System.Collections.IEnumerable and not string:
                    break;
                default:
                    parts.Add(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "");
                    break;
            }
        }
        return string.Join(' ', parts).ToLowerInvariant();
    }

    private static string CollapseEmptyQuotePairs(string text)
    {
        var current = text;
        string previous;
        do
        {
            previous = current;
            current = EmptyQuotePairRegex().Replace(current, "");
        } while (current != previous);
        return current;
    }

    /// <summary>
    /// Normalizes free-form command/argument text before it is matched against a classifier
    /// pattern: Unicode confusables/invisible characters, $IFS-as-space substitution, and
    /// empty-quote-pair token splitting (cu''rl, r""m). Does not attempt full shell-grammar parsing.
    /// </summary>
    public static string NormalizeForMatch(string text)
    {
        var normalized = text.Normalize(NormalizationForm.FormKC);
        normalized = InvisibleFormatCharsRegex().Replace(normalized, "");
        normalized = IfsSeparatorRegex().Replace(normalized, " ");
        normalized = CollapseEmptyQuotePairs(normalized);
        normalized = BackslashEscapeRegex().Replace(normalized, "$1");
        return normalized;
    }

    public static string NormalizeHost(string hostLike) => PathUtil.NormalizeHost(hostLike);
    public static bool IsPathWithin(string candidate, string prefix) => PathUtil.IsPathWithin(candidate, prefix);
    public static string NormalizePath(string rawPath) => PathUtil.NormalizePath(rawPath);
    public static bool ContainsPathTraversal(string rawPath) => PathUtil.ContainsPathTraversal(rawPath);
    public static bool IsIpLiteral(string host) => PathUtil.IsIpLiteral(host);
    public static bool IsPrivateOrMetadataTarget(string host) => PathUtil.IsPrivateOrMetadataTarget(host);

    private const int MaxHostSearchDepth = 8;

    private static string? FindNestedHost(object? value, int depth = 0)
    {
        if (value is null || depth > MaxHostSearchDepth) return null;

        if (value is System.Collections.IEnumerable enumerable and not string and not IReadOnlyDictionary<string, object?>)
        {
            foreach (var item in enumerable)
            {
                var found = FindNestedHost(item, depth + 1);
                if (found is not null) return found;
            }
            return null;
        }

        if (value is IReadOnlyDictionary<string, object?> record)
        {
            var direct = FirstString(record, HostKeys);
            if (direct is not null) return direct;
            foreach (var nested in record.Values)
            {
                if (nested is IReadOnlyDictionary<string, object?> or (System.Collections.IEnumerable and not string))
                {
                    var found = FindNestedHost(nested, depth + 1);
                    if (found is not null) return found;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Pulls a candidate network host out of an explicit host/url argument -- checked at the top
    /// level first, then recursively through nested objects/arrays -- or otherwise scans a
    /// shell-command-like string for the first http(s):// URL. Returns a normalized hostname.
    /// </summary>
    public static string? ExtractCandidateHost(IReadOnlyDictionary<string, object?> args)
    {
        var explicitHost = ExtractHost(args) ?? FindNestedHost(args);
        if (explicitHost is not null) return PathUtil.NormalizeHost(NormalizeForMatch(explicitHost));

        var command = NormalizeForMatch(ExtractCommand(args) ?? StringifyArgs(args));
        var urlMatch = UrlInCommandRegex().Match(command);
        if (urlMatch.Success) return PathUtil.NormalizeHost(urlMatch.Value);
        return null;
    }

    /// <summary>Extracts whichever resource identifier a credential-scoped call is targeting.</summary>
    public static string? ExtractCredentialIdentifier(IReadOnlyDictionary<string, object?> args) =>
        ExtractCredentialName(args) ?? ExtractPath(args);

    /// <summary>Whether identifier (a path or a named credential) matches an entry in credentials
    /// -- exact match, a trailing path segment match, or a substring match.</summary>
    public static bool IsCredentialGranted(string identifier, IReadOnlyList<string> credentials)
    {
        var lower = identifier.ToLowerInvariant();
        return credentials.Any(granted =>
        {
            var g = granted.ToLowerInvariant();
            return lower == g || lower.EndsWith("/" + g, StringComparison.Ordinal) || lower.Contains(g, StringComparison.Ordinal);
        });
    }

    [GeneratedRegex(
        @"\b(?:open|readfile|readfilesync|writefile|writefilesync|unlink|unlinksync|rmsync|rmdirsync|chmod|chown|chmodsync|chownsync|os\.remove|os\.unlink|os\.rmdir|os\.chmod|os\.chown|fs\.chmod|fs\.chown|shutil\.rmtree|shutil\.copy\w*)\s*\(\s*[""']([^""']+)[""']",
        RegexOptions.IgnoreCase)]
    private static partial Regex CodeFileCallRegex();

    [GeneratedRegex(@"[""'`]((?:\.\./)+[^""'`]*|/(?:[\w.-]+/)*[\w.-]+)[""'`]")]
    private static partial Regex CodeBarePathRegex();

    [GeneratedRegex(
        @"\b(?:os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree|fs\.unlink|fs\.unlinksync|fs\.rm|fs\.rmsync|fs\.rmdir|fs\.rmdirsync|unlinksync|rmsync|rmdirsync)\s*\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex CodeDeleteRegex();

    [GeneratedRegex(
        @"\b(?:os\.chmod|os\.chown|fs\.chmod|fs\.chmodsync|fs\.chown|fs\.chownsync|chmodsync|chownsync)\s*\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex CodeChmodRegex();

    [GeneratedRegex(@"\b(?:writefile|writefilesync|fs\.writefile|fs\.writefilesync|os\.write)\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex CodeWriteCallRegex();

    [GeneratedRegex(@"\bopen\s*\([^)]*?,\s*[""'](\w*[wax]\w*)[""']", RegexOptions.IgnoreCase)]
    private static partial Regex CodeOpenWriteModeRegex();

    [GeneratedRegex("[\\u00AD\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF]")]
    private static partial Regex InvisibleFormatCharsRegex();

    [GeneratedRegex(@"\$\{?IFS\}?(\$\d+)?", RegexOptions.IgnoreCase)]
    private static partial Regex IfsSeparatorRegex();

    [GeneratedRegex(@"(['""])\1")]
    private static partial Regex EmptyQuotePairRegex();

    [GeneratedRegex(@"\\([A-Za-z0-9])")]
    private static partial Regex BackslashEscapeRegex();

    [GeneratedRegex(@"https?://[^\s""'|]+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlInCommandRegex();
}
