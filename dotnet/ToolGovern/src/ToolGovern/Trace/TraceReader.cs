using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ToolGovern.Trace;

/// <summary>
/// Reads a JSON Lines trace file for local inspection, filtering, and chain verification.
/// </summary>
public static partial class TraceReader
{
    /// <summary>Constant-time comparison of two signature strings.</summary>
    private static bool SignaturesMatch(string actual, string expected)
    {
        var actualBuf = Encoding.UTF8.GetBytes(actual);
        var expectedBuf = Encoding.UTF8.GetBytes(expected);
        if (actualBuf.Length != expectedBuf.Length) return false;
        return CryptographicOperations.FixedTimeEquals(actualBuf, expectedBuf);
    }

    public sealed class TraceQuery
    {
        /// <summary>A relative time window, e.g. "24h", "7d", "30m", or an absolute ISO 8601 timestamp.</summary>
        public string? Since { get; init; }
        public Decision? Decision { get; init; }
        public string? AgentId { get; init; }
        /// <summary>Matches entries where this rule ID appears anywhere in RuleFired.</summary>
        public string? RuleId { get; init; }
    }

    public sealed record ChainVerificationIssue(string TraceId, string Reason);

    public sealed record ChainVerificationResult(bool Valid, IReadOnlyList<ChainVerificationIssue> Issues);

    public sealed class VerifyChainOptions
    {
        /// <summary>Required to verify entries signed with hmac-sha256:. Entries signed with the
        /// legacy unkeyed sha256: scheme verify without it.</summary>
        public byte[]? SecretKey { get; init; }
    }

    /// <summary>Reads and parses every line of a JSON Lines trace file. Blank lines are skipped.</summary>
    public static async Task<List<TraceEntry>> ReadTrace(string filePath)
    {
        var raw = await File.ReadAllTextAsync(filePath, Encoding.UTF8);
        var entries = new List<TraceEntry>();
        var lines = raw.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].Trim();
            if (trimmed.Length == 0) continue;
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                entries.Add(TraceEntryCodec.FromJsonElement(doc.RootElement.Clone()));
            }
            catch (JsonException cause)
            {
                throw new InvalidOperationException($"Malformed trace line {i + 1} in {filePath}: not valid JSON", cause);
            }
        }
        return entries;
    }

    [GeneratedRegex(@"^(\d+)(m|h|d)$")]
    private static partial Regex SincePattern();

    /// <summary>Parses a since window string into an absolute cutoff DateTimeOffset.</summary>
    public static DateTimeOffset ParseSince(string since, DateTimeOffset? now = null)
    {
        var nowValue = now ?? DateTimeOffset.UtcNow;
        var match = SincePattern().Match(since);
        if (!match.Success)
        {
            if (DateTimeOffset.TryParse(since, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var asDate))
            {
                return asDate;
            }
            throw new ArgumentException($"Invalid --since value \"{since}\". Use \"<n>m\", \"<n>h\", \"<n>d\", or an ISO 8601 timestamp.");
        }
        var amount = int.Parse(match.Groups[1].Value);
        var unit = match.Groups[2].Value;
        var msPerUnit = unit switch
        {
            "m" => 60_000,
            "h" => 3_600_000,
            _ => 86_400_000,
        };
        return nowValue.AddMilliseconds(-(double)amount * msPerUnit);
    }

    /// <summary>Filters trace entries by time window, decision, agent identity, and/or fired rule ID.</summary>
    public static List<TraceEntry> FilterTrace(IReadOnlyList<TraceEntry> entries, TraceQuery query)
    {
        DateTimeOffset? cutoff = query.Since is not null ? ParseSince(query.Since) : null;
        return entries.Where(entry =>
        {
            if (cutoff is not null && DateTimeOffset.Parse(entry.Timestamp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal) < cutoff.Value) return false;
            if (query.Decision is not null && entry.Decision != query.Decision.Value) return false;
            if (query.AgentId is not null && entry.AgentId != query.AgentId) return false;
            if (query.RuleId is not null && !entry.RuleFired.Contains(query.RuleId)) return false;
            return true;
        }).ToList();
    }

    /// <summary>
    /// Recomputes each entry's signature and confirms it matches Signature, and confirms
    /// PriorTraceId correctly links to the previous entry in the same session. Returns every
    /// issue found rather than stopping at the first one.
    /// </summary>
    public static ChainVerificationResult VerifyChain(IReadOnlyList<TraceEntry> entries, VerifyChainOptions? options = null)
    {
        options ??= new VerifyChainOptions();
        var issues = new List<ChainVerificationIssue>();
        var lastSeenBySession = new Dictionary<string, string?>();

        foreach (var entry in entries)
        {
            var scheme = entry.Signature.Split(':', 2)[0];
            if (scheme == "hmac-sha256" && options.SecretKey is null)
            {
                issues.Add(new ChainVerificationIssue(entry.TraceId,
                    "Entry is signed with hmac-sha256 but no secretKey was supplied to verify it."));
            }
            else if (scheme is "hmac-sha256" or "sha256")
            {
                var expected = TraceWriter.ComputeEntrySignature(entry, scheme == "hmac-sha256" ? options.SecretKey : null);
                if (!SignaturesMatch(entry.Signature, expected))
                {
                    issues.Add(new ChainVerificationIssue(entry.TraceId, "Signature does not match entry content."));
                }
            }
            else
            {
                issues.Add(new ChainVerificationIssue(entry.TraceId, $"Unrecognized signature scheme \"{scheme}\"."));
            }

            var expectedPrior = lastSeenBySession.GetValueOrDefault(entry.SessionId);
            if (entry.PriorTraceId != expectedPrior)
            {
                issues.Add(new ChainVerificationIssue(entry.TraceId,
                    $"prior_trace_id \"{entry.PriorTraceId ?? "null"}\" does not match the expected previous entry \"{expectedPrior ?? "null"}\" for session \"{entry.SessionId}\"."));
            }
            lastSeenBySession[entry.SessionId] = entry.TraceId;
        }

        return new ChainVerificationResult(issues.Count == 0, issues);
    }
}
