using System.Text;
using ToolGovern;
using ToolGovern.Trace;
using Xunit;

namespace ToolGovern.Tests.Trace;

public class TraceReaderTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    private string MakeTempTraceFile()
    {
        var dir = Directory.CreateTempSubdirectory("toolgovern-trace-reader-").FullName;
        _tempDirs.Add(dir);
        return Path.Combine(dir, "trace.jsonl");
    }

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    private static readonly ScopeDeclaration EmptyScope = new() { Network = NetworkScope.False, Filesystem = [], Credentials = [] };

    [Fact]
    public async Task reads_back_exactly_what_was_written_skipping_blank_lines()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash", Args = new Dictionary<string, object?>(),
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash", Args = new Dictionary<string, object?>(),
            Decision = Decision.Deny, RuleFired = ["TG01-rm-rf"], DeclaredScope = EmptyScope,
        });

        var entries = await TraceReader.ReadTrace(filePath);
        Assert.Equal(2, entries.Count);
        Assert.Equal(Decision.Deny, entries[1].Decision);
    }

    [Fact]
    public async Task throws_a_descriptive_error_on_a_malformed_line()
    {
        var filePath = MakeTempTraceFile();
        await File.WriteAllTextAsync(filePath, "{not valid json}\n", Encoding.UTF8);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => TraceReader.ReadTrace(filePath));
        Assert.Contains("Malformed trace line", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void parse_since_parses_minutes()
    {
        var now = new DateTimeOffset(2026, 7, 11, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2026, 7, 11, 11, 30, 0, TimeSpan.Zero), TraceReader.ParseSince("30m", now));
    }

    [Fact]
    public void parse_since_parses_hours()
    {
        var now = new DateTimeOffset(2026, 7, 11, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero), TraceReader.ParseSince("24h", now));
    }

    [Fact]
    public void parse_since_parses_days()
    {
        var now = new DateTimeOffset(2026, 7, 11, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2026, 7, 4, 12, 0, 0, TimeSpan.Zero), TraceReader.ParseSince("7d", now));
    }

    [Fact]
    public void parse_since_parses_an_iso_timestamp_directly()
    {
        var now = new DateTimeOffset(2026, 7, 11, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero), TraceReader.ParseSince("2026-07-01T00:00:00.000Z", now));
    }

    [Fact]
    public void parse_since_throws_on_an_invalid_value() =>
        Assert.Throws<ArgumentException>(() => TraceReader.ParseSince("not-a-window"));

    private static List<TraceEntry> BuildFilterFixture()
    {
        var baseEntry = new TraceEntry
        {
            TraceId = "t1", Timestamp = "2026-07-11T10:00:00.000Z", SessionId = "s1", AgentId = "coordinator",
            Tool = "bash", ArgumentsHash = "sha256:aaa", Decision = Decision.Allow, RuleFired = [],
            DeclaredScope = EmptyScope, Signature = "sha256:bbb", PriorTraceId = null,
        };
        return
        [
            baseEntry,
            new TraceEntry
            {
                TraceId = "t2", Timestamp = baseEntry.Timestamp, SessionId = "s1", AgentId = "research-sub",
                Tool = "bash", ArgumentsHash = "sha256:aaa", Decision = Decision.Deny, RuleFired = ["TG01-rm-rf"],
                DeclaredScope = EmptyScope, Signature = "sha256:bbb", PriorTraceId = null,
            },
            new TraceEntry
            {
                TraceId = "t3", Timestamp = "2026-07-01T00:00:00.000Z", SessionId = "s1", AgentId = "research-sub",
                Tool = "bash", ArgumentsHash = "sha256:aaa", Decision = Decision.RequireApproval,
                RuleFired = ["TG02-write-outside-scope"], DeclaredScope = EmptyScope, Signature = "sha256:bbb", PriorTraceId = null,
            },
        ];
    }

    [Fact]
    public void filter_trace_filters_by_decision() =>
        Assert.Single(TraceReader.FilterTrace(BuildFilterFixture(), new TraceReader.TraceQuery { Decision = Decision.Deny }));

    [Fact]
    public void filter_trace_filters_by_agent_id() =>
        Assert.Equal(2, TraceReader.FilterTrace(BuildFilterFixture(), new TraceReader.TraceQuery { AgentId = "research-sub" }).Count);

    [Fact]
    public void filter_trace_filters_by_rule_id() =>
        Assert.Single(TraceReader.FilterTrace(BuildFilterFixture(), new TraceReader.TraceQuery { RuleId = "TG02-write-outside-scope" }));

    [Fact]
    public void filter_trace_filters_by_a_since_window_excluding_older_entries()
    {
        var result = TraceReader.FilterTrace(BuildFilterFixture(), new TraceReader.TraceQuery { Since = "2026-07-05T00:00:00.000Z" });
        Assert.Equal(["t1", "t2"], result.Select(e => e.TraceId));
    }

    [Fact]
    public void filter_trace_combines_multiple_filters()
    {
        var result = TraceReader.FilterTrace(BuildFilterFixture(), new TraceReader.TraceQuery { AgentId = "research-sub", Decision = Decision.Deny });
        Assert.Equal(["t2"], result.Select(e => e.TraceId));
    }

    [Fact]
    public void filter_trace_returns_everything_when_no_filters_given() =>
        Assert.Equal(3, TraceReader.FilterTrace(BuildFilterFixture(), new TraceReader.TraceQuery()).Count);

    [Fact]
    public async Task verify_chain_validates_a_chain_written_by_trace_writer()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "pwd" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });

        var entries = await TraceReader.ReadTrace(filePath);
        var result = TraceReader.VerifyChain(entries);
        Assert.True(result.Valid);
        Assert.Empty(result.Issues);
    }

    [Fact]
    public async Task verify_chain_detects_a_tampered_signature()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        var entries = await TraceReader.ReadTrace(filePath);
        var tampered = CloneWithDecision(entries[0], Decision.Deny);

        var result = TraceReader.VerifyChain([tampered]);
        Assert.False(result.Valid);
        Assert.Contains("Signature does not match", result.Issues[0].Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task verify_chain_does_not_throw_on_a_truncated_signature()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        var entries = await TraceReader.ReadTrace(filePath);
        var truncated = CloneWithSignature(entries[0], entries[0].Signature[..^4]);

        var result = TraceReader.VerifyChain([truncated]);
        Assert.False(result.Valid);
        Assert.Contains("Signature does not match", result.Issues[0].Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task documents_the_residual_limitation_of_the_unkeyed_sha256_scheme()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        var entries = await TraceReader.ReadTrace(filePath);
        var tampered = CloneWithDecision(entries[0], Decision.Deny);
        var forged = CloneWithSignature(tampered, TraceWriter.ComputeEntrySignature(tampered));

        var result = TraceReader.VerifyChain([forged]);
        // Documented v0.1 limitation, not a passing "security" assertion: without a secret key,
        // anyone with write access to the trace file can recompute a valid signature after
        // tampering.
        Assert.True(result.Valid);
    }

    private static readonly byte[] TestSecretKey = Encoding.UTF8.GetBytes("test-only-secret-key-do-not-use-in-real-deployments");

    [Fact]
    public async Task hmac_verifies_a_chain_written_with_a_secret_key()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath, TestSecretKey);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        var entries = await TraceReader.ReadTrace(filePath);
        Assert.StartsWith("hmac-sha256:", entries[0].Signature, StringComparison.Ordinal);
        var result = TraceReader.VerifyChain(entries, new TraceReader.VerifyChainOptions { SecretKey = TestSecretKey });
        Assert.True(result.Valid);
    }

    [Fact]
    public async Task hmac_verifies_a_chain_written_without_a_key_even_if_a_key_is_supplied_anyway()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        var entries = await TraceReader.ReadTrace(filePath);
        Assert.StartsWith("sha256:", entries[0].Signature, StringComparison.Ordinal);
        var result = TraceReader.VerifyChain(entries, new TraceReader.VerifyChainOptions { SecretKey = TestSecretKey });
        Assert.True(result.Valid);
    }

    [Fact]
    public async Task hmac_reports_an_issue_when_no_key_supplied_to_verify_an_hmac_signed_entry()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath, TestSecretKey);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        var entries = await TraceReader.ReadTrace(filePath);
        var result = TraceReader.VerifyChain(entries);
        Assert.False(result.Valid);
        Assert.Contains("no secretKey was supplied", result.Issues[0].Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task hmac_catches_tampering_the_unkeyed_scheme_would_miss()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath, TestSecretKey);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        var entries = await TraceReader.ReadTrace(filePath);
        var tampered = CloneWithDecision(entries[0], Decision.Deny);
        var forged = CloneWithSignature(tampered, TraceWriter.ComputeEntrySignature(tampered, Encoding.UTF8.GetBytes("wrong-key")));

        var result = TraceReader.VerifyChain([forged], new TraceReader.VerifyChainOptions { SecretKey = TestSecretKey });
        Assert.False(result.Valid);
        Assert.Contains("Signature does not match", result.Issues[0].Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void verify_chain_rejects_an_entry_with_an_unrecognized_signature_scheme()
    {
        var entry = new TraceEntry
        {
            TraceId = "t1", Timestamp = "2026-07-11T10:00:00.000Z", SessionId = "s1", AgentId = "a",
            Tool = "bash", ArgumentsHash = "sha256:aaa", Decision = Decision.Allow, RuleFired = [],
            DeclaredScope = EmptyScope, Signature = "md5:deadbeef", PriorTraceId = null,
        };
        var result = TraceReader.VerifyChain([entry]);
        Assert.False(result.Valid);
        Assert.Contains("Unrecognized signature scheme", result.Issues[0].Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task detects_a_broken_prior_trace_id_chain()
    {
        var filePath = MakeTempTraceFile();
        var writer = new TraceWriter(filePath);
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash", Args = new Dictionary<string, object?>(),
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });
        await writer.Append(new TraceEntryInput
        {
            SessionId = "s1", AgentId = "a", Tool = "bash", Args = new Dictionary<string, object?>(),
            Decision = Decision.Allow, RuleFired = [], DeclaredScope = EmptyScope,
        });

        var entries = await TraceReader.ReadTrace(filePath);
        var brokenChain = new List<TraceEntry> { entries[1] };
        var result = TraceReader.VerifyChain(brokenChain);
        Assert.False(result.Valid);
        Assert.Contains(result.Issues, i => i.Reason.Contains("prior_trace_id", StringComparison.Ordinal));
    }

    private static TraceEntry CloneWithDecision(TraceEntry entry, Decision decision) => new()
    {
        TraceId = entry.TraceId, Timestamp = entry.Timestamp, SessionId = entry.SessionId, AgentId = entry.AgentId,
        Tool = entry.Tool, ArgumentsHash = entry.ArgumentsHash, Decision = decision, RuleFired = entry.RuleFired,
        DeclaredScope = entry.DeclaredScope, AgentIdSource = entry.AgentIdSource, Signature = entry.Signature,
        PriorTraceId = entry.PriorTraceId, ApprovedBy = entry.ApprovedBy,
    };

    private static TraceEntry CloneWithSignature(TraceEntry entry, string signature) => new()
    {
        TraceId = entry.TraceId, Timestamp = entry.Timestamp, SessionId = entry.SessionId, AgentId = entry.AgentId,
        Tool = entry.Tool, ArgumentsHash = entry.ArgumentsHash, Decision = entry.Decision, RuleFired = entry.RuleFired,
        DeclaredScope = entry.DeclaredScope, AgentIdSource = entry.AgentIdSource, Signature = signature,
        PriorTraceId = entry.PriorTraceId, ApprovedBy = entry.ApprovedBy,
    };
}
