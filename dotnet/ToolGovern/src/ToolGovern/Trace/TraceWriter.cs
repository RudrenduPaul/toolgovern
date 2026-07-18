using System.Security.Cryptography;
using System.Text;

namespace ToolGovern.Trace;

/// <summary>
/// Signed, append-only JSON Lines trace writer.
///
/// Every gate decision -- allow, deny, or require-approval -- gets one line. <c>PriorTraceId</c>
/// chains each entry to the one before it in the same session, so a reader can walk the chain and
/// detect a missing, reordered, or tampered entry.
///
/// By default, "signed" means a <c>sha256:</c> content hash, not a keyed signature -- a
/// deliberate default that needs no key management: it proves an entry has not changed since it
/// was written, but it does not stop someone with write access to the trace file from editing an
/// entry and recomputing a signature that still passes. Pass a <c>secretKey</c> in the
/// constructor to sign with <c>hmac-sha256:</c> instead, which closes that gap for anyone who
/// does not also hold the key.
/// </summary>
public sealed class TraceWriter
{
    private readonly string _filePath;
    private readonly byte[]? _secretKey;

    /// <summary>Tracks the last trace_id written per session so entries chain correctly across calls.</summary>
    private readonly Dictionary<string, string?> _lastTraceIdBySession = new();
    private Task _writeQueue = Task.CompletedTask;
    private readonly object _queueLock = new();

    public TraceWriter(string filePath, byte[]? secretKey = null)
    {
        _filePath = filePath;
        _secretKey = secretKey;
    }

    private static string Sha256Hex(string content) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    private static string HmacSha256Hex(byte[] key, string content) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(content)));

    /// <summary>Computes the content hash a TraceEntry should have, given everything except
    /// Signature. This is the unkeyed form -- kept as the fallback sha256: scheme
    /// ComputeEntrySignature() uses when no secret key is configured.</summary>
    public static string ComputeEntryContentHash(TraceEntry entry)
    {
        var content = TraceEntryCodec.ContentDict(
            entry.TraceId, entry.Timestamp, entry.SessionId, entry.AgentId, entry.Tool,
            entry.ArgumentsHash, entry.Decision, entry.RuleFired, entry.DeclaredScope,
            entry.AgentIdSource, entry.PriorTraceId, entry.ApprovedBy);
        return Sha256Hex(CanonicalJson.Serialize(content));
    }

    /// <summary>
    /// Computes what Signature should be for entry (everything except Signature). With no
    /// secretKey, this is sha256:&lt;hex&gt; of the entry's canonicalized content. With a
    /// secretKey, this is hmac-sha256:&lt;hex&gt; -- only someone holding the same key can produce
    /// a signature that verifies.
    /// </summary>
    public static string ComputeEntrySignature(TraceEntry entry, byte[]? secretKey = null)
    {
        var content = CanonicalJson.Serialize(TraceEntryCodec.ContentDict(
            entry.TraceId, entry.Timestamp, entry.SessionId, entry.AgentId, entry.Tool,
            entry.ArgumentsHash, entry.Decision, entry.RuleFired, entry.DeclaredScope,
            entry.AgentIdSource, entry.PriorTraceId, entry.ApprovedBy));
        return secretKey is not null
            ? $"hmac-sha256:{HmacSha256Hex(secretKey, content)}"
            : $"sha256:{Sha256Hex(content)}";
    }

    /// <summary>Appends one gate decision to the trace file and returns the entry that was written.</summary>
    public async Task<TraceEntry> Append(TraceEntryInput input)
    {
        var priorTraceId = _lastTraceIdBySession.GetValueOrDefault(input.SessionId);
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var argumentsHash = $"sha256:{Sha256Hex(CanonicalJson.Serialize(input.Args))}";
        var ruleFired = input.RuleFired.ToList();

        // trace_id is derived from the entry's own (unkeyed) content hash -- it is an identifier,
        // not a security boundary, so it stays reproducible/public even when the signature is keyed.
        var idSeedContent = TraceEntryCodec.ContentDict(
            "", timestamp, input.SessionId, input.AgentId, input.Tool, argumentsHash,
            input.Decision, ruleFired, input.DeclaredScope, input.AgentIdSource, priorTraceId, input.ApprovedBy);
        var idSeedHash = Sha256Hex(CanonicalJson.Serialize(idSeedContent));
        var traceId = $"tg_{timestamp[..10]}_{idSeedHash[..6]}";

        var entryForSigning = new TraceEntry
        {
            TraceId = traceId,
            Timestamp = timestamp,
            SessionId = input.SessionId,
            AgentId = input.AgentId,
            Tool = input.Tool,
            ArgumentsHash = argumentsHash,
            Decision = input.Decision,
            RuleFired = ruleFired,
            DeclaredScope = input.DeclaredScope,
            AgentIdSource = input.AgentIdSource,
            Signature = "",
            PriorTraceId = priorTraceId,
            ApprovedBy = input.ApprovedBy,
        };
        var signature = ComputeEntrySignature(entryForSigning, _secretKey);
        var entry = new TraceEntry
        {
            TraceId = traceId,
            Timestamp = timestamp,
            SessionId = input.SessionId,
            AgentId = input.AgentId,
            Tool = input.Tool,
            ArgumentsHash = argumentsHash,
            Decision = input.Decision,
            RuleFired = ruleFired,
            DeclaredScope = input.DeclaredScope,
            AgentIdSource = input.AgentIdSource,
            Signature = signature,
            PriorTraceId = priorTraceId,
            ApprovedBy = input.ApprovedBy,
        };

        // Serialize writes so concurrent calls within one process never interleave lines or race
        // on _lastTraceIdBySession, which would silently break the chain.
        Task previous;
        lock (_queueLock)
        {
            previous = _writeQueue;
            _writeQueue = WriteLineAfter(previous, entry);
            previous = _writeQueue;
        }
        await previous;

        _lastTraceIdBySession[input.SessionId] = traceId;
        return entry;
    }

    private async Task WriteLineAfter(Task previous, TraceEntry entry)
    {
        await previous.ConfigureAwait(false);
        var dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        var line = CanonicalJson.Serialize(TraceEntryCodec.FullDict(entry)) + "\n";
        await File.AppendAllTextAsync(_filePath, line, Encoding.UTF8).ConfigureAwait(false);
    }
}
