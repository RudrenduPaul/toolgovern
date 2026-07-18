namespace ToolGovern.Scoping;

/// <summary>
/// Helpers for validating and comparing <see cref="ScopeDeclaration"/> values. A ScopeDeclaration
/// is intentionally simple: an agent gets access to what it declares, and nothing else.
/// </summary>
public static class ScopeDeclarationHelpers
{
    /// <summary>The empty scope: no network, no filesystem, no credentials. This is the
    /// default-deny floor.</summary>
    public static readonly ScopeDeclaration EmptyScope = new()
    {
        Network = NetworkScope.False,
        Filesystem = [],
        Credentials = [],
    };

    /// <summary>Generous ceiling on agentId length. Not a protocol limit -- just large enough that
    /// no realistic identity scheme trips it, while still rejecting unbounded strings that look
    /// like a buffer-abuse or log-flooding attempt.</summary>
    private const int MaxAgentIdLength = 256;

    /// <summary>Code points with no legitimate reason to appear in an agent identity string: ASCII
    /// control characters (0x00-0x1F, 0x7F) and the Unicode line/paragraph separators (0x2028,
    /// 0x2029). Letting them through invites log-injection, null-byte truncation tricks, or
    /// terminal/ANSI escape abuse.</summary>
    private static bool IsDisallowedControlCodeUnit(char c) =>
        (c >= 0x00 && c <= 0x1f) || c == 0x7f || c == 0x2028 || c == 0x2029;

    /// <summary>
    /// Format-only validation for an agentId string.
    ///
    /// IMPORTANT -- what this is NOT: this does not verify that a caller actually is the agent it
    /// claims to be. toolgovern has no cryptographic identity verification mechanism; any caller
    /// can still supply any well-formed agentId and have it accepted as-is. A string that passes
    /// IsValidAgentId is merely well-formed -- it remains just as much a bare, unverified claim as
    /// any other string that passes.
    ///
    /// What this DOES do: reject a narrow, concrete class of malformed/malicious inputs -- an
    /// empty string, a string past a sane length ceiling, or a string containing control
    /// characters/embedded null bytes that could be used for log injection or to confuse
    /// downstream string handling. This is a hygiene filter, not an authentication mechanism.
    /// </summary>
    public static bool IsValidAgentId(string? value)
    {
        if (value is null) return false;
        if (value.Length == 0) return false;
        if (value.Length > MaxAgentIdLength) return false;
        foreach (var c in value)
        {
            if (IsDisallowedControlCodeUnit(c)) return false;
        }
        return true;
    }
}
