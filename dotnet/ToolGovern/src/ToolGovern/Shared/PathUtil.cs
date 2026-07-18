using System.Text.RegularExpressions;

namespace ToolGovern.Shared;

/// <summary>
/// Low-level path/host normalization helpers shared by the classifier and the scoping registry.
/// Ported faithfully from the TypeScript original's <c>shared/paths.ts</c>.
/// </summary>
public static partial class PathUtil
{
    /// <summary>Collapses "./", trailing slashes, and duplicate slashes for stable prefix comparison.</summary>
    public static string NormalizePath(string rawPath)
    {
        var path = rawPath.Trim();
        if (path.StartsWith("./", StringComparison.Ordinal))
        {
            path = path[2..];
        }
        path = MultiSlashRegex().Replace(path, "/");
        if (path.Length > 1 && path.EndsWith('/'))
        {
            path = path[..^1];
        }
        return path;
    }

    /// <summary>True if candidate is equal to, or a path-segment child of, prefix.</summary>
    public static bool IsPathWithin(string candidate, string prefix)
    {
        var normalizedCandidate = NormalizePath(candidate);
        var normalizedPrefix = NormalizePath(prefix);
        if (normalizedPrefix.Length == 0 || normalizedPrefix == ".")
        {
            return true;
        }
        return normalizedCandidate == normalizedPrefix
            || normalizedCandidate.StartsWith(normalizedPrefix + "/", StringComparison.Ordinal);
    }

    /// <summary>True if the path contains a ".." segment that could escape a scoped prefix via traversal.</summary>
    public static bool ContainsPathTraversal(string rawPath) =>
        rawPath.Split('/').Contains("..");

    /// <summary>Best-effort hostname extraction from a bare host string or a full URL.</summary>
    public static string NormalizeHost(string hostLike)
    {
        var trimmed = hostLike.Trim();
        if (SchemePrefixRegex().IsMatch(trimmed))
        {
            try
            {
                var uri = new Uri(trimmed);
                return uri.Host.ToLowerInvariant();
            }
            catch (UriFormatException)
            {
                // fall through to the raw-string heuristics below
            }
        }

        var withoutPath = trimmed.Split('/')[0];
        var bracketed = BracketedHostRegex().Match(withoutPath);
        if (bracketed.Success)
        {
            return bracketed.Groups[1].Value.ToLowerInvariant();
        }

        if (withoutPath.Count(c => c == ':') >= 2)
        {
            return withoutPath.ToLowerInvariant();
        }

        var withoutPort = withoutPath.Split(':')[0];
        return withoutPort.ToLowerInvariant();
    }

    private static bool IsDottedIpv4Literal(string host) => DottedIpv4Regex().IsMatch(host);

    /// <summary>Parses host as an IPv4 address in either dotted-decimal or bare single-integer
    /// decimal form (the latter is a well-known technique for slipping a private/metadata target
    /// past a dotted-decimal-only IP-literal check). Returns null if host is neither form.</summary>
    private static int[]? ParseIpv4Octets(string host)
    {
        if (IsDottedIpv4Literal(host))
        {
            var parts = host.Split('.');
            var octets = new int[4];
            for (var i = 0; i < 4; i++)
            {
                if (!int.TryParse(parts[i], out var o) || o > 255) return null;
                octets[i] = o;
            }
            return octets;
        }

        if (BareDecimalRegex().IsMatch(host))
        {
            if (!long.TryParse(host, out var value) || value < 0 || value > 0xffffffffL) return null;
            return
            [
                (int)((value >> 24) & 0xff),
                (int)((value >> 16) & 0xff),
                (int)((value >> 8) & 0xff),
                (int)(value & 0xff),
            ];
        }

        return null;
    }

    private static bool IsIpv4Literal(string host) => ParseIpv4Octets(host) is not null;

    /// <summary>Strips an optional surrounding [...] bracket pair and a trailing %zone scope id
    /// from an IPv6 literal, e.g. [fe80::1%eth0] -> fe80::1.</summary>
    private static string StripIpv6Decoration(string host)
    {
        var h = host.Trim();
        var bracketed = FullBracketRegex().Match(h);
        if (bracketed.Success) h = bracketed.Groups[1].Value;
        var zoneIndex = h.IndexOf('%');
        if (zoneIndex != -1) h = h[..zoneIndex];
        return h;
    }

    /// <summary>Parses a bare (undecorated) IPv6 literal into its eight 16-bit groups, expanding a
    /// single "::" run and an embedded IPv4 tail. Returns null if not syntactically valid.</summary>
    private static int[]? ParseIpv6Groups(string host)
    {
        if (!host.Contains(':')) return null;
        var doubleColonCount = CountOccurrences(host, "::");
        if (doubleColonCount > 1) return null;
        var hasDoubleColon = host.Contains("::");

        string head = host, tail = "";
        if (hasDoubleColon)
        {
            var parts = host.Split("::");
            if (parts.Length != 2) return null;
            head = parts[0];
            tail = parts[1];
        }

        var hextetPattern = HextetRegex();
        static string[] SplitHextets(string segment) => segment.Length == 0 ? [] : segment.Split(':');

        var headParts = SplitHextets(head);
        var tailParts = SplitHextets(tail).ToList();

        int[]? embeddedIpv4 = null;
        if (tailParts.Count > 0 && IsDottedIpv4Literal(tailParts[^1]))
        {
            var octetStrs = tailParts[^1].Split('.');
            var octets = new int[4];
            for (var i = 0; i < 4; i++)
            {
                if (!int.TryParse(octetStrs[i], out var o) || o > 255) return null;
                octets[i] = o;
            }
            embeddedIpv4 = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
            tailParts.RemoveAt(tailParts.Count - 1);
        }

        if (headParts.Any(p => !hextetPattern.IsMatch(p))) return null;
        if (tailParts.Any(p => !hextetPattern.IsMatch(p))) return null;

        var headGroups = headParts.Select(p => Convert.ToInt32(p, 16)).ToArray();
        var tailGroups = tailParts.Select(p => Convert.ToInt32(p, 16)).ToArray();
        var embeddedLength = embeddedIpv4 is not null ? 2 : 0;
        var total = headGroups.Length + tailGroups.Length + embeddedLength;

        int[] groups;
        if (hasDoubleColon)
        {
            var zeros = 8 - total;
            if (zeros < 0) return null;
            groups = [.. headGroups, .. new int[zeros], .. tailGroups, .. (embeddedIpv4 ?? [])];
        }
        else
        {
            if (total != 8) return null;
            groups = [.. headGroups, .. tailGroups, .. (embeddedIpv4 ?? [])];
        }

        return groups.Length == 8 ? groups : null;
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) != -1)
        {
            count++;
            index += needle.Length;
        }
        return count;
    }

    private static bool IsIpv6Literal(string host) => ParseIpv6Groups(StripIpv6Decoration(host)) is not null;

    /// <summary>True if host is a raw IP literal, IPv4 or IPv6 (not a domain name).</summary>
    public static bool IsIpLiteral(string host) => IsIpv4Literal(host) || IsIpv6Literal(host);

    /// <summary>True if IPv4 octets fall in a loopback, RFC1918-private, or link-local range.</summary>
    private static bool IsPrivateIpv4Octets(int[] octets)
    {
        var a = octets[0];
        var b = octets[1];
        if (a == 127) return true;
        if (a == 10) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        if (a == 169 && b == 254) return true;
        return false;
    }

    /// <summary>True if host is a raw IP literal (v4 or v6) that targets loopback, an
    /// RFC1918/unique-local private range, link-local space, or a cloud-metadata endpoint.</summary>
    public static bool IsPrivateOrMetadataTarget(string host)
    {
        var ipv4Octets = ParseIpv4Octets(host);
        if (ipv4Octets is not null)
        {
            return IsPrivateIpv4Octets(ipv4Octets);
        }

        var groups = ParseIpv6Groups(StripIpv6Decoration(host));
        if (groups is null) return false;

        var (g0, g1, g2, g3, g4, g5, g6, g7) =
            (groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7]);

        // ::1 loopback
        if (g0 == 0 && g1 == 0 && g2 == 0 && g3 == 0 && g4 == 0 && g5 == 0 && g6 == 0 && g7 == 1)
        {
            return true;
        }
        // fe80::/10 link-local
        if ((g0 & 0xffc0) == 0xfe80) return true;
        // fc00::/7 unique-local
        if ((g0 & 0xfe00) == 0xfc00) return true;
        // IPv4-mapped (::ffff:a.b.c.d)
        if (g0 == 0 && g1 == 0 && g2 == 0 && g3 == 0 && g4 == 0 && g5 == 0xffff)
        {
            var octets = new[] { g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff };
            return IsPrivateIpv4Octets(octets);
        }
        return false;
    }

    /// <summary>True if host matches allowed exactly or is a subdomain of it.</summary>
    public static bool HostMatchesAllowed(string host, string allowed)
    {
        var h = host.ToLowerInvariant();
        var a = allowed.ToLowerInvariant();
        return h == a || h.EndsWith("." + a, StringComparison.Ordinal);
    }

    /// <summary>True if identifier matches granted exactly, as a path suffix, or as a substring --
    /// used for credential-identifier comparisons where declared scopes are often coarse-grained.</summary>
    public static bool CredentialMatchesGranted(string identifier, string granted)
    {
        var i = identifier.ToLowerInvariant();
        var g = granted.ToLowerInvariant();
        return i == g || i.EndsWith("/" + g, StringComparison.Ordinal) || i.Contains(g, StringComparison.Ordinal);
    }

    [GeneratedRegex(@"/+")]
    private static partial Regex MultiSlashRegex();

    [GeneratedRegex(@"^[a-z][a-z0-9+.\-]*://", RegexOptions.IgnoreCase)]
    private static partial Regex SchemePrefixRegex();

    [GeneratedRegex(@"^\[([^\]]+)\]")]
    private static partial Regex BracketedHostRegex();

    [GeneratedRegex(@"^(\d{1,3}\.){3}\d{1,3}$")]
    private static partial Regex DottedIpv4Regex();

    [GeneratedRegex(@"^\d{1,10}$")]
    private static partial Regex BareDecimalRegex();

    [GeneratedRegex(@"^\[([^\]]+)\]$")]
    private static partial Regex FullBracketRegex();

    [GeneratedRegex(@"^[0-9a-f]{1,4}$", RegexOptions.IgnoreCase)]
    private static partial Regex HextetRegex();
}
