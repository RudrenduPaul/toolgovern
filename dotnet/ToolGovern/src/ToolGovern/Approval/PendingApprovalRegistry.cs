using ToolGovern.Classifier;

namespace ToolGovern.Approval;

/// <summary>
/// <see cref="PendingApprovalRegistry"/> -- a durable, keyed record of require-approval gate
/// decisions that outlives a single in-process, 30-second onApprovalRequired callback.
///
/// Three design decisions here are load-bearing, mirroring the TypeScript original exactly:
///
/// 1. pendingId is always server-generated, never caller-supplied. RegisterPending() mints the ID
///    and hands it back; ResolvePending() never creates an entry for an unrecognized ID -- an
///    unknown pendingId is "not-found", full stop.
/// 2. Alias tolerance for the same pending approval. RegisterAlias() lets a caller record that
///    some other identifier now also refers to an already-registered pendingId; Get() and
///    ResolvePending() accept either the original ID or any registered alias.
/// 3. Edited arguments are re-classified, never smuggled through on the strength of the original
///    approval. ResolvePending() accepts editedArgs; when supplied alongside an Allow decision,
///    the edited arguments are run back through the classifier before the resolution is accepted.
/// </summary>
public enum PendingApprovalStatus
{
    Pending,
    Resolved,
    Expired,
}

/// <summary>What governTool() (or any other caller) supplies to persist one require-approval gate
/// decision as a durable, resumable record.</summary>
public sealed class PendingApprovalDetails
{
    public required string AgentId { get; init; }
    public required string SessionId { get; init; }
    public string? CoordinatorId { get; init; }
    public required string Tool { get; init; }
    public required IReadOnlyDictionary<string, object?> Args { get; init; }
    public required ScopeDeclaration Scope { get; init; }
    public required IReadOnlyList<RuleMatch> FiredRules { get; init; }
    public AgentIdSource? AgentIdSource { get; init; }
    public IReadOnlyList<string>? DisabledRules { get; init; }
    public IReadOnlyList<string>? DowngradeToApproval { get; init; }
    /// <summary>How long this pending approval stays resolvable, in milliseconds from
    /// registration. Null (the default) means it never expires on its own.</summary>
    public double? TtlMs { get; init; }
}

/// <summary>What a resolved pending approval recorded about its own resolution.</summary>
public sealed class PendingApprovalResolution
{
    public required Decision Decision { get; init; }
    public string? ApprovedBy { get; init; }
    public required long ResolvedAt { get; init; }
    public IReadOnlyDictionary<string, object?>? EditedArgs { get; init; }
    /// <summary>Present only when editedArgs was supplied and actually re-classified.</summary>
    public ClassifierResult? Reclassified { get; init; }
}

/// <summary>The public, read-only view of one registered pending approval, as returned by Get().</summary>
public sealed class PendingApproval
{
    public required string PendingId { get; init; }
    public required string AgentId { get; init; }
    public required string SessionId { get; init; }
    public string? CoordinatorId { get; init; }
    public required string Tool { get; init; }
    public required IReadOnlyDictionary<string, object?> Args { get; init; }
    public required ScopeDeclaration Scope { get; init; }
    public required IReadOnlyList<RuleMatch> FiredRules { get; init; }
    public AgentIdSource? AgentIdSource { get; init; }
    public required PendingApprovalStatus Status { get; init; }
    public required long CreatedAt { get; init; }
    public double? ExpiresAt { get; init; }
    /// <summary>Every alias currently resolving to this same entry, in registration order. Does
    /// not include PendingId itself.</summary>
    public required IReadOnlyList<string> Aliases { get; init; }
    public PendingApprovalResolution? Resolution { get; init; }
}

public sealed class ResolvePendingInput
{
    /// <summary>The two terminal decisions a pending approval can be resolved to. RequireApproval
    /// is never a valid resolution -- something either ends up allowed or denied.</summary>
    public required Decision Decision { get; init; }
    public string? ApprovedBy { get; init; }
    /// <summary>Edited arguments to approve/deny instead of the originally registered args. When
    /// present together with Decision == Allow, the edited arguments are re-run through the
    /// classifier before the resolution is accepted.</summary>
    public IReadOnlyDictionary<string, object?>? EditedArgs { get; init; }
}

public enum ResolvePendingStatus
{
    Resolved,
    NotFound,
    AlreadyResolved,
    Expired,
}

public sealed class ResolvePendingOutcome
{
    public required ResolvePendingStatus Status { get; init; }
    /// <summary>Echoes back whatever ID/alias the caller resolved with -- NOT necessarily the
    /// canonical pendingId, when Status is NotFound.</summary>
    public required string PendingId { get; init; }
    /// <summary>The decision actually in effect. Present only for Resolved and AlreadyResolved.</summary>
    public Decision? FinalDecision { get; init; }
    public string? ApprovedBy { get; init; }
    /// <summary>The arguments actually approved/denied: EditedArgs when supplied, the originally
    /// registered Args otherwise.</summary>
    public IReadOnlyDictionary<string, object?>? Args { get; init; }
    /// <summary>Only present when EditedArgs was supplied and actually re-classified.</summary>
    public IReadOnlyList<RuleMatch>? FiredRules { get; init; }
}

/// <summary>Raised by RegisterAlias() when asked to alias an ID/alias with no registered entry.</summary>
public sealed class UnknownPendingApprovalException(string pendingId)
    : Exception($"toolgovern: no pending approval is registered under id/alias \"{pendingId}\".")
{
    public string PendingId { get; } = pendingId;
}

/// <summary>Raised by RegisterAlias() when alias already refers to a different pending approval
/// than the one being aliased.</summary>
public sealed class PendingApprovalAliasConflictException(string alias)
    : Exception($"toolgovern: alias \"{alias}\" already refers to a different pending approval.")
{
    public string Alias { get; } = alias;
}

internal sealed class PendingApprovalEntry
{
    public required string PendingId { get; init; }
    public required string AgentId { get; init; }
    public required string SessionId { get; init; }
    public string? CoordinatorId { get; init; }
    public required string Tool { get; init; }
    public required IReadOnlyDictionary<string, object?> Args { get; init; }
    public required ScopeDeclaration Scope { get; init; }
    public required IReadOnlyList<RuleMatch> FiredRules { get; init; }
    public AgentIdSource? AgentIdSource { get; init; }
    public required IReadOnlyList<string> DisabledRules { get; init; }
    public required IReadOnlyList<string> DowngradeToApproval { get; init; }
    public required long CreatedAt { get; init; }
    public double? ExpiresAt { get; init; }
    public List<string> Aliases { get; } = [];
    public PendingApprovalStatus Status { get; set; } = PendingApprovalStatus.Pending;
    public PendingApprovalResolution? Resolution { get; set; }
}

public sealed class PendingApprovalRegistryOptions
{
    /// <summary>Injectable clock, purely for deterministic tests of TtlMs expiry. Defaults to the
    /// system clock, in Unix epoch milliseconds.</summary>
    public Func<long>? Now { get; init; }

    /// <summary>Injectable ID generator, purely for deterministic tests. Defaults to a GUID.</summary>
    public Func<string>? IdFactory { get; init; }

    /// <summary>Injectable re-classification function -- defaults to the real ClassifierEngine.ClassifyAsync().</summary>
    public Func<RuleContext, ClassifierEngine.ClassifyOptions, Task<ClassifierResult>>? Reclassify { get; init; }
}

/// <summary>A keyed, in-memory registry of pending require-approval gate decisions.</summary>
public sealed class PendingApprovalRegistry
{
    private readonly Dictionary<string, PendingApprovalEntry> _entries = new();

    /// <summary>alias -> canonical pendingId. A canonical pendingId is never itself a key in this
    /// map -- ResolveCanonicalId() checks _entries first, so a real ID always wins over any alias.</summary>
    private readonly Dictionary<string, string> _aliasToCanonical = new();

    private readonly Func<long> _now;
    private readonly Func<string> _idFactory;
    private readonly Func<RuleContext, ClassifierEngine.ClassifyOptions, Task<ClassifierResult>> _reclassify;

    public PendingApprovalRegistry(PendingApprovalRegistryOptions? options = null)
    {
        options ??= new PendingApprovalRegistryOptions();
        _now = options.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _idFactory = options.IdFactory ?? (() => Guid.NewGuid().ToString());
        _reclassify = options.Reclassify ?? ((ctx, opts) => ClassifierEngine.ClassifyAsync(ctx, opts));
    }

    /// <summary>Persists one require-approval gate decision and returns its server-generated
    /// pendingId. The caller never supplies (and cannot influence) this ID.</summary>
    public string RegisterPending(PendingApprovalDetails details)
    {
        var pendingId = _idFactory();
        var createdAt = _now();
        var entry = new PendingApprovalEntry
        {
            PendingId = pendingId,
            AgentId = details.AgentId,
            SessionId = details.SessionId,
            CoordinatorId = details.CoordinatorId,
            Tool = details.Tool,
            Args = details.Args,
            Scope = details.Scope,
            FiredRules = details.FiredRules,
            AgentIdSource = details.AgentIdSource,
            DisabledRules = details.DisabledRules ?? [],
            DowngradeToApproval = details.DowngradeToApproval ?? [],
            CreatedAt = createdAt,
            ExpiresAt = details.TtlMs is not null ? createdAt + details.TtlMs : null,
        };
        _entries[pendingId] = entry;
        return pendingId;
    }

    /// <summary>Records that alias now also refers to the pending approval registered under
    /// pendingId (which may itself already be an alias). Resolving by pendingId OR alias
    /// afterward reaches the same entry.</summary>
    public void RegisterAlias(string pendingId, string alias)
    {
        var canonical = ResolveCanonicalId(pendingId);
        if (canonical is null)
        {
            throw new UnknownPendingApprovalException(pendingId);
        }
        var existingTarget = ResolveCanonicalId(alias);
        if (existingTarget is not null && existingTarget != canonical)
        {
            throw new PendingApprovalAliasConflictException(alias);
        }
        _entries[canonical].Aliases.Add(alias);
        _aliasToCanonical[alias] = canonical;
    }

    /// <summary>Looks up a pending approval by its pendingId OR any registered alias. Returns null
    /// for anything unrecognized -- never fabricates an entry.</summary>
    public PendingApproval? Get(string pendingIdOrAlias)
    {
        var canonical = ResolveCanonicalId(pendingIdOrAlias);
        if (canonical is null) return null;
        return _entries.TryGetValue(canonical, out var entry) ? ToPublic(entry) : null;
    }

    /// <summary>
    /// Resolves a pending approval, by pendingId or any registered alias, to a terminal decision.
    /// An unrecognized id/alias returns NotFound -- it is NEVER treated as a fresh grant to be
    /// created on the spot. An already-resolved entry returns AlreadyResolved with the original
    /// resolution's outcome. An expired entry (past TtlMs) returns Expired. Otherwise, the entry
    /// is resolved; if editedArgs is supplied together with Decision == Allow, the edited
    /// arguments are re-run through the classifier (the same rule overrides captured at
    /// registration time); any result other than Allow overrides the human's Allow down to Deny.
    /// </summary>
    public async Task<ResolvePendingOutcome> ResolvePending(string pendingIdOrAlias, ResolvePendingInput input)
    {
        var canonical = ResolveCanonicalId(pendingIdOrAlias);
        if (canonical is null)
        {
            return new ResolvePendingOutcome { Status = ResolvePendingStatus.NotFound, PendingId = pendingIdOrAlias };
        }
        var entry = _entries[canonical];

        if (entry.Status == PendingApprovalStatus.Expired || (entry.ExpiresAt is not null && _now() > entry.ExpiresAt))
        {
            entry.Status = PendingApprovalStatus.Expired;
            return new ResolvePendingOutcome { Status = ResolvePendingStatus.Expired, PendingId = canonical };
        }

        if (entry.Status == PendingApprovalStatus.Resolved)
        {
            var resolution = entry.Resolution!;
            return new ResolvePendingOutcome
            {
                Status = ResolvePendingStatus.AlreadyResolved,
                PendingId = canonical,
                FinalDecision = resolution.Decision,
                ApprovedBy = resolution.ApprovedBy,
                Args = resolution.EditedArgs ?? entry.Args,
                FiredRules = resolution.Reclassified?.FiredRules,
            };
        }

        var effectiveArgs = input.EditedArgs ?? entry.Args;
        var finalDecision = input.Decision;
        ClassifierResult? reclassified = null;

        if (input.EditedArgs is not null && input.Decision == Decision.Allow)
        {
            var ctx = new RuleContext
            {
                AgentId = entry.AgentId,
                SessionId = entry.SessionId,
                CoordinatorId = entry.CoordinatorId,
                Tool = entry.Tool,
                Args = input.EditedArgs,
                Scope = entry.Scope,
            };
            reclassified = await _reclassify(ctx, new ClassifierEngine.ClassifyOptions
            {
                DisabledRules = entry.DisabledRules,
                DowngradeToApproval = entry.DowngradeToApproval,
            });
            if (reclassified.Decision != Decision.Allow)
            {
                finalDecision = Decision.Deny;
            }
        }

        entry.Status = PendingApprovalStatus.Resolved;
        entry.Resolution = new PendingApprovalResolution
        {
            Decision = finalDecision,
            ApprovedBy = input.ApprovedBy,
            ResolvedAt = _now(),
            EditedArgs = input.EditedArgs,
            Reclassified = reclassified,
        };

        return new ResolvePendingOutcome
        {
            Status = ResolvePendingStatus.Resolved,
            PendingId = canonical,
            FinalDecision = finalDecision,
            ApprovedBy = input.ApprovedBy,
            Args = effectiveArgs,
            FiredRules = reclassified?.FiredRules,
        };
    }

    private string? ResolveCanonicalId(string idOrAlias)
    {
        if (_entries.ContainsKey(idOrAlias)) return idOrAlias;
        return _aliasToCanonical.GetValueOrDefault(idOrAlias);
    }

    private static PendingApproval ToPublic(PendingApprovalEntry entry) => new()
    {
        PendingId = entry.PendingId,
        AgentId = entry.AgentId,
        SessionId = entry.SessionId,
        CoordinatorId = entry.CoordinatorId,
        Tool = entry.Tool,
        Args = entry.Args,
        Scope = entry.Scope,
        FiredRules = entry.FiredRules,
        AgentIdSource = entry.AgentIdSource,
        Status = entry.Status,
        CreatedAt = entry.CreatedAt,
        ExpiresAt = entry.ExpiresAt,
        Aliases = entry.Aliases.ToList(),
        Resolution = entry.Resolution,
    };
}
