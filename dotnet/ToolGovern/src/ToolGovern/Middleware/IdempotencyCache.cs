using ToolGovern.Trace;

namespace ToolGovern.Middleware;

/// <summary>
/// <see cref="IdempotencyCache{TResult}"/> -- the primitive behind GovernTool()'s optional
/// idempotency option.
///
/// SCOPE AND LIMITATIONS (read before relying on this for anything beyond a single-process first
/// pass): this is a plain in-process dictionary. It does NOT survive a process restart, and it is
/// NOT shared across multiple processes or replicas. A new cache is created per GovernTool() call,
/// so it is scoped to that one gated tool instance -- it is never shared globally across every
/// gate in a process.
/// </summary>
public sealed class IdempotencyOptions
{
    /// <summary>Turn on idempotency dedup for this gated tool.</summary>
    public required bool Enabled { get; init; }

    /// <summary>How long a completed result stays eligible to be replayed for an identical retry,
    /// in milliseconds. Defaults to 60_000 (60s).</summary>
    public double? TtlMs { get; init; }
}

/// <summary>
/// A scoped, in-memory claim-if-absent cache keyed on a stable serialization of tool name +
/// arguments.
/// </summary>
public sealed class IdempotencyCache<TResult>
{
    private const double DefaultTtlMs = 60_000;

    private sealed class CacheEntry
    {
        /// <summary>The in-flight or settled execution. Concurrent identical calls made before
        /// the first one resolves share this same task instead of each re-invoking the underlying
        /// tool.</summary>
        public required Task<TResult> Task { get; init; }

        /// <summary>Null while Task is still pending -- a pending claim never expires out from
        /// under a call that is still running.</summary>
        public double? ExpiresAt { get; set; }
    }

    private readonly Dictionary<string, CacheEntry> _entries = new();
    private readonly double _ttlMs;
    private readonly object _lock = new();

    public IdempotencyCache(double? ttlMs = null)
    {
        _ttlMs = ttlMs ?? DefaultTtlMs;
    }

    /// <summary>Stable key for one tool+args combination. CanonicalJson sorts object keys
    /// recursively, so argument insertion order must never cause two logically-identical calls to
    /// miss each other.</summary>
    public static string KeyFor(string tool, IReadOnlyDictionary<string, object?> args) =>
        $"{tool}:{CanonicalJson.Serialize(args)}";

    private static double NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>
    /// Returns the cached result for key if a live (non-expired) entry exists, executing run only
    /// when there is no live claim. A failed execution is evicted immediately -- it is never
    /// cached as if it had succeeded, so a transient failure remains retryable.
    /// </summary>
    public async Task<TResult> ClaimIfAbsent(string key, Func<Task<TResult>> run)
    {
        var now = NowMs();
        Task<TResult> task;
        lock (_lock)
        {
            if (_entries.TryGetValue(key, out var existing) && (existing.ExpiresAt is null || existing.ExpiresAt > now))
            {
                task = existing.Task;
            }
            else
            {
                if (existing is not null)
                {
                    _entries.Remove(key);
                }
                try
                {
                    task = run();
                }
                catch (Exception ex)
                {
                    // A synchronous throw from `run` must behave exactly like a rejected task --
                    // mirrors the Promise semantics the TypeScript original relies on.
                    task = Task.FromException<TResult>(ex);
                }
                var entry = new CacheEntry { Task = task };
                _entries[key] = entry;

                // Fire-and-forget continuation that resolves the entry's expiry once the task
                // settles, mirroring the TS original's post-await bookkeeping.
                _ = task.ContinueWith(t =>
                {
                    lock (_lock)
                    {
                        if (!_entries.TryGetValue(key, out var current) || current != entry) return;
                        if (t.IsFaulted || t.IsCanceled)
                        {
                            _entries.Remove(key);
                        }
                        else
                        {
                            entry.ExpiresAt = NowMs() + _ttlMs;
                        }
                    }
                }, TaskScheduler.Default);
            }
        }

        return await task;
    }
}
