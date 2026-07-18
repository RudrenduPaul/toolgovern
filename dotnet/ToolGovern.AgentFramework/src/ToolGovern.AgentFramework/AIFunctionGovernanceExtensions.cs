using Microsoft.Extensions.AI;
using ToolGovern.Middleware;

namespace ToolGovern.AgentFramework;

/// <summary>Ergonomic entry points for gating an <see cref="AIFunction"/> with toolgovern.</summary>
public static class AIFunctionGovernanceExtensions
{
    /// <summary>
    /// Returns a new <see cref="AIFunction"/> that evaluates every invocation of
    /// <paramref name="function"/> through toolgovern's classifier before the real function body
    /// executes. Equivalent to <c>new ToolGovernAIFunction(function, options)</c>.
    /// </summary>
    public static AIFunction WithToolGovern(this AIFunction function, GovernToolOptions options) =>
        new ToolGovernAIFunction(function, options);

    /// <summary>
    /// Applies <see cref="WithToolGovern(AIFunction, GovernToolOptions)"/> to every
    /// <see cref="AIFunction"/> in <paramref name="functions"/>, in order. Any non-<see cref="AIFunction"/>
    /// entries an agent's tool list might contain (e.g. hosted tools) are returned unchanged --
    /// toolgovern's per-call classifier only applies at the local-function-invocation boundary.
    /// </summary>
    public static IReadOnlyList<AIFunction> WithToolGovern(
        this IEnumerable<AIFunction> functions,
        GovernToolOptions options)
    {
        ArgumentNullException.ThrowIfNull(functions);
        ArgumentNullException.ThrowIfNull(options);
        return functions.Select(f => f.WithToolGovern(options)).ToList();
    }
}
