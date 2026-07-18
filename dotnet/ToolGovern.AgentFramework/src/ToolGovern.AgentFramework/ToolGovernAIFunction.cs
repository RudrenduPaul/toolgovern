using Microsoft.Extensions.AI;
using ToolGovern.Middleware;

namespace ToolGovern.AgentFramework;

/// <summary>
/// Wraps a real <see cref="AIFunction"/> so every invocation is evaluated by toolgovern's
/// classifier BEFORE the wrapped function's own body ever runs.
/// </summary>
/// <remarks>
/// <para>
/// This is a direct implementation of the pattern Microsoft's own <c>Microsoft.Extensions.AI</c>
/// maintainer proposed as the answer to
/// <see href="https://github.com/microsoft/agent-framework/issues/2254">agent-framework#2254</see>
/// ("Built-in Security &amp; Validation Middleware for AI Function Tools"): subclass
/// <see cref="DelegatingAIFunction"/>, override <c>InvokeCoreAsync</c>, and do the
/// validation/policy work there before calling through to the inner function. See that issue's
/// own reference code sample from @stephentoub (a <c>ValidateQueryFunction : DelegatingAIFunction</c>
/// with an overridden <c>InvokeCoreAsync</c>) -- this class is the same shape, wired to
/// toolgovern's real classifier instead of a hand-rolled validator.
/// </para>
/// <para>
/// <see cref="Microsoft.Extensions.AI.ApprovalRequiredAIFunction"/> itself is also a
/// <see cref="DelegatingAIFunction"/> subclass, but it is a <b>static, per-tool</b> switch: every
/// call to a tool wrapped in it requires approval, or none do, decided once at wrap time with no
/// visibility into the actual call arguments. toolgovern's classifier is a <b>per-call,
/// argument-aware</b> verdict -- the same tool can be allowed for one call and denied or flagged
/// for approval on the next, based on what the arguments actually do (which path, which host,
/// which credential). The two compose: wrapping an already-<c>ApprovalRequiredAIFunction</c>-wrapped
/// function in a <see cref="ToolGovernAIFunction"/> (or vice versa) runs both gates.
/// </para>
/// <para>
/// This wraps at the tool-definition boundary the framework itself exposes
/// (<see cref="DelegatingAIFunction"/>/<see cref="AIFunction.InvokeAsync"/>) -- it does not
/// monkey-patch <c>Microsoft.Agents.AI</c> or <c>Microsoft.Extensions.AI</c> internals. Every path
/// that can reach the wrapped function (a direct <c>function.InvokeAsync(...)</c> call, or
/// Agent Framework's own function-calling loop invoking a registered tool) goes through the
/// classifier first, because the gate lives inside <see cref="InvokeCoreAsync"/> itself, which
/// <see cref="AIFunction.InvokeAsync"/> (the framework's own public entry point) always calls.
/// </para>
/// <para>
/// <b>Known limitation, stated honestly:</b> <see cref="ToolDefinition{TResult}"/>'s
/// <c>Execute</c> delegate (the core <c>ToolGovern.Net</c> gate this class reuses via
/// <see cref="ToolGovernMiddleware.GovernTool{TResult}"/>) has no <see cref="CancellationToken"/>
/// parameter -- that delegate shape is shared, unmodified, with the TypeScript/Python ports and
/// predates this .NET Agent Framework adapter. This class carries the real per-call
/// <see cref="CancellationToken"/> through to the wrapped function via an <see cref="AsyncLocal{T}"/>
/// captured immediately before invoking the governed gate, which is correct for the normal
/// single-threaded async-await call chain this wrapper produces (no explicit thread hop happens
/// between setting it and the gate reading it) but would not survive a caller who detaches the
/// continuation onto a different logical call context (e.g. via <c>Task.Run</c> inside a custom
/// <see cref="AIFunction"/> implementation it wraps).
/// </para>
/// </remarks>
public sealed class ToolGovernAIFunction : DelegatingAIFunction
{
    private readonly ToolDefinition<object?> _governed;
    private readonly AsyncLocal<CancellationToken> _currentCancellationToken = new();
    private readonly AsyncLocal<IServiceProvider?> _currentServices = new();

    /// <summary>
    /// Wraps <paramref name="innerFunction"/> so every call is evaluated by toolgovern's
    /// classifier, using <paramref name="options"/> as the declared scope + rule overrides.
    /// </summary>
    public ToolGovernAIFunction(AIFunction innerFunction, GovernToolOptions options)
        : base(innerFunction)
    {
        ArgumentNullException.ThrowIfNull(innerFunction);
        ArgumentNullException.ThrowIfNull(options);

        var toolDefinition = new ToolDefinition<object?>
        {
            Name = innerFunction.Name,
            Execute = async args =>
            {
                var effectiveArguments = new AIFunctionArguments(new Dictionary<string, object?>(args))
                {
                    Services = _currentServices.Value,
                };
                var result = await innerFunction
                    .InvokeAsync(effectiveArguments, _currentCancellationToken.Value)
                    .ConfigureAwait(false);
                return result;
            },
        };

        // Built ONCE, not per-call: ToolGovernMiddleware.GovernTool() owns this instance's
        // idempotency cache (when options.Idempotency is enabled) and closes over the disabled
        // rules / downgrade list captured at wrap time. Rebuilding it on every InvokeCoreAsync
        // call would silently reset the idempotency cache on every single invocation, defeating
        // its entire purpose.
        _governed = ToolGovernMiddleware.GovernTool(toolDefinition, options);
    }

    /// <inheritdoc />
    protected override async ValueTask<object?> InvokeCoreAsync(
        AIFunctionArguments arguments,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        // Captured so the governed Execute closure above (which, per ToolDefinition<TResult>'s
        // shape, receives only the argument dictionary) can still reach the real per-call
        // cancellation token and service provider -- see the "Known limitation" remarks above.
        _currentCancellationToken.Value = cancellationToken;
        _currentServices.Value = arguments.Services;

        var argsDict = new Dictionary<string, object?>(arguments);
        return await _governed.Execute(argsDict).ConfigureAwait(false);
    }
}
