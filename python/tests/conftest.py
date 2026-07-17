import pytest

from toolgovern import RuleContext, ScopeDeclaration


def make_ctx(
    args,
    tool="shell",
    scope=None,
    agent_id="agent-1",
    session_id="session-1",
    coordinator_id=None,
    scope_registry=None,
):
    """Shared helper for building a RuleContext in tests, mirroring the TS test suite's
    inline context construction."""
    return RuleContext(
        agent_id=agent_id,
        session_id=session_id,
        coordinator_id=coordinator_id,
        tool=tool,
        args=args,
        scope=scope if scope is not None else ScopeDeclaration(),
        scope_registry=scope_registry,
    )


@pytest.fixture
def ctx_factory():
    return make_ctx
