"""Loads and validates a ``toolgovern.policy.yml`` file from disk.

Ported from ``packages/toolgovern/src/policy/loadPolicy.ts``::

    policy = load_policy("./toolgovern.policy.yml")
    gated_shell_tool = govern_tool(shell_tool, policy)

``load_policy`` is synchronous by design -- it is meant to run once at process startup, the same
way a framework loads any other config file.
"""

from __future__ import annotations

from typing import List

import yaml

from ..types import Policy
from .validate_policy import as_policy, validate_policy


class PolicyValidationError(Exception):
    def __init__(self, file_path: str, errors: List[str]) -> None:
        self.errors = errors
        message = f'Invalid policy file "{file_path}":\n' + "\n".join(f"  - {e}" for e in errors)
        super().__init__(message)


def load_policy(file_path: str) -> Policy:
    """Parses and validates a policy file, raising ``PolicyValidationError`` if it is invalid."""
    with open(file_path, "r", encoding="utf-8") as f:
        raw_text = f.read()
    try:
        parsed = yaml.safe_load(raw_text)
    except yaml.YAMLError as cause:
        raise ValueError(f'Failed to parse policy file "{file_path}" as YAML.') from cause

    result = validate_policy(parsed)
    if not result.valid:
        raise PolicyValidationError(file_path, list(result.errors))
    return as_policy(parsed)
