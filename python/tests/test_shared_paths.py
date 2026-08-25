"""Unit tests for toolgovern.shared.paths -- 2026-08-24 security fix.

Previously ``normalize_path``/``contains_path_traversal`` only split on "/", so a backslash-
delimited ".." segment was invisible to traversal detection, and a scope prefix like "/allowed"
would treat any candidate that merely started with the literal string "/allowed/" as in-scope even
when the remainder was pure backslash-delimited traversal
(``/allowed/sub\\..\\..\\..\\secrets``). This undercut the "sub-agent can't reach outside its
declared scope" guarantee identically across the TypeScript, Python, and .NET ports.
"""

from toolgovern.shared.paths import contains_path_traversal, is_path_within, normalize_path


def test_normalize_path_converts_backslashes_to_forward_slashes():
    assert normalize_path("workspace\\sub\\file.txt") == "workspace/sub/file.txt"


def test_normalize_path_collapses_mixed_separators_consistently():
    assert normalize_path("./workspace\\sub/../file.txt") == "workspace/sub/../file.txt"


def test_contains_path_traversal_detects_backslash_delimited_dotdot():
    assert contains_path_traversal("sub\\..\\..\\..\\secrets") is True


def test_contains_path_traversal_detects_mixed_separator_dotdot():
    assert contains_path_traversal("sub/..\\../secrets") is True


def test_contains_path_traversal_false_for_clean_backslash_path():
    assert contains_path_traversal("workspace\\sub\\file.txt") is False


def test_contains_path_traversal_still_detects_forward_slash_case():
    assert contains_path_traversal("../../etc/passwd") is True


def test_is_path_within_still_recognizes_nested_path_as_in_scope():
    assert is_path_within("/allowed/sub/dir/file.txt", "/allowed") is True


def test_is_path_within_still_rejects_unrelated_path():
    assert is_path_within("/other/dir/file.txt", "/allowed") is False
