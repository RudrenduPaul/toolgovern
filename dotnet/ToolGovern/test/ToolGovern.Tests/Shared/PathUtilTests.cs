using ToolGovern.Shared;
using Xunit;

namespace ToolGovern.Tests.Shared;

/// <summary>
/// 2026-08-24 security fix: PathUtil.NormalizePath/ContainsPathTraversal used to split only on
/// '/', so a backslash-delimited ".." segment (e.g. "sub\..\..\..\secrets") was never recognized
/// as traversal -- the same string compared as a literal in-scope child of the declared prefix
/// because it happened to start with the right characters, letting a sub-agent escape its
/// declared filesystem scope undetected. Identical bug in the TypeScript and Python ports; all
/// three share this fix.
/// </summary>
public class PathUtilTests
{
    [Fact]
    public void NormalizePath_converts_backslashes_to_forward_slashes() =>
        Assert.Equal("workspace/sub/file.txt", PathUtil.NormalizePath("workspace\\sub\\file.txt"));

    [Fact]
    public void NormalizePath_collapses_mixed_separators_consistently() =>
        Assert.Equal("workspace/sub/../file.txt", PathUtil.NormalizePath("./workspace\\sub/../file.txt"));

    [Fact]
    public void ContainsPathTraversal_detects_backslash_delimited_dotdot() =>
        Assert.True(PathUtil.ContainsPathTraversal("sub\\..\\..\\..\\secrets"));

    [Fact]
    public void ContainsPathTraversal_detects_mixed_separator_dotdot() =>
        Assert.True(PathUtil.ContainsPathTraversal("sub/..\\../secrets"));

    [Fact]
    public void ContainsPathTraversal_false_for_clean_backslash_path() =>
        Assert.False(PathUtil.ContainsPathTraversal("workspace\\sub\\file.txt"));

    [Fact]
    public void ContainsPathTraversal_still_detects_forward_slash_case() =>
        Assert.True(PathUtil.ContainsPathTraversal("../../etc/passwd"));

    [Fact]
    public void IsPathWithin_still_recognizes_nested_path_as_in_scope() =>
        Assert.True(PathUtil.IsPathWithin("/allowed/sub/dir/file.txt", "/allowed"));

    [Fact]
    public void IsPathWithin_still_rejects_unrelated_path() =>
        Assert.False(PathUtil.IsPathWithin("/other/dir/file.txt", "/allowed"));
}
