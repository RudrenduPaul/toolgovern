using ToolGovern.Trace;
using Xunit;

namespace ToolGovern.Tests.Trace;

public class CanonicalJsonTests
{
    [Fact]
    public void sorts_object_keys_regardless_of_insertion_order()
    {
        var a = new Dictionary<string, object?> { ["b"] = 2, ["a"] = 1 };
        var b = new Dictionary<string, object?> { ["a"] = 1, ["b"] = 2 };
        Assert.Equal(CanonicalJson.Serialize(a), CanonicalJson.Serialize(b));
    }

    [Fact]
    public void sorts_nested_object_keys_recursively()
    {
        var a = new Dictionary<string, object?>
        {
            ["outer"] = new Dictionary<string, object?> { ["z"] = 1, ["a"] = 2 },
        };
        var b = new Dictionary<string, object?>
        {
            ["outer"] = new Dictionary<string, object?> { ["a"] = 2, ["z"] = 1 },
        };
        Assert.Equal(CanonicalJson.Serialize(a), CanonicalJson.Serialize(b));
    }

    [Fact]
    public void does_not_sort_array_elements()
    {
        var value = new Dictionary<string, object?> { ["list"] = new List<object?> { 3, 1, 2 } };
        Assert.Equal("{\"list\":[3,1,2]}", CanonicalJson.Serialize(value));
    }

    [Fact]
    public void produces_different_output_for_different_content()
    {
        var a = new Dictionary<string, object?> { ["command"] = "ls" };
        var b = new Dictionary<string, object?> { ["command"] = "pwd" };
        Assert.NotEqual(CanonicalJson.Serialize(a), CanonicalJson.Serialize(b));
    }

    [Fact]
    public void serializes_null_and_bool_and_string_primitives()
    {
        var value = new Dictionary<string, object?> { ["a"] = null, ["b"] = true, ["c"] = "x" };
        Assert.Equal("{\"a\":null,\"b\":true,\"c\":\"x\"}", CanonicalJson.Serialize(value));
    }
}
