using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ToolGovern.Trace;

/// <summary>
/// Deterministic JSON serialization: object keys are sorted recursively so the same logical
/// content always hashes to the same bytes, regardless of the insertion order the caller used.
/// This is what makes the trace's sha256 content hash reproducible and verifiable later.
///
/// Accepts the same small set of shapes the rest of this port passes around: <c>null</c>,
/// <c>bool</c>, numeric primitives, <c>string</c>, <c>IReadOnlyDictionary&lt;string, object?&gt;</c>
/// (serialized as an object with keys sorted ordinally), and <c>IEnumerable</c> (serialized as an
/// array, in original order -- only object keys are sorted, never array elements).
/// </summary>
public static class CanonicalJson
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Serialize(object? value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            WriteValue(writer, value);
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                break;
            case bool b:
                writer.WriteBooleanValue(b);
                break;
            case string s:
                writer.WriteStringValue(s);
                break;
            case int i:
                writer.WriteNumberValue(i);
                break;
            case long l:
                writer.WriteNumberValue(l);
                break;
            case double d:
                writer.WriteNumberValue(d);
                break;
            case float f:
                writer.WriteNumberValue(f);
                break;
            case decimal dec:
                writer.WriteNumberValue(dec);
                break;
            case IReadOnlyDictionary<string, object?> dict:
                WriteObject(writer, dict);
                break;
            case IDictionary<string, object?> dict2:
                WriteObject(writer, dict2);
                break;
            case System.Collections.IEnumerable enumerable and not string:
                WriteArray(writer, enumerable);
                break;
            default:
                // Fall back to round-tripping through System.Text.Json for anything else (e.g. a
                // plain record/enum passed by a caller outside this port's own call sites).
                writer.WriteRawValue(JsonSerializer.Serialize(value), skipInputValidation: true);
                break;
        }
    }

    private static void WriteObject(Utf8JsonWriter writer, IEnumerable<KeyValuePair<string, object?>> entries)
    {
        writer.WriteStartObject();
        foreach (var (key, value) in entries.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            writer.WritePropertyName(key);
            WriteValue(writer, value);
        }
        writer.WriteEndObject();
    }

    private static void WriteArray(Utf8JsonWriter writer, System.Collections.IEnumerable enumerable)
    {
        writer.WriteStartArray();
        foreach (var item in enumerable)
        {
            WriteValue(writer, item);
        }
        writer.WriteEndArray();
    }
}
