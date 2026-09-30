using System.Text;
using System.Text.Json;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

internal static class RawExportReader
{
    private const int MaximumExportLayers = 8;

    public static async Task<bool> ValidateAsync(StreamReader reader, CancellationToken cancellationToken, Action<long>? reportProgress = null)
    {
        var detected = false;
        var lineNumber = 0L;
        var validated = 0L;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                return detected;
            }

            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (!detected)
            {
                if (!IsExport(line))
                {
                    return false;
                }

                detected = true;
            }

            Decode(line, lineNumber);
            reportProgress?.Invoke(++validated);
        }
    }

    public static string Decode(string line, long lineNumber)
    {
        var raw = line;
        for (var layer = 0; layer < MaximumExportLayers; layer++)
        {
            raw = DecodeRecord(raw, lineNumber);
            if (!IsExport(raw))
            {
                return raw;
            }
        }

        throw InvalidRecord(lineNumber, $"more than {MaximumExportLayers} nested export layers");
    }

    private static string DecodeRecord(string line, long lineNumber)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw InvalidRecord(lineNumber, "expected a CyberAlarm exported event");
            }

            var timestamp = false;
            var pattern = false;
            var parsed = false;
            var status = false;
            var rawCount = 0;
            JsonElement rawValue = default;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                timestamp |= property.NameEquals("Timestamp");
                pattern |= property.NameEquals("PatternName");
                parsed |= property.NameEquals("ParseResult");
                status |= property.NameEquals("ValidationStatus");
                if (property.NameEquals("RawData"))
                {
                    rawCount++;
                    rawValue = property.Value;
                }
            }

            if (!HasExportSignature(timestamp, pattern, parsed, status, rawCount > 0))
            {
                throw InvalidRecord(lineNumber, "expected a CyberAlarm exported event");
            }

            if (rawCount != 1 || rawValue.ValueKind != JsonValueKind.String)
            {
                throw InvalidRecord(lineNumber, "RawData must appear once and contain a string");
            }

            var raw = rawValue.GetString();
            if (string.IsNullOrWhiteSpace(raw))
            {
                throw InvalidRecord(lineNumber, "RawData must not be empty");
            }

            return raw;
        }
        catch (JsonException)
        {
            // Do not include parser exceptions: their messages may contain customer log fragments.
            throw InvalidRecord(lineNumber, "invalid JSON");
        }
    }

    private static bool IsExport(string line)
    {
        if (!line.AsSpan().TrimStart().StartsWith("{", StringComparison.Ordinal))
        {
            return false;
        }

        var timestamp = false;
        var pattern = false;
        var parsed = false;
        var status = false;
        var raw = false;
        var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(line));
        try
        {
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return false;
            }

            while (reader.Read())
            {
                if (reader.TokenType != JsonTokenType.PropertyName || reader.CurrentDepth != 1)
                {
                    continue;
                }

                timestamp |= reader.ValueTextEquals("Timestamp");
                pattern |= reader.ValueTextEquals("PatternName");
                parsed |= reader.ValueTextEquals("ParseResult");
                status |= reader.ValueTextEquals("ValidationStatus");
                raw |= reader.ValueTextEquals("RawData");
            }
        }
        catch (JsonException)
        {
            // Recognisable truncated exports must reach validation, not become plain syslog.
        }

        return HasExportSignature(timestamp, pattern, parsed, status, raw);
    }

    private static bool HasExportSignature(bool timestamp, bool pattern, bool parsed, bool status, bool raw) =>
        timestamp && ((pattern && parsed) || (status && raw));

    private static InvalidDataException InvalidRecord(long lineNumber, string reason) =>
        new($"Invalid raw export at line {lineNumber}: {reason}.");
}
