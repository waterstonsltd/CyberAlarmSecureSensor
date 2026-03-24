using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class KeyValueParser : IParser
{
    // One dictionary per thread, cleared and reused each call.
    // Safe because ParseKeyValues is fully synchronous — no awaits cross the use of this buffer.
    // ASYNC SAFETY: [ThreadStatic] is unsafe with async/await — a continuation may resume on a
    // different thread and see a different (or null) buffer instance. If Parse or ParseKeyValues
    // ever becomes async, replace this with a per-call local or an ArrayPool-backed approach.
    [ThreadStatic]
    private static Dictionary<string, string>? _keyValueBuffer;

    private KeyValueParserConfig? _config;

    public Result Initialise(object? config)
    {
        try
        {
            if (config is JsonElement configElement)
            {
                _config = configElement.Deserialize<KeyValueParserConfig>(SerializationOptions.ParserConfig);
            }
            else if (config is KeyValueParserConfig keyValueParserConfig)
            {
                _config = keyValueParserConfig;
            }

            return Result.FailIf(_config is null, "Failed to parse config.");
        }
        catch (Exception ex)
        {
            return Result.Fail(ex.Message);
        }
    }

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);
        ArgumentNullException.ThrowIfNull(_config);

        var keyValues = ParseKeyValues(log, _config.Regex);
        if (keyValues is null or { Count: 0 })
        {
            return new FormatError();
        }

        if (!TryGetValue(keyValues, _config.SourceIpKeys, out var sourceIp) ||
            (!TryGetValue(keyValues, _config.DestinationIpKeys, out var destinationIp) && !_config.IsDestinationIpOptional) ||
            (!TryGetValue(keyValues, _config.SourcePortKeys, out var sourcePortValue) && !_config.IsSourcePortOptional) ||
            (!TryGetValue(keyValues, _config.DestinationPortKeys, out var destinationPortValue) && !_config.IsDestinationPortOptional) ||
            (!TryGetValue(keyValues, _config.ProtocolKeys, out var protocolValue) && !_config.IsProtocolOptional) ||
            (!TryGetValue(keyValues, _config.ActionKeys, out var actionValue) && !_config.IsActionOptional))
        {
            return new UnparsableEventError();
        }

        return new ParseResult(
            sourceIp,
            destinationIp,
            sourcePortValue.ToPort(),
            destinationPortValue.ToPort(),
            protocolValue.ToProtocol(),
            ToAction(actionValue),
            ExtractDuration(keyValues),
            ExtractBytes(keyValues));
    }

    private static Dictionary<string, string>? ParseKeyValues(string log, Regex regex)
    {
        var matches = regex.Matches(log);
        if (matches.Count == 0)
        {
            return null;
        }

        _keyValueBuffer ??= new Dictionary<string, string>(32);

        // ASYNC SAFETY: if this method ever becomes async, Clear() could race with
        // a continuation that resumed on the same thread after an await.
        _keyValueBuffer.Clear();

        foreach (Match match in matches)
        {
            var key = match.Groups[1].Value;
            var value = match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Value;
            _keyValueBuffer[key] = value;
        }

        // ASYNC SAFETY: the caller must not use this reference across any await —
        // the buffer is shared and will be overwritten on the next call on this thread.
        return _keyValueBuffer;
    }

    private static bool TryGetValue(Dictionary<string, string> keyValues, string[] keys, [MaybeNullWhen(false)] out string value)
    {
        value = null;

        foreach (var key in keys ?? [])
        {
            if (keyValues.TryGetValue(key, out value))
            {
                return true;
            }
        }

        return false;
    }

    private EventAction ToAction(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return EventAction.Unknown;
        }

        if (_config!.AllowActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Allow;
        }

        if (_config.DenyActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Deny;
        }

        if (_config.DropActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Drop;
        }

        if (_config.CloseActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Close;
        }

        if (_config.ResetActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Reset;
        }

        if (_config.TimeoutActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Timeout;
        }

        return EventAction.Unknown;
    }

    private TimeSpan? ExtractDuration(Dictionary<string, string> keyValues)
    {
        if (_config!.DurationKeys.Length == 0 || !TryGetValue(keyValues, _config.DurationKeys, out var durationValue))
        {
            return null;
        }

        if (_config.DurationIsSeconds && long.TryParse(durationValue, out var seconds))
        {
            return TimeSpan.FromSeconds(seconds);
        }

        return durationValue.ToDuration();
    }

    private long? ExtractBytes(Dictionary<string, string> keyValues)
    {
        TryGetValue(keyValues, _config!.TotalBytesKeys, out var totalBytesValue);
        TryGetValue(keyValues, _config.SentBytesKeys, out var sentBytesValue);
        TryGetValue(keyValues, _config.ReceivedBytesKeys, out var receivedBytesValue);

        var total = totalBytesValue.ToLong();
        var sent = sentBytesValue.ToLong();
        var received = receivedBytesValue.ToLong();

        if (total.HasValue)
        {
            return total;
        }

        if (sent.HasValue || received.HasValue)
        {
            return (sent ?? 0) + (received ?? 0);
        }

        return null;
    }
}
