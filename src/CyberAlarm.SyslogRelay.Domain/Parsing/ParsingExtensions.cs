using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

[SuppressMessage("Minor Code Smell", "S2325:Methods and properties that don't access instance data should be static", Justification = "Ok for extension methods.")]
internal static partial class ParsingExtensions
{
    extension(object? config)
    {
        public T? ParseConfig<T>()
        {
            if (config is JsonElement configElement)
            {
                return configElement.Deserialize<T>(SerializationOptions.ParserConfig);
            }
            else if (config is T parsedConfig)
            {
                return parsedConfig;
            }

            return default;
        }
    }

    extension(string log)
    {
        public Dictionary<string, string> ParseKeyValues(char pairDelimiter, char valueDelimiter)
        {
            return log
                .Split(pairDelimiter, StringSplitOptions.RemoveEmptyEntries)
                .Select(ToKeyValuePair)
                .Where(x => x.HasValue)
                .ToDictionary(x => x!.Value.Key, x => x!.Value.Value);

            KeyValuePair<string, string>? ToKeyValuePair(string text)
            {
                var items = text.Split(valueDelimiter, StringSplitOptions.RemoveEmptyEntries);
                return items.Length == 2 ? new(items[0].Trim(), items[1].Trim()) : null;
            }
        }

        public Dictionary<string, string>? ParseKeyValues(Dictionary<string, string> keyValues, Regex? regex = default)
        {
            ArgumentNullException.ThrowIfNull(keyValues);

            regex ??= DefaultKeyValueRegex();

            var matches = regex.Matches(log);
            if (matches.Count == 0)
            {
                return null;
            }

            foreach (Match match in matches)
            {
                var key = match.Groups[1].Value;
                var value = match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Value;
                keyValues[key] = value;
            }

            return keyValues;
        }
    }

    extension(string? value)
    {
        public int? ToPort() =>
            int.TryParse(value, out var port) ? port : null;

        public long? ToLong() =>
            long.TryParse(value, out var result) ? result : null;

        public TimeSpan? ToDuration() =>
            TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out var duration) ? duration : null;

        public EventProtocol ToProtocol() =>
            Enum.TryParse<EventProtocol>(value, true, out var protocol) && Enum.IsDefined(protocol)
            ? protocol
            : EventProtocol.Unknown;
    }

    extension(Match match)
    {
        public string From(string groupKey) =>
            match.Groups[groupKey].Value;

        public int? NumberFrom(string groupKey) =>
            int.TryParse(match.Groups[groupKey].Value, out var result) ? result : null;
    }

    [GeneratedRegex(@"(\w+)=(?:""([^""]*)""|(\S+))")]
    private static partial Regex DefaultKeyValueRegex();
}
