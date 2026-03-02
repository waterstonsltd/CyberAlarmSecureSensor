using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

[SuppressMessage("Minor Code Smell", "S2325:Methods and properties that don't access instance data should be static", Justification = "Ok for extension methods.")]
internal static partial class ParsingExtensions
{
    extension(string log)
    {
        public Dictionary<string, string>? ParseKeyValues()
        {
            var matches = KeyValueRegex().Matches(log);
            if (matches.Count == 0)
            {
                return null;
            }

            var keyValues = new Dictionary<string, string>();
            foreach (Match match in matches)
            {
                var key = match.Groups[1].Value;
                var value = match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Value;
                keyValues[key] = value;
            }

            return keyValues;
        }
    }

    extension(string value)
    {
        public EventProtocol ToProtocol() =>
            Enum.TryParse<EventProtocol>(value, true, out var protocol) && Enum.IsDefined(protocol)
            ? protocol
            : EventProtocol.Unknown;
    }

    extension(Match match)
    {
        public string From(string groupKey) =>
            match.Groups[groupKey].Value;

        public int NumberFrom(string groupKey) =>
            int.Parse(match.Groups[groupKey].Value);
    }

    [GeneratedRegex(@"(\w+)=(?:""([^""]*)""|(\S+))")]
    private static partial Regex KeyValueRegex();
}
