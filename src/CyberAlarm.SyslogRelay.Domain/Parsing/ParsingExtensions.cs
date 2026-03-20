using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

[SuppressMessage("Minor Code Smell", "S2325:Methods and properties that don't access instance data should be static", Justification = "Ok for extension methods.")]
internal static class ParsingExtensions
{
    extension(string? value)
    {
        public int? ToPort() =>
            int.TryParse(value, out var port) ? port : null;

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
}
