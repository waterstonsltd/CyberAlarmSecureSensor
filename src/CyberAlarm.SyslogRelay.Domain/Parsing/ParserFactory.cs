using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class ParserFactory(IEnumerable<IParser> parsers) : IParserFactory
{
    private readonly Dictionary<string, IParser> _parsers = parsers.ToDictionary(x => x.Name);

    public IParser Create(EventPattern pattern)
    {
        var parserName = SelectParser(pattern);
        if (_parsers.TryGetValue(parserName, out var parser))
        {
            return parser;
        }

        throw new InvalidOperationException($"No parser found for '{pattern}'.");
    }

    private static string SelectParser(EventPattern pattern) =>
        pattern switch
        {
            EventPattern.CiscoAsa => nameof(CiscoAsaParser),
            _ => throw new NotSupportedException($"Parsing for '{pattern}' not supported."),
        };
}
