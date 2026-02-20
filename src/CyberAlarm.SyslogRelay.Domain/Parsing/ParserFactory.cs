using CyberAlarm.SyslogRelay.Common.Models;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class ParserFactory(
    IEnumerable<IParser> parsers,
    ILogger<ParserFactory> logger) : IParserFactory
{
    private readonly Dictionary<string, IParser> _parsers = parsers.ToDictionary(x => x.Name);
    private readonly ILogger<ParserFactory> _logger = logger;

    public IParser? Create(string parserName)
    {
        ArgumentException.ThrowIfNullOrEmpty(parserName);

        if (!_parsers.TryGetValue(parserName, out var parser))
        {
            _logger.LogError("No parser called '{Parser}' found.", parserName);
        }

        return parser;
    }
}
