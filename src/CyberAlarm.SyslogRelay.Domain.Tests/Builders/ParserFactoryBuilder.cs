using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ParserFactoryBuilder
{
    public ParserFactoryBuilder()
    {
        Parsers = [];
        Logger = Substitute.For<ILogger<ParserFactory>>();
    }

    public List<IParser> Parsers { get; }

    public ILogger<ParserFactory> Logger { get; }

    public ParserFactory Build() => new(Parsers, Logger);

    public ParserFactoryBuilder WithParsers(IEnumerable<IParser> parsers)
    {
        Parsers.AddRange(parsers);
        return this;
    }
}
