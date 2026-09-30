using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ParserFactoryBuilder
{
    public ParserFactoryBuilder()
    {
        ServiceProvider = Substitute.For<IKeyedServiceProvider>();
        Logger = Substitute.For<ILogger<ParserFactory>>();
    }

    public IKeyedServiceProvider ServiceProvider { get; }

    public ILogger<ParserFactory> Logger { get; }

    public ParserFactory Build() => new(ServiceProvider, Logger);

    public ParserFactoryBuilder WithParser(IParser? parser)
    {
        ServiceProvider
            .GetKeyedService(typeof(IParser), Arg.Any<object?>())
            .Returns(parser);

        return this;
    }
}
