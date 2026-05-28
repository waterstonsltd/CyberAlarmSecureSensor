using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.PatternMatching;
using CyberAlarm.SyslogRelay.Domain.Status;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class PatternMatchingServiceBuilder : IDisposable
{
    private RelayOptions _options = new RelayOptionsBuilder()
        .WithPatternMatchingCacheDurationInSeconds(3600)
        .Build();

    private readonly MemoryCache _memoryCache = new(new MemoryCacheOptions());

    public PatternMatchingServiceBuilder()
    {
        StatusService = Substitute.For<IStatusService>();
        ParserFactory = Substitute.For<IParserFactory>();
        Logger = Substitute.For<ILogger<PatternMatchingService>>();
    }

    public IStatusService StatusService { get; }

    public IParserFactory ParserFactory { get; }

    public ILogger<PatternMatchingService> Logger { get; }

    public PatternMatchingService Build() =>
        new(_memoryCache, StatusService, ParserFactory, Options.Create(_options), Logger);

    public void Dispose() => _memoryCache.Dispose();

    public PatternMatchingServiceBuilder WithOptions(RelayOptions options)
    {
        _options = options;
        return this;
    }
}
