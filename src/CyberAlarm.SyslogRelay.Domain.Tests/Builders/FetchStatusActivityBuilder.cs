using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Status;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class FetchStatusActivityBuilder
{
    private RelayOptions _options = new RelayOptionsBuilder().Build();

    public FetchStatusActivityBuilder()
    {
        StatusService = Substitute.For<IStatusService>();
        StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok(new RelayStatusBuilder().Build()));

        Logger = Substitute.For<ILogger<FetchStatusActivity>>();
    }

    public IStatusService StatusService { get; }

    public ILogger<FetchStatusActivity> Logger { get; }

    public FetchStatusActivity Build() =>
        new(StatusService, Options.Create(_options), Logger);

    public FetchStatusActivityBuilder WithOptions(RelayOptions options)
    {
        _options = options;
        return this;
    }
}
