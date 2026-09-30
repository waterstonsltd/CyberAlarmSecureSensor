using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Status;
using FluentResults;
using Microsoft.Extensions.Hosting;
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

        HostEnvironment = Substitute.For<IHostEnvironment>();
        HostEnvironment.EnvironmentName.Returns(Environments.Production);

        Logger = Substitute.For<ILogger<FetchStatusActivity>>();
    }

    public IStatusService StatusService { get; }

    public IHostEnvironment HostEnvironment { get; }

    public ILogger<FetchStatusActivity> Logger { get; }

    public FetchStatusActivity Build() =>
        new(StatusService, HostEnvironment, Options.Create(_options), Logger);

    public FetchStatusActivityBuilder WithOptions(RelayOptions options)
    {
        _options = options;
        return this;
    }

    public FetchStatusActivityBuilder WithDevelopmentEnvironment()
    {
        HostEnvironment.EnvironmentName.Returns(Environments.Development);
        return this;
    }
}
