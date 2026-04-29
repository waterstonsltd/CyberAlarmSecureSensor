using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Initialisation;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class InitialiseHealthCheckActivityBuilder
{
    public InitialiseHealthCheckActivityBuilder()
    {
        HealthCheckService = Substitute.For<IHealthCheckService>();
        HealthCheckService
            .InitialiseAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok());

        Logger = Substitute.For<ILogger<InitialiseHealthCheckActivity>>();
    }

    public IHealthCheckService HealthCheckService { get; }

    public ILogger<InitialiseHealthCheckActivity> Logger { get; }

    public InitialiseHealthCheckActivity Build() => new(HealthCheckService, Logger);
}
