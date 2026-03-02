using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Initialisation;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ResetHealthCheckActivityBuilder
{
    public ResetHealthCheckActivityBuilder()
    {
        HealthCheckService = Substitute.For<IHealthCheckService>();
        Logger = Substitute.For<ILogger<ResetHealthCheckActivity>>();
    }

    public IHealthCheckService HealthCheckService { get; }

    public ILogger<ResetHealthCheckActivity> Logger { get; }

    public ResetHealthCheckActivity Build() => new(HealthCheckService, Logger);
}
