using CyberAlarm.SyslogRelay.Domain.Status;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class CachedStatusServiceBuilder
{
    public CachedStatusServiceBuilder()
    {
        StatusService = Substitute.For<IStatusService>();
        Logger = Substitute.For<ILogger<CachedStatusService>>();
    }

    public IStatusService StatusService { get; }

    public ILogger<CachedStatusService> Logger { get; }

    public CachedStatusService Build() => new(StatusService, Logger);
}
