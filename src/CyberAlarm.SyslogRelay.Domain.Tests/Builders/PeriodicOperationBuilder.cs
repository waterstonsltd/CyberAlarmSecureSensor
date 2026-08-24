using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class PeriodicOperationBuilder
{
    public PeriodicOperationBuilder()
    {
        ApplicationManager = Substitute.For<IApplicationManager>();
        Logger = Substitute.For<ILogger<PeriodicOperation>>();
    }

    public IApplicationManager ApplicationManager  { get; }

    public ILogger<PeriodicOperation> Logger { get; }

    public PeriodicOperation Build() => new(ApplicationManager, Logger);
}
