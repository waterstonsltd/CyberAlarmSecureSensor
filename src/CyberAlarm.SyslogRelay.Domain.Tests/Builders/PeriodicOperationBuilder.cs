using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class PeriodicOperationBuilder
{
    public PeriodicOperationBuilder()
    {
        Logger = Substitute.For<ILogger<PeriodicOperation>>();
    }

    public ILogger<PeriodicOperation> Logger { get; }

    public PeriodicOperation Build() => new(Logger);
}
