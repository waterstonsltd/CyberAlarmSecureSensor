using CyberAlarm.SyslogRelay.Domain.State;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class CachedStateServiceBuilder
{
    public CachedStateServiceBuilder()
    {
        StateService = Substitute.For<IStateService>();
        Logger = Substitute.For<ILogger<CachedStateService>>();
    }

    public IStateService StateService { get; }

    public ILogger<CachedStateService> Logger { get; }

    public CachedStateService Build() => new(StateService, Logger);
}
