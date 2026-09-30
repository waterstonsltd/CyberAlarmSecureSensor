using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.State;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class LoadStateActivityBuilder
{
    public LoadStateActivityBuilder()
    {
        StateService = Substitute.For<IStateService>();
        StateService
            .GetStateAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder().Build());

        Logger = Substitute.For<ILogger<LoadStateActivity>>();
    }

    public IStateService StateService { get; }

    public ILogger<LoadStateActivity> Logger { get; }

    public LoadStateActivity Build() =>
        new(StateService, Logger);
}
