using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class StateServiceBuilder
{
    public StateServiceBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        FileManager
            .DeserialiseFromFileAsync<RelayState>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder().Build());

        Logger = Substitute.For<ILogger<StateService>>();
    }

    public IFileManager FileManager { get; }

    public ILogger<StateService> Logger { get; }

    public StateService Build() => new(FileManager, Logger);
}
