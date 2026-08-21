using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Status;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class StatusServiceBuilder
{
    public StatusServiceBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        StateService = Substitute.For<IStateService>();
        StatusClient = Substitute.For<IStatusClient>();
        Logger = Substitute.For<ILogger<StatusService>>();
    }

    public IFileManager FileManager { get; }

    public IStateService StateService { get; }

    public IStatusClient StatusClient { get; }

    public ILogger<StatusService> Logger { get; }

    public StatusService Build() => new(FileManager, StateService, StatusClient, Logger);
}
