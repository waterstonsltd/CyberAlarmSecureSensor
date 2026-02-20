using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class CheckWriteAccessActivityBuilder
{
    public CheckWriteAccessActivityBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        FileManager
            .CanWriteFile(Arg.Any<string>())
            .Returns(true);

        PlatformService = Substitute.For<IPlatformService>();
        PlatformService
            .GetPlatformType()
            .Returns(PlatformType.Linux);

        Logger = Substitute.For<ILogger<CheckWriteAccessActivity>>();
    }

    public IFileManager FileManager { get; }

    public IPlatformService PlatformService { get; }

    public ILogger<CheckWriteAccessActivity> Logger { get; }

    public CheckWriteAccessActivity Build() => new(FileManager, PlatformService, Logger);
}
