using CyberAlarm.EventBundler.Services;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute.ReturnsExtensions;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class FileBundlerBuilder
{
    private RelayOptions _relayOptions;

    public FileBundlerBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        FileManager
            .GetProcessingFolder()
            .Returns("default processing folder");
        FileManager.OpenWriteStreamForFile(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(new MemoryStream());
        FileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(new MemoryStream());

        EventBundler = Substitute.For<IEventBundlerService>();
        PlatformService = Substitute.For<IPlatformService>();
        PlatformService.GetPlatform().Returns(new Domain.Services.Platform("default os", "default runtime", "default architecture", false));
        StatusService = Substitute.For<IStatusService>();
        StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStatusBuilder().Build());
        RsaKeyProvider = Substitute.For<IRsaKeyProvider>();
        Logger = Substitute.For<ILogger<FileBundler>>();
        _relayOptions = new RelayOptionsBuilder().Build();
    }

    public IFileManager FileManager { get; }

    public IEventBundlerService EventBundler { get; }

    public IPlatformService PlatformService { get; }

    public ILogger<FileBundler> Logger { get; }

    public IStatusService StatusService { get; }

    public IRsaKeyProvider RsaKeyProvider { get; }

    public FileBundlerBuilder WithRelayOptions(RelayOptions relayOptions)
    {
        _relayOptions = relayOptions;
        return this;
    }

    public FileBundlerBuilder WithSourceFiles(IEnumerable<string> files)
    {
        FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(files);

        return this;
    }

    public FileBundlerBuilder WithEventsMetaData(IEnumerable<(string FileName, EventsMetaData EventsMetaData)> metadata)
    {
        FileManager
            .DeserialiseFromFileAsync<Dictionary<string, EventsMetaData>>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(metadata.ToDictionary(x => x.FileName, x => x.EventsMetaData));

        return this;
    }

    public FileBundler Build() =>
        new(FileManager, EventBundler, PlatformService, StatusService, RsaKeyProvider, Options.Create(_relayOptions), Logger);
}
