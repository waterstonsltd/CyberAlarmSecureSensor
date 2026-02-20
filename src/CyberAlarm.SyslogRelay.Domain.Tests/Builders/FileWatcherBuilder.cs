using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class FileWatcherBuilder
{
    private RelayOptions _options = new RelayOptionsBuilder().Build();

    public FileWatcherBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        FileManager
            .Exists(Arg.Any<string>())
            .Returns(true);
        FileManager
            .OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Stream.Null);

        PeriodicOperation = Substitute.For<IPeriodicOperation>();
        PeriodicOperation.Start(Arg.Do<PeriodicOperationSettings>(settings =>
        {
            settings.Operation(CancellationToken.None).GetAwaiter().GetResult();
        }), Arg.Any<CancellationToken>());

        Logger = Substitute.For<ILogger<FileWatcher>>();
    }

    public IFileManager FileManager { get; }

    public IPeriodicOperation PeriodicOperation { get; private set; }

    public ILogger<FileWatcher> Logger { get; }

    public FileWatcher Build() =>
        new(FileManager, PeriodicOperation, Options.Create(_options), Logger);

    public FileWatcherBuilder WithOptions(RelayOptions options)
    {
        _options = options;
        return this;
    }
}
