using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class FileSelectorBuilder
{
    public FileSelectorBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        Logger = Substitute.For<ILogger<FileSelector>>();
    }

    public IFileManager FileManager { get; }

    public ILogger<FileSelector> Logger { get; }

    public FileSelector Build() => new(FileManager, Logger);
}
