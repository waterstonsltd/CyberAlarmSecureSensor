using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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

    public FileSelector Build() => new(FileManager, new UploadMetrics(new TestMeterFactory()), Logger);
}
