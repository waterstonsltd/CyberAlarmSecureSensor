using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class SourceGrouperBuilder
{
    private IOptions<RelayOptions> _options;

    public SourceGrouperBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        FileManager.Exists(Arg.Any<string>()).Returns(true);
        Logger = Substitute.For<ILogger<SourceGrouper>>();
        Options = new RelayOptions();
        _options = Substitute.For<IOptions<RelayOptions>>();
        _options.Value.Returns(Options);
    }

    public IFileManager FileManager { get; }

    public ILogger<SourceGrouper> Logger { get; }

    public RelayOptions Options { get; }

    public SourceGrouper Build() => new(FileManager,_options,  Logger);
}
