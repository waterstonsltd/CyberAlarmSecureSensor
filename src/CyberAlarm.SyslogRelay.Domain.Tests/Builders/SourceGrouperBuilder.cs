using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class SourceGrouperBuilder
{
    private IOptions<RelayOptions> _relayOptions;
    private IOptions<PipelineOptions> _pipelineOptions;
    private PipelineOptions _configuredPipelineOptions;

    public SourceGrouperBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        FileManager.Exists(Arg.Any<string>()).Returns(true);
        Logger = Substitute.For<ILogger<SourceGrouper>>();
        RelayOptions = new RelayOptions();
        _configuredPipelineOptions = new PipelineOptions();
        _relayOptions = Substitute.For<IOptions<RelayOptions>>();
        _relayOptions.Value.Returns(RelayOptions);
        _pipelineOptions = Substitute.For<IOptions<PipelineOptions>>();
        _pipelineOptions.Value.Returns(_configuredPipelineOptions);
    }

    public IFileManager FileManager { get; }

    public ILogger<SourceGrouper> Logger { get; }

    public RelayOptions RelayOptions { get; }

    public SourceGrouperBuilder WithUploadRawLogs(bool uploadRawLogs)
    {
        _configuredPipelineOptions = new PipelineOptions
        {
            UploadRawLogs = uploadRawLogs,
        };
        _pipelineOptions.Value.Returns(_configuredPipelineOptions);

        return this;
    }

    public SourceGrouper Build() => new(FileManager, _relayOptions, _pipelineOptions, new UploadMetrics(new TestMeterFactory()), Logger);
}
