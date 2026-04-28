using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class BufferedPersistenceStageBuilder
{
    private IPeriodicOperation _periodicOperation = Substitute.For<IPeriodicOperation>();
    private PipelineOptions _options = new();

    public BufferedPersistenceStageBuilder WithPeriodicOperation(IPeriodicOperation periodicOperation)
    {
        _periodicOperation = periodicOperation;
        return this;
    }

    public BufferedPersistenceStageBuilder WithOptions(PipelineOptions options)
    {
        _options = options;
        return this;
    }

    public BufferedPersistenceStage Build()
    {
        var fileManager = Substitute.For<IFileManager>();
        fileManager.GetLogsFolder().Returns("/tmp/logs");
        fileManager.AppendAndSaveItemsAsNdjson(
            Arg.Any<IEnumerable<ParsedEvent>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var appManager = Substitute.For<IApplicationManager>();
        var healthCheckService = Substitute.For<IHealthCheckService>();
        var healthToken = Substitute.For<IHealthToken>();
        healthCheckService.GetHealthToken(Arg.Any<string>()).Returns(healthToken);

        var services = new PipelineStageServices(
            appManager,
            healthCheckService,
            Options.Create(_options),
            new PipelineMetrics(new TestMeterFactory()));

        return new BufferedPersistenceStage(
            fileManager,
            _periodicOperation,
            services,
            NullLogger<BufferedPersistenceStage>.Instance);
    }
}
