using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ValidationStageBuilder
{
    private PipelineOptions _options = new();
    private TestStage<ValidationStageOutput> _nextStage = new([]);

    public ValidationStageBuilder()
    {
        ApplicationManager = Substitute.For<IApplicationManager>();
        HealthCheckService = Substitute.For<IHealthCheckService>();
        Logger = Substitute.For<ILogger<ValidationStage>>();
    }

    public IApplicationManager ApplicationManager { get; }

    public IHealthCheckService HealthCheckService { get; }

    public ILogger<ValidationStage> Logger { get; }

    public ValidationStage Build() =>
        new(new(ApplicationManager, HealthCheckService, Options.Create(_options), new PipelineMetrics(new TestMeterFactory())), Logger) { NextStage = _nextStage, };

    public ValidationStageBuilder WithOptions(PipelineOptions options)
    {
        _options = options;
        return this;
    }

    public ValidationStageBuilder WithOutputCollection(List<ValidationStageOutput> outputs)
    {
        _nextStage = new(outputs);
        return this;
    }
}
