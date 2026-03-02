using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ValidationStageBuilder
{
    private PipelineOptions _options = new();
    private TestStage<ValidationStageOutput> _nextStage = new([]);

    public ValidationStageBuilder()
    {
        HealthCheckService = Substitute.For<IHealthCheckService>();
        Logger = Substitute.For<ILogger<ValidationStage>>();
    }

    public IHealthCheckService HealthCheckService { get; }

    public ILogger<ValidationStage> Logger { get; }

    public ValidationStage Build() =>
        new(HealthCheckService, Options.Create(_options), Logger) { NextStage = _nextStage, };

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
