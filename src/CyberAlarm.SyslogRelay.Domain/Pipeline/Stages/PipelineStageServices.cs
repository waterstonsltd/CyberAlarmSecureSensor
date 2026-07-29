using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class PipelineStageServices(
    IApplicationManager applicationManager,
    IHealthCheckService healthCheckService,
    IOptions<PipelineOptions> options,
    PipelineMetrics metrics)
{
    public IApplicationManager ApplicationManager { get; } = applicationManager;

    public IHealthCheckService HealthCheckService { get; } = healthCheckService;

    public PipelineOptions Options { get; } = options.Value;

    public PipelineMetrics Metrics { get; } = metrics;
}
