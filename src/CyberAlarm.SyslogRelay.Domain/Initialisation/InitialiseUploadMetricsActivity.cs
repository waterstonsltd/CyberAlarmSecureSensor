using System.Diagnostics;
using System.Diagnostics.Metrics;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using FluentResults;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

/// <summary>
/// Registers the <c>upload.build_info</c> gauge at startup using the meter
/// factory directly, so the running build version is visible from the first
/// Prometheus scrape without depending on the upload cycle having run.
/// </summary>
internal sealed class InitialiseUploadMetricsActivity : IStartupActivity
{
    public InitialiseUploadMetricsActivity(IMeterFactory meterFactory, IOptions<RelayOptions> relayOptions)
    {
        var buildVersion = relayOptions.Value.BuildVersion;
        var meter = meterFactory.Create(UploadMetrics.MeterName);
        meter.CreateObservableGauge<int>(
            "upload.build_info",
            () => new Measurement<int>(1, new TagList { { "version", buildVersion } }),
            description: "Always 1. The 'version' tag contains the current build version for display in dashboards.");
    }

    public Task<Result> RunAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Result.Ok());
}
