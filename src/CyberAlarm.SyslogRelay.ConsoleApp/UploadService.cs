using System.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

public class UploadService(
    IScheduler scheduler,
    IStatusService statusService,
    UploadPipelineServices pipeline,
    IOptions<ScheduleOptions> scheduleOptions,
    ILogger<UploadService> logger) : BackgroundService
{
    private readonly IScheduler _scheduler = scheduler;
    private readonly IStatusService _statusService = statusService;
    private readonly ScheduleOptions _options = scheduleOptions.Value;
    private readonly UploadPipelineServices _pipeline = pipeline;
    private readonly ILogger<UploadService> _logger = logger;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Upload started");
        _logger.LogInformation("Scheduler interval: {Interval}", _options.UploadInterval);
        await _scheduler.RunOnSchedule(
            _options.UploadInterval,
            async cancellationToken =>
            {
                var stopwatch = Stopwatch.StartNew();
                try
                {
                    var status = await _statusService.GetStatusAsync(cancellationToken);
                    if (status.UploadsDisabled)
                    {
                        _logger.LogInformation("Uploads are disabled by server status; skipping upload cycle");
                        return;
                    }

                    await _pipeline.FileSelector.SelectFilesAsync(cancellationToken);
                    await _pipeline.SourceGrouper.GroupLogsBySourceAsync(cancellationToken);
                    await _pipeline.FileBundler.BundleFilesAsync(cancellationToken);
                    await _pipeline.SecureUploader.UploadFilesAsync(cancellationToken);

                    stopwatch.Stop();
                    _logger.LogInformation(
                        "Scheduled upload completed successfully in {Elapsed}",
                        stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    _logger.LogError(
                        ex,
                        "Scheduled upload failed after {Elapsed}: {Message}",
                        stopwatch.Elapsed.ToString(@"hh\:mm\:ss"),
                        ex.Message);
                }
            },
            stoppingToken);
    }
}
