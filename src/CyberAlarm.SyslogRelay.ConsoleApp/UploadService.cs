using System.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

public class UploadService(
    IScheduler scheduler,
    IFileSelector fileSelector,
    ISourceGrouper sourceGrouper,
    IFileBundler fileBundler,
    ISecureUploader secureUploader,
    IOptions<ScheduleOptions> scheduleOptions,
    ILogger<UploadService> logger) : BackgroundService
{
    private readonly IScheduler _scheduler = scheduler;
    private readonly ScheduleOptions _options = scheduleOptions.Value;
    private readonly IFileSelector _fileSelector = fileSelector;
    private readonly ISourceGrouper _sourceGrouper = sourceGrouper;
    private readonly IFileBundler _fileBundler = fileBundler;
    private readonly ISecureUploader _secureUploader = secureUploader;
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
                    await _fileSelector.SelectFilesAsync(cancellationToken);
                    await _sourceGrouper.GroupLogsBySourceAsync(cancellationToken);
                    await _fileBundler.BundleFilesAsync(cancellationToken);
                    await _secureUploader.UploadFilesAsync(cancellationToken);

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
