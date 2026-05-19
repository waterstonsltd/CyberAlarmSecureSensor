using System.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

public class UploadService(
    IStatusService statusService,
    UploadPipelineServices pipeline,
    IOptions<ScheduleOptions> scheduleOptions,
    Func<TimeSpan, IPeriodicTimer> timerFactory,
    ILogger<UploadService> logger) : BackgroundService
{
    private readonly IStatusService _statusService = statusService;
    private readonly ScheduleOptions _options = scheduleOptions.Value;
    private readonly UploadPipelineServices _pipeline = pipeline;
    private readonly Func<TimeSpan, IPeriodicTimer> _timerFactory = timerFactory;
    private readonly ILogger<UploadService> _logger = logger;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Upload service started. Using initial interval of {InitialInterval} until first successful upload, then {Interval}",
            _options.InitialUploadInterval,
            _options.UploadInterval);

        // Run immediately on startup, then use fast polling until first success
        var uploadedThisSession = await RunUploadCycleAsync(stoppingToken);
        var timer = _timerFactory(uploadedThisSession ? _options.UploadInterval : _options.InitialUploadInterval);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                var previouslyUploaded = uploadedThisSession;
                uploadedThisSession = await RunUploadCycleAsync(stoppingToken) || uploadedThisSession;

                // Switch to normal interval after first successful upload this session
                if (uploadedThisSession && !previouslyUploaded)
                {
                    _logger.LogInformation(
                        "First upload of session completed. Switching to normal interval: {Interval}",
                        _options.UploadInterval);

                    timer = _timerFactory(_options.UploadInterval);
                }
            }
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogInformation(ex, "Upload service cancellation requested");
        }
    }

    private async Task<bool> RunUploadCycleAsync(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            var status = await _statusService.GetStatusAsync(cancellationToken);
            if (status.UploadsDisabled)
            {
                _logger.LogInformation("Uploads are disabled by server status; skipping upload cycle");
                return false;
            }

            await _pipeline.FileSelector.SelectFilesAsync(cancellationToken);
            await _pipeline.SourceGrouper.GroupLogsBySourceAsync(cancellationToken);
            await _pipeline.FileBundler.BundleFilesAsync(cancellationToken);
            await _pipeline.SecureUploader.UploadFilesAsync(cancellationToken);

            stopwatch.Stop();
            _logger.LogInformation(
                "Scheduled upload completed successfully in {Elapsed}",
                stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));

            return true;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(
                ex,
                "Scheduled upload failed after {Elapsed}: {Message}",
                stopwatch.Elapsed.ToString(@"hh\:mm\:ss"),
                ex.Message);
            return false;
        }
    }
}
