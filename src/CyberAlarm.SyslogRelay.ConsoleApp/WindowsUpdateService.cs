using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Velopack;
using Velopack.Sources;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

internal sealed class WindowsUpdateService : BackgroundService
{
    private const string UpdateEnabledKey = "WindowsUpdate:Enabled";
    private const string UpdateIntervalHoursKey = "WindowsUpdate:CheckIntervalHours";
    private const string RepositoryUrlKey = "WindowsUpdate:RepositoryUrl";
    private static readonly TimeSpan MinimumUpdateInterval = TimeSpan.FromHours(1);

    private readonly IConfiguration configuration;
    private readonly ILogger<WindowsUpdateService> logger;

    public WindowsUpdateService(IConfiguration configuration, ILogger<WindowsUpdateService> logger)
    {
        this.configuration = configuration;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (!configuration.GetValue(UpdateEnabledKey, true))
        {
            logger.LogInformation("Windows auto-update is disabled.");
            return;
        }

        using var timer = new PeriodicTimer(GetUpdateInterval());

        do
        {
            await CheckForUpdatesAsync(stoppingToken);
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task CheckForUpdatesAsync(CancellationToken cancellationToken)
    {
        try
        {
            var repoUrl = configuration[RepositoryUrlKey];
            if (string.IsNullOrWhiteSpace(repoUrl))
            {
                logger.LogWarning("Skipping update check because {ConfigurationKey} is not configured.", RepositoryUrlKey);
                return;
            }

            var source = new GithubSource(repoUrl, accessToken: null, prerelease: false);
            var options = new UpdateOptions
            {
                ExplicitChannel = "stable",
            };

            var updateManager = new UpdateManager(source, options);
            if (!updateManager.IsInstalled)
            {
                logger.LogDebug("Skipping update check because the app is not installed via Velopack.");
                return;
            }

            var update = await updateManager.CheckForUpdatesAsync().ConfigureAwait(false);
            if (update is null)
            {
                logger.LogDebug("No Windows update available.");
                return;
            }

            logger.LogInformation("Downloading Windows update {Version}.", update.TargetFullRelease.Version);
            await updateManager.DownloadUpdatesAsync(update, cancelToken: cancellationToken).ConfigureAwait(false);

            logger.LogInformation("Applying Windows update {Version} and exiting for restart.", update.TargetFullRelease.Version);
            updateManager.ApplyUpdatesAndExit(update.TargetFullRelease);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Windows update check failed.");
        }
    }

    private TimeSpan GetUpdateInterval()
    {
        var configuredHours = configuration.GetValue(UpdateIntervalHoursKey, 4);
        return TimeSpan.FromHours(Math.Max(configuredHours, MinimumUpdateInterval.TotalHours));
    }
}
