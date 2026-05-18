using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Status;
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
    private const string AllowPreReleaseKey = "WindowsUpdate:AllowPreRelease";
    private static readonly TimeSpan MinimumUpdateInterval = TimeSpan.FromHours(1);

    private readonly IConfiguration configuration;
    private readonly IStatusService statusService;
    private readonly ILogger<WindowsUpdateService> logger;

    public WindowsUpdateService(IConfiguration configuration, IStatusService statusService, ILogger<WindowsUpdateService> logger)
    {
        this.configuration = configuration;
        this.statusService = statusService;
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
            var allowPreRelease = configuration.GetValue(AllowPreReleaseKey, false);

            Version? approvedVersion = null;
            if (!allowPreRelease)
            {
                approvedVersion = await GetApprovedVersionAsync(cancellationToken).ConfigureAwait(false);
                if (approvedVersion is null)
                {
                    return;
                }
            }
            else
            {
                logger.LogDebug("Pre-release auto-update is enabled; skipping stable version gate.");
            }

            var installedVersion = GetInstalledVersion();
            if (installedVersion is null)
            {
                return;
            }

            if (!allowPreRelease && installedVersion >= approvedVersion!)
            {
                logger.LogDebug(
                    "Skipping Windows update check because installed version {InstalledVersion} is already at or above approved version {ApprovedVersion}.",
                    installedVersion,
                    approvedVersion);
                return;
            }

            await PerformVelopackCheckAndUpdateAsync(allowPreRelease, approvedVersion, installedVersion, cancellationToken);
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

    private async Task PerformVelopackCheckAndUpdateAsync(bool allowPreRelease, Version? approvedVersion, Version? installedVersion, CancellationToken cancellationToken)
    {
        var repoUrl = configuration[RepositoryUrlKey];
        if (string.IsNullOrWhiteSpace(repoUrl))
        {
            logger.LogWarning("Skipping update check because {ConfigurationKey} is not configured.", RepositoryUrlKey);
            return;
        }

        var source = new GithubSource(repoUrl, accessToken: null, prerelease: allowPreRelease);
        var options = allowPreRelease
            ? new UpdateOptions()
            : new UpdateOptions { ExplicitChannel = "stable" };

        var updateManager = new UpdateManager(source, options);
        if (!updateManager.IsInstalled)
        {
            logger.LogWarning("Skipping update check because the app is not installed via Velopack. Re-run the installer script to enable auto-updates.");
            return;
        }

        var update = await updateManager.CheckForUpdatesAsync().ConfigureAwait(false);
        if (update is null)
        {
            logger.LogWarning(
                "No Windows update available from GitHub for approved version {ApprovedVersion} while installed version is {InstalledVersion}.",
                allowPreRelease ? "(pre-release channel)" : approvedVersion!.ToString(),
                installedVersion);
            return;
        }

        if (!TryParseVersion(update.TargetFullRelease.Version.ToString(), out var targetVersion))
        {
            logger.LogWarning(
                "Skipping Windows update because offered target version '{TargetVersion}' could not be parsed.",
                update.TargetFullRelease.Version);
            return;
        }

        if (!allowPreRelease && targetVersion != approvedVersion)
        {
            logger.LogWarning(
                "Skipping Windows update because GitHub offered version {TargetVersion} but the approved version is {ApprovedVersion}.",
                targetVersion,
                approvedVersion);
            return;
        }

        logger.LogInformation("Downloading Windows update {Version}.", update.TargetFullRelease.Version);
        await updateManager.DownloadUpdatesAsync(update, cancelToken: cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Applying Windows update {Version} and exiting for restart.", update.TargetFullRelease.Version);
        updateManager.ApplyUpdatesAndExit(update.TargetFullRelease);
    }

    private TimeSpan GetUpdateInterval()
    {
        var configuredHours = configuration.GetValue(UpdateIntervalHoursKey, 1);
        return TimeSpan.FromHours(Math.Max(configuredHours, MinimumUpdateInterval.TotalHours));
    }

    private async Task<Version?> GetApprovedVersionAsync(CancellationToken cancellationToken)
    {
        var refreshResult = await statusService.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
        if (refreshResult.IsFailed)
        {
            logger.LogWarning(
                "Skipping Windows update because relay status could not be refreshed: {ErrorMessage}",
                refreshResult.ErrorMessage);
            return null;
        }

        var status = refreshResult.Value;
        if (!TryParseVersion(status.CurrentVersion, out var approvedVersion))
        {
            logger.LogWarning(
                "Skipping Windows update because approved currentVersion '{CurrentVersion}' could not be parsed.",
                status.CurrentVersion);
            return null;
        }

        return approvedVersion;
    }

    private Version? GetInstalledVersion()
    {
        var configuredBuildVersion = configuration["BuildVersion"];
        if (!TryParseVersion(configuredBuildVersion, out var installedVersion))
        {
            logger.LogWarning(
                "Skipping Windows update because configured BuildVersion '{BuildVersion}' could not be parsed.",
                configuredBuildVersion ?? "<null>");
            return null;
        }

        return installedVersion;
    }

    private static bool TryParseVersion(string? value, out Version version)
    {
        if (!string.IsNullOrWhiteSpace(value) && Version.TryParse(value, out var parsedVersion))
        {
            version = parsedVersion;
            return true;
        }

        version = new Version();
        return false;
    }
}
