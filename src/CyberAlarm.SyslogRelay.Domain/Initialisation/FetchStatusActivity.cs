using CyberAlarm.SyslogRelay.Domain.Status;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

internal sealed class FetchStatusActivity(
    IStatusService statusService,
    IOptions<RelayOptions> options,
    ILogger<FetchStatusActivity> logger) : IStartupActivity
{
    private readonly IStatusService _statusService = statusService;
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<FetchStatusActivity> _logger = logger;

    public async Task<Result> RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Fetch latest status.");
        var result = await _statusService.RefreshStatusAsync(cancellationToken);
        if (result.IsFailed)
        {
            return result.ToResult();
        }

        var status = result.Value;

        _logger.LogDebug("Check minimum supported version.");
        if (!Version.TryParse(status.MinimumSupportedVersion, out var minimumSupportedVersion))
        {
            return Result.Fail($"Minimum supported version '{status.MinimumSupportedVersion}' could not be parsed.");
        }

        var buildVersion = new Version(_options.BuildVersion);
        if (buildVersion < minimumSupportedVersion)
        {
            return Result.Fail($"Build version '{buildVersion}' is not supported. Minimum supported version is '{minimumSupportedVersion}'.");
        }

        _logger.LogDebug("Check current version.");
        if (!Version.TryParse(status.CurrentVersion, out var currentVersion))
        {
            return Result.Fail($"Current version '{status.CurrentVersion}' could not be parsed.");
        }

        if (buildVersion < currentVersion)
        {
            _logger.LogWarning("A newer version '{CurrentVersion}' is available: running build version '{BuildVersion}'.", currentVersion, buildVersion);
        }

        return Result.Ok();
    }
}
