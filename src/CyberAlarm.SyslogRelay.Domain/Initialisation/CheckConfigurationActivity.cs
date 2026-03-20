using CyberAlarm.SyslogRelay.Domain.Registration;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

internal sealed class CheckConfigurationActivity(
    IOptions<RelayOptions> options,
    ILogger<CheckConfigurationActivity> logger) : IStartupActivity
{
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<CheckConfigurationActivity> _logger = logger;

    public Task<Result> RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Validate configuration.");
        var result = ValidateConfiguration();
        if (result.IsFailed)
        {
            return Task.FromResult(result);
        }

        return Task.FromResult(Result.Ok());
    }

    private Result ValidateConfiguration()
    {
        _logger.LogDebug("Validating build version.");
        if (string.IsNullOrWhiteSpace(_options.BuildVersion))
        {
            return Result.Fail("Build version is not configured.");
        }

        if (!Version.TryParse(_options.BuildVersion, out _))
        {
            return Result.Fail($"Build version '{_options.BuildVersion}' could not be parsed.");
        }

        _logger.LogDebug("Validating status endpoint.");
        if (string.IsNullOrWhiteSpace(_options.StatusEndpoint))
        {
            return Result.Fail("Status endpoint is not configured.");
        }

        _logger.LogDebug("Validating registration token.");
        var tokenResult = RegistrationToken.Validate(_options.RegistrationToken);
        if (tokenResult.IsFailed)
        {
            return tokenResult;
        }

        return Result.Ok();
    }
}
