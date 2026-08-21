using CyberAlarm.SyslogRelay.Domain.Registration;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

internal sealed class RegistrationActivity(
    IRegistrationService registrationService,
    ILogger<RegistrationActivity> logger) : IStartupActivity
{
    private readonly IRegistrationService _registrationService = registrationService;
    private readonly ILogger<RegistrationActivity> _logger = logger;

    public async Task<Result> RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Register application.");
        return await _registrationService.RegisterAsync(cancellationToken);
    }
}
