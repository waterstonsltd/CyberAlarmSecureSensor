using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Registration;

internal sealed class RegistrationService(
    IPlatformService platformService,
    IRegistrationClient registrationClient,
    IRsaKeyProvider rsaKeyProvider,
    IStateService stateService,
    IOptions<RelayOptions> options,
    ILogger<RegistrationService> logger) : IRegistrationService
{
    private readonly IPlatformService _platformService = platformService;
    private readonly IRegistrationClient _registrationClient = registrationClient;
    private readonly IRsaKeyProvider _rsaKeyProvider = rsaKeyProvider;
    private readonly IStateService _stateService = stateService;
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<RegistrationService> _logger = logger;

    public async Task<Result> RegisterAsync(CancellationToken cancellationToken)
    {
        _logger.LogDebug("Check if registered already.");
        var state = await _stateService.GetStateAsync(cancellationToken);
        if (!state.IsRegistered)
        {
            return await Register(state, cancellationToken);
        }

        if (string.IsNullOrEmpty(state.RegistrationToken))
        {
            return Result.Fail("Registration token missing from the state.");
        }

        if (!_rsaKeyProvider.KeysExist())
        {
            return Result.Fail("Registered already but missing RSA keys.");
        }

        if (state.RegistrationToken != _options.RegistrationToken)
        {
            _logger.LogWarning("Re-registering because the registration token has changed.");
            return await Register(state, cancellationToken);
        }

        return Result.Ok();
    }

    private async Task<Result> Register(RelayState state, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Not yet registered: performing registration now.");
        var publicKeyPem = await _rsaKeyProvider.GetPublicKeyPem(cancellationToken);

        var request = new RegistrationRequest
        {
            PublicKey = TrimPemLabels(publicKeyPem),
            RegistrationToken = _options.RegistrationToken,
            SyslogRelayBuildVersion = _options.BuildVersion,
            SyslogRelayPlatform = _platformService.GetPlatform(),
        };

        var result = await _registrationClient.PostRegistrationAsync(request, cancellationToken);
        if (result.IsFailed)
        {
            return result;
        }

        state = state with { IsRegistered = true, RegistrationToken = _options.RegistrationToken };
        await _stateService.SetStateAsync(state, cancellationToken);

        return Result.Ok();
    }

    private static string TrimPemLabels(ReadOnlySpan<char> pem)
    {
        var headerLength = pem.IndexOf("-\n");
        var headerEnd = headerLength < 0 ? 0 : headerLength + 2;

        var footerBegin = pem.IndexOf("\n-");
        footerBegin = footerBegin < headerEnd ? pem.Length : footerBegin;

        return pem[headerEnd..footerBegin].ToString();
    }
}
