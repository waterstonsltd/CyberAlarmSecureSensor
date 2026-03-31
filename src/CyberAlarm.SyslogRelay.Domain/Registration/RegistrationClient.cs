using System.Net.Http.Json;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Registration;

internal sealed class RegistrationClient(
    IHttpClientFactory httpClientFactory,
    IOptions<RelayOptions> options,
    ILogger<RegistrationClient> logger) : IRegistrationClient
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<RegistrationClient> _logger = logger;

    public async Task<Result> PostRegistrationAsync(RegistrationRequest request, CancellationToken cancellationToken)
    {
        if (_options.EnableRequestLogging)
        {
            _logger.LogDebug(
                "Sending registration request for relay version {Version} on platform {Platform}.",
                request.SyslogRelayBuildVersion,
                request.SyslogRelayPlatform);
        }

        var httpClient = _httpClientFactory.CreateClient(nameof(RegistrationClient));

        try
        {
            var response = await httpClient.PostAsJsonAsync(_options.RegistrationEndpoint, request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var errorResponse = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogError("Failed to register: received {StatusCode} with response {ErrorResponse}.", response.StatusCode, errorResponse);
                return Result.Fail($"Failed to register: received {response.StatusCode}.");
            }

            _logger.LogDebug("Successfully completed registration.");
            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred when calling register endpoint.");
            return Result.Fail($"Error occurred when calling register endpoint: {ex.Message}");
        }
    }
}
