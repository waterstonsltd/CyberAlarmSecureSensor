using System.Net.Http.Json;
using CyberAlarm.SyslogRelay.Domain.Status;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Registration;

internal sealed class RegistrationClient(
    IHttpClientFactory httpClientFactory,
    IStatusService statusService,
    IOptions<RelayOptions> options,
    ILogger<RegistrationClient> logger) : IRegistrationClient
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly IStatusService _statusService = statusService;
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<RegistrationClient> _logger = logger;

    public async Task<Result> PostRegistrationAsync(RegistrationRequest request, CancellationToken cancellationToken)
    {
        if (_options.EnableRequestLogging)
        {
            _logger.LogDebug("Sending request: {@Request}", request);
        }

        var status = await _statusService.GetStatusAsync(cancellationToken);
        var httpClient = _httpClientFactory.CreateClient(nameof(RegistrationClient));

        try
        {
            var response = await httpClient.PostAsJsonAsync(status.RegistrationEndpoint, request, cancellationToken);
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
