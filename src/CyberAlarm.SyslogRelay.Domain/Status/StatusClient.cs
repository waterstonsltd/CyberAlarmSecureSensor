using System.Net;
using System.Net.Http.Json;
using CyberAlarm.SyslogRelay.Common.Status.Models;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Status;

internal sealed class StatusClient(
    IHttpClientFactory httpClientFactory,
    IOptions<RelayOptions> options,
    ILogger<StatusClient> logger) : IStatusClient
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<StatusClient> _logger = logger;

    public async Task<Result<RelayStatus>> GetStatusAsync(CancellationToken cancellationToken)
    {
        var httpClient = _httpClientFactory.CreateClient(nameof(StatusClient));

        try
        {
            var response = await httpClient.GetAsync(_options.StatusEndpoint, cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                _logger.LogDebug("Status not modified.");
                return new StatusNotModifiedWarning();
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get status.");
                return Result.Fail<RelayStatus>("Failed to get status.");
            }

            var status = await response.Content.ReadFromJsonAsync<RelayStatus>(SerializationOptions.Default, cancellationToken);
            if (status is null)
            {
                _logger.LogError("Failed to deserialise status response.");
                return Result.Fail<RelayStatus>("Failed to deserialise status response.");
            }

            _logger.LogDebug("Successfully fetched status: {@Status}", status);
            return status;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred when calling status endpoint.");
            return Result.Fail<RelayStatus>($"Error occurred when calling status endpoint: {ex.Message}");
        }
    }
}
