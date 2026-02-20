using CyberAlarm.SyslogRelay.Common.Status.Models;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Status;

internal sealed class CachedStatusService(IStatusService innerService, ILogger<CachedStatusService> logger) : IStatusService
{
    private readonly IStatusService _innerService = innerService;
    private readonly ILogger<CachedStatusService> _logger = logger;

    private RelayStatus? _cachedStatus;

    public async Task<RelayStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        if (_cachedStatus != null)
        {
            _logger.LogDebug("Returning cached status.");
            return _cachedStatus;
        }

        _cachedStatus = await _innerService.GetStatusAsync(cancellationToken);
        return _cachedStatus;
    }

    public async Task<Result<RelayStatus>> RefreshStatusAsync(CancellationToken cancellationToken)
    {
        var result = await _innerService.RefreshStatusAsync(cancellationToken);
        if (result.IsSuccess)
        {
            _cachedStatus = result.Value;
        }

        return result;
    }
}
