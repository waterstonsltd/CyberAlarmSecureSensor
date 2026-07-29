using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.State;

internal sealed class CachedStateService(IStateService innerService, ILogger<CachedStateService> logger) : IStateService
{
    private readonly IStateService _innerService = innerService;
    private readonly ILogger<CachedStateService> _logger = logger;

    private RelayState? _cachedState;

    public async Task<RelayState> GetStateAsync(CancellationToken cancellationToken)
    {
        if (_cachedState != null)
        {
            _logger.LogDebug("Returning cached state.");
            return _cachedState;
        }

        _cachedState = await _innerService.GetStateAsync(cancellationToken);
        return _cachedState;
    }

    public async Task<RelayState> SetStateAsync(RelayState state, CancellationToken cancellationToken)
    {
        _cachedState = await _innerService.SetStateAsync(state, cancellationToken);
        return _cachedState;
    }

    public async Task<RelayState> UpdateStateAsync(Func<RelayState, RelayState> updater, CancellationToken cancellationToken)
    {
        _cachedState = _cachedState is null
            ? await _innerService.UpdateStateAsync(updater, cancellationToken)
            : await _innerService.SetStateAsync(updater(_cachedState), cancellationToken);

        return _cachedState;
    }
}
