using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.State;

internal sealed class StateService(
    IFileManager fileManager,
    ILogger<StateService> logger) : IStateService
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly ILogger<StateService> _logger = logger;

    private readonly string _stateFilePath = Path.Combine(fileManager.GetDataPath(), "state.json");

    public Task<RelayState> GetStateAsync(CancellationToken cancellationToken) => GetState(cancellationToken);

    public Task<RelayState> SetStateAsync(RelayState state, CancellationToken cancellationToken) => SetState(state, cancellationToken);

    public async Task<RelayState> UpdateStateAsync(Func<RelayState, RelayState> updater, CancellationToken cancellationToken)
    {
        var state = await GetState(cancellationToken);
        var updatedState = updater(state);

        return await SetState(updatedState, cancellationToken);
    }

    private async Task<RelayState> GetState(CancellationToken cancellationToken)
    {
        _logger.LogDebug("Reading state from file.");
        var state = await ReadFromFile(cancellationToken);
        if (state is null)
        {
            _logger.LogDebug("No state found: writing empty state to file.");
            await WriteToFile(RelayState.Empty, cancellationToken);
            return RelayState.Empty;
        }

        return state;
    }

    private async Task<RelayState> SetState(RelayState state, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Writing state to file: {State}", state);
        await WriteToFile(state, cancellationToken);

        return state;
    }

    private Task<RelayState?> ReadFromFile(CancellationToken cancellationToken) =>
        _fileManager.DeserialiseFromFileAsync<RelayState>(_stateFilePath, cancellationToken);

    private Task WriteToFile(RelayState state, CancellationToken cancellationToken) =>
        _fileManager.SerialiseToFileAsync(state, _stateFilePath, cancellationToken);
}
