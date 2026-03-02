namespace CyberAlarm.SyslogRelay.Domain.State;

public interface IStateService
{
    Task<RelayState> GetStateAsync(CancellationToken cancellationToken);

    Task<RelayState> SetStateAsync(RelayState state, CancellationToken cancellationToken);

    Task<RelayState> UpdateStateAsync(Func<RelayState, RelayState> updater, CancellationToken cancellationToken);
}
