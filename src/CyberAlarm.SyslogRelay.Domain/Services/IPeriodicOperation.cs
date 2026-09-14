namespace CyberAlarm.SyslogRelay.Domain.Services;

public interface IPeriodicOperation : IDisposable
{
    void Start(PeriodicOperationSettings settings, CancellationToken cancellationToken);

    Task StopAsync();
}
