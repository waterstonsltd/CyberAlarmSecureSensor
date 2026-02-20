namespace CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;

public interface IPeriodicTimer : IDisposable
{
    ValueTask<bool> WaitForNextTickAsync(CancellationToken cancellationToken = default);
}
