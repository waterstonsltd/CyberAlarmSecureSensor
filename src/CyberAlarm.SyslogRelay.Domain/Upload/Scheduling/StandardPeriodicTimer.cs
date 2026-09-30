namespace CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;

public sealed class StandardPeriodicTimer(TimeSpan timeSpan) : IPeriodicTimer
{
    private readonly PeriodicTimer _actualTimer = new(timeSpan);

    public async ValueTask<bool> WaitForNextTickAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await _actualTimer.WaitForNextTickAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    public void Dispose() => _actualTimer.Dispose();
}
