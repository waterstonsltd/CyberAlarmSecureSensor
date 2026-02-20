using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Services;

public sealed class PeriodicOperation(ILogger<PeriodicOperation> logger) : IPeriodicOperation
{
    private readonly ILogger<PeriodicOperation> _logger = logger;

    private Func<CancellationToken, Task>? _operation;
    private string? _operationDescription;
    private PeriodicTimer? _timer;
    private CancellationTokenSource? _timerCts;
    private Task? _timerTask;

    public void Start(PeriodicOperationSettings settings, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(settings.Operation);

        _operation = settings.Operation;
        _operationDescription = settings.OperationDescription ?? "operation";
        _timer = new PeriodicTimer(settings.Interval);
        _timerCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _timerTask = RunTimerAsync(_timerCts.Token);
    }

    public async Task StopAsync()
    {
        if (_timerCts != null)
        {
            await _timerCts.CancelAsync();
            _timerCts.Dispose();
            _timerCts = null;
        }

        if (_timerTask != null)
        {
            try
            {
                await _timerTask;
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Periodic {Operation} cancelled.", _operationDescription);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error when stopping periodic {Operation}.", _operationDescription);
            }
        }
    }

    public void Dispose()
    {
        _timer?.Dispose();

        if (_timerCts != null)
        {
            _timerCts.Cancel();
            _timerCts.Dispose();
            _timerCts = null;
        }
    }

    private async Task RunTimerAsync(CancellationToken cancellationToken)
    {
        do
        {
            try
            {
                _logger.LogDebug("Running periodic {Operation}.", _operationDescription);
                await _operation!.Invoke(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Error during periodic {Operation}.", _operationDescription);
            }
        }
        while (await _timer!.WaitForNextTickAsync(cancellationToken));
    }
}
