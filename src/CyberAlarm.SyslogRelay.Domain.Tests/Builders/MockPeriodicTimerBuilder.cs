using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

/// <summary>
/// Allows mocking of IPeriodicTimer for unit tests.
/// When using timer.WaitForNextTickAsync() in a loop, you can use this mock to simulate
/// timer ticks or cancellation.
/// Inspired by https://stackoverflow.com/questions/74867695/mock-periodictimer-for-unittests
/// </summary>
public sealed class MockPeriodicTimerBuilder : IDisposable
{
    private readonly IPeriodicTimer _mock = Substitute.For<IPeriodicTimer>();
    private readonly SemaphoreSlim _isWaitingForTick = new(0, 1);
    private TaskCompletionSource<bool>? _taskCompletionSource;
    private bool _runOnce;

    /// <summary>
    /// Use this extension method to bypass the timer tick logic
    /// if your test only needs to run the loop once.
    /// </summary>
    /// <returns></returns>
    public MockPeriodicTimerBuilder RunOnce()
    {
        _runOnce = true;
        return this;
    }

    /// <summary>
    /// Build the mock IPeriodicTimer.
    /// Note that we've disabled warnings on use of ValueTask as we know that
    /// WaitForNextTickAsync will always be awaited in code.
    /// </summary>
    /// <returns></returns>
    public IPeriodicTimer Build()
    {
#pragma warning disable CA2012 // Use ValueTasks correctly
        if (_runOnce)
        {
            _mock.WaitForNextTickAsync(Arg.Any<CancellationToken>()).Returns(ValueTask.FromResult(false));
        }
        else
        {
            _mock.WaitForNextTickAsync(Arg.Any<CancellationToken>()).Returns(call => GetNextTickTask(call.Arg<CancellationToken>()));
        }
#pragma warning restore CA2012 // Use ValueTasks correctly
        return _mock;
    }

    /// <summary>
    /// Call this method from a test to simulate the timer tick.
    /// This will cause the code within the timer.WaitForNextTickAsync() loop to run once.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    public void Tick()
    {
        CompleteTask(true);
    }

    /// <summary>
    /// Call this method from a test to complete execution
    /// and exit the timer.WaitForNextTickAsync() loop.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    public void Complete()
    {
        CompleteTask(false);
    }

    /// <summary>
    /// Call this to simulate an external cancellation.
    /// It cancels the token and also sets the task to cancelled as, depending where you are in the execution cycle,
    /// you may not catch the cancellation properly.
    /// In theory this is simulating how the actual PeriodicTimer would behave.
    /// </summary>
    /// <param name="token"></param>
    public void Cancel(CancellationTokenSource cancellationTokenSource)
    {
        cancellationTokenSource.Cancel();
        CancelTask(cancellationTokenSource.Token);
    }

    /// <summary>
    /// This method should be called BEFORE calling Tick() or Complete()
    /// to ensure that the timer is actually waiting for the next tick.
    /// Failure to call this method could cause intermittent failures.
    /// </summary>
    /// <param name="timeout"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    public async Task WaitUntilNextTickRequested(TimeSpan? timeout = null)
    {
        var timedOut = !await _isWaitingForTick.WaitAsync(timeout ?? TimeSpan.FromSeconds(10));
        if (timedOut)
            throw new ArgumentException("This is a testing exception from PeriodicTimerBuilder: Waiting for the next tick timed out. Ensure sufficient time is allowed for the processing to complete.");
    }

    public void Dispose()
    {
        _isWaitingForTick.Dispose();
    }

    // This method is called every time the system calls WaitForNextTickAsync()
    // and the resulting ValueTask<bool> is awaited in the while loop.
    // Call Tick() to complete the ValueTask which simulates the timer tick.
    private ValueTask<bool> GetNextTickTask(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            CancelTask(cancellationToken);
            return new ValueTask<bool>(Task.FromCanceled<bool>(cancellationToken));
        }

        if (_taskCompletionSource is not null)
        {
            _taskCompletionSource.SetException(new ArgumentException("This is a testing exception from PeriodicTimerBuilder. WaitForNextTickAsync has been called before the previous Task has returned."));
        }

        _taskCompletionSource = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _isWaitingForTick.Release();

        return new ValueTask<bool>(_taskCompletionSource.Task);
    }

    // This method completes and clears the current TaskCompletionSource.
    // Note that we have to nullify _taskCompletionSource BEFORE calling SetResult,
    // using a local variable to hold the reference.
    // This is to prevent race conditions where setting the result causes the calling
    // code to continue before the _taskCompletionSource is cleared.
    private void CompleteTask(bool result)
    {
        if (_taskCompletionSource is null)
            throw new ArgumentException("This is a testing exception from PeriodicTimerBuilder: Next tick has been triggered before anything is awaiting it");

        var taskCompletionSource = _taskCompletionSource;
        _taskCompletionSource = null;
        taskCompletionSource.SetResult(result);
    }

    // This method cancels and clears the current TaskCompletionSource.
    // Note that we have to nullify _taskCompletionSource BEFORE calling TrySetCanceled,
    // using a local variable to hold the reference.
    // This is to prevent race conditions where setting the result causes the calling
    // code to continue before the _taskCompletionSource is cleared.
    private void CancelTask(CancellationToken cancellationToken)
    {
        var taskCompletionSource = _taskCompletionSource;
        _taskCompletionSource = null;
        taskCompletionSource?.TrySetCanceled(cancellationToken);
    }
}
