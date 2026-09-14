using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Pipeline;

public sealed class BufferedPersistenceStageTests
{
    [Fact]
    public async Task ConcurrentProcessAndPeriodicFlush_DoesNotThrow()
    {
        // Arrange — capture the periodic flush callback registered by the stage
        Func<CancellationToken, Task>? periodicFlush = null;
        var periodicOperation = Substitute.For<IPeriodicOperation>();
        periodicOperation
            .When(x => x.Start(Arg.Any<PeriodicOperationSettings>(), Arg.Any<CancellationToken>()))
            .Do(x => periodicFlush = x.ArgAt<PeriodicOperationSettings>(0).Operation);

        var stage = new BufferedPersistenceStageBuilder()
            .WithPeriodicOperation(periodicOperation)
            .Build();

        var input = new ValidationStageOutput(
            SyslogEvent.FromTcp("192.168.1.1", "test"),
            null,
            null,
            new ValidationResult(ValidationStatus.Success));

        await stage.StartAsync(CancellationToken.None);

        // Act — feed items through the processing loop and hammer the periodic flush
        // concurrently. Without a lock this races between List<T>(IEnumerable) reading
        // _buffer.Count to pre-allocate and the processing loop calling _buffer.Add,
        // producing: ArgumentException: Destination array was not long enough.
        var feedTask = Task.Run(async () =>
        {
            for (var i = 0; i < 20_000; i++)
            {
                await stage.EnqueueAsync(input, CancellationToken.None);
            }
        });

        var flushTask = Task.Run(async () =>
        {
            while (!feedTask.IsCompleted)
            {
                if (periodicFlush is not null)
                {
                    await periodicFlush(CancellationToken.None);
                }

                await Task.Yield();
            }
        });

        // Assert — must complete without throwing
        await Task.WhenAll(feedTask, flushTask);
        await stage.StopAsync(CancellationToken.None);
    }
}
