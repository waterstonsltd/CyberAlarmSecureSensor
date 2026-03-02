using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

namespace CyberAlarm.SyslogRelay.Domain.Tests;

internal sealed class TestStage<TInput>(List<TInput> results) : IPipelineStage<TInput>
{
    public IPipelineStage? NextStage => null;

    public List<TInput> Results { get; } = results;

    public Task EnqueueAsync(TInput input, CancellationToken cancellationToken)
    {
        Results.Add(input);
        return Task.CompletedTask;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
