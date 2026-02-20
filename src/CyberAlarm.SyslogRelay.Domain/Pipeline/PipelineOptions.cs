namespace CyberAlarm.SyslogRelay.Domain.Pipeline;

public sealed class PipelineOptions
{
    public int ChannelCapacity { get; init; } = 10_000;

    public int PersistenceBufferSize { get; init; } = 1_000;

    public int PersistenceBufferIntervalInSeconds { get; init; } = 60;
}
